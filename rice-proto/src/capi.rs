// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// everything will be unsafe since this is a FFI
#![allow(clippy::missing_safety_doc)]
#![deny(improper_ctypes_definitions)]

//! # C API
//!
//! The C API for `rice-proto`.
//!
//! ## Conventions
//!
//! 1. All refcounted objects (`_ref()` and `_unref()` functions are available for the type)
//!    are `Send+Sync` and contain interior mutability.
//! 2. All non-refcounted objects are `Send`, but not `Sync`.
//!
//! ### Lifetime
//!
//! 1. Any function that takes a `*const _` does not take ownership of the provided pointer.
//! 2. For functions that take a `*mut _` argument,
//!    1. If the argument is a refcounted type then by default no reference is consumed unless
//!       specified otherwise. As an exception, `_unref()` and `_free()` functions always
//!       consume the provided reference.
//!    2. Otherwise, the argument consumes the reference.
//!
//! ### Allocations
//!
//! All heap allocated resources allocated by `rice-proto` must also be freed by a `rice-proto`
//! function in order to correctly match the allocation with the correct allocator.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::CStr;
use libc::{c_char, c_int, c_void};
use tracing::{debug, warn};

use core::mem::MaybeUninit;

use alloc::sync::{Arc, Weak};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::str::FromStr;
use std::sync::{Mutex, Once};

use crate::agent::AgentPoll;
use crate::agent::{Agent, AgentError};
use crate::candidate::{Candidate, CandidatePair, CandidateType, TransportType};
use crate::component::ComponentConnectionState;
use crate::gathering::GatheredCandidate;
use crate::stream::Credentials;
#[cfg(feature = "openssl")]
use crate::turn::OpensslTurnConfig;
#[cfg(feature = "rustls")]
use crate::turn::RustlsTurnConfig;
use crate::turn::{TurnConfig, TurnCredentials, TurnTlsConfig};
use stun_proto::Instant;
use stun_proto::agent::{StunError, Transmit};
use stun_proto::types::AddressFamily;
use stun_proto::types::data::{Data, DataOwned, DataSlice};
use turn_client_proto::client::TurnClient;

use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

pub use rice_ctypes::{RiceAddress, RiceError, RiceTransportType};

// cbindgen does not generate definitions for reexported types, so do that here, now.
#[allow(unused)]
mod cbindgen_workarounds {
    /// A socket address.
    pub struct RiceAddress;
    /// The transport family
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u32)]
    pub enum RiceTransportType {
        /// The UDP transport
        Udp,
        /// The TCP transport
        Tcp,
    }
    const _: () = assert!(core::mem::size_of::<RiceTransportType>() == core::mem::size_of::<u32>());
    const _: () = assert!(RiceTransportType::Udp as u32 == super::RiceTransportType::Udp as u32);
    const _: () = assert!(RiceTransportType::Tcp as u32 == super::RiceTransportType::Tcp as u32);
    /// Errors when processing an operation.
    #[repr(i32)]
    pub enum RiceError {
        /// Not an error. The operation was completed successfully.
        Success = 0,
        /// The operation failed for an unspecified reason.
        Failed = -1,
        /// A required resource was not found.
        ResourceNotFound = -2,
        /// The operation is already in progress.
        AlreadyInProgress = -3,
    }
    const _: () = assert!(core::mem::size_of::<RiceError>() == core::mem::size_of::<i32>());
    const _: () = assert!(RiceError::Success as i32 == super::RiceError::Success as i32);
    const _: () = assert!(RiceError::Failed as i32 == super::RiceError::Failed as i32);
    const _: () =
        assert!(RiceError::ResourceNotFound as i32 == super::RiceError::ResourceNotFound as i32);
    const _: () =
        assert!(RiceError::AlreadyInProgress as i32 == super::RiceError::AlreadyInProgress as i32);
}

static TRACING: Once = Once::new();

fn init_logs() {
    TRACING.call_once(|| {
        let level_filter = std::env::var("RICE_LOG")
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        let _ = tracing::subscriber::set_global_default(registry);
    });
}

/// Query the built version of `rice-proto`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_version(major: *mut u32, minor: *mut u32, patch: *mut u32) {
    unsafe {
        if !major.is_null() {
            *major = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
        }
        if !minor.is_null() {
            *minor = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap();
        }
        if !patch.is_null() {
            *patch = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap();
        }
    }
}

fn transport_type_from_c(transport: RiceTransportType) -> TransportType {
    match transport {
        RiceTransportType::Udp => TransportType::Udp,
        RiceTransportType::Tcp => TransportType::Tcp,
    }
}

fn transport_type_to_c(transport: TransportType) -> RiceTransportType {
    match transport {
        TransportType::Udp => RiceTransportType::Udp,
        TransportType::Tcp => RiceTransportType::Tcp,
    }
}

#[derive(Debug)]
struct RiceAgentInner {
    stun_servers: Vec<(TransportType, SocketAddr)>,
    streams: Vec<Arc<RiceStream>>,
}

/// The Rice Agent used for interacting with the ICE process.
#[derive(Debug)]
pub struct RiceAgent {
    proto_agent: Arc<Mutex<Agent>>,
    inner: Arc<Mutex<RiceAgentInner>>,
}

/// Create a new ICE Agent.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_new(controlling: bool, trickle_ice: bool) -> *mut RiceAgent {
    unsafe {
        init_logs();

        let proto_agent = Arc::new(Mutex::new(
            Agent::builder()
                .trickle_ice(trickle_ice)
                .controlling(controlling)
                .build(),
        ));

        let agent = Arc::new(RiceAgent {
            proto_agent,
            inner: Arc::new(Mutex::new(RiceAgentInner {
                stun_servers: vec![],
                streams: vec![],
            })),
        });

        mut_override(Arc::into_raw(agent))
    }
}

/// Increase the reference count of the `RiceAgent`.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_ref(agent: *const RiceAgent) -> *mut RiceAgent {
    unsafe {
        Arc::increment_strong_count(agent);
        mut_override(agent)
    }
}

/// Decrease the reference count of the `RiceAgent`.
///
/// If this is the last reference, then the `RiceAgent` is freed.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_unref(agent: *mut RiceAgent) {
    unsafe { Arc::decrement_strong_count(agent) }
}

/// Close the `RiceAgent`.
///
/// Closure does involve closing network resources (signalled through calls to
/// `rice_agent_poll()`) and will only succesfully complete once `rice_agent_poll`() returns
/// `Closed`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_close(agent: *const RiceAgent, now_nanos: i64) {
    unsafe {
        let agent = Arc::from_raw(agent);
        let mut proto_agent = agent.proto_agent.lock().unwrap();
        proto_agent.close(Instant::from_nanos(now_nanos));

        drop(proto_agent);
        core::mem::forget(agent);
    }
}

/// Return the process-local unique id for this agent.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_id(agent: *const RiceAgent) -> u64 {
    unsafe {
        let agent = Arc::from_raw(agent);
        let proto_agent = agent.proto_agent.lock().unwrap();
        let ret = proto_agent.id();

        drop(proto_agent);
        core::mem::forget(agent);
        ret
    }
}

/// Get the controlling state of the `RiceAgent`.
///
/// A return value of `true` indicates the `RiceAgent` is in controlling mode, false the controlled
/// mode.  This value can change during ICE processing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_get_controlling(agent: *const RiceAgent) -> bool {
    unsafe {
        let agent = Arc::from_raw(agent);
        let proto_agent = agent.proto_agent.lock().unwrap();
        let ret = proto_agent.controlling();

        drop(proto_agent);
        core::mem::forget(agent);
        ret
    }
}

/// Return value of `rice_agent_poll()`.
#[derive(Debug)]
#[repr(C)]
pub enum RiceAgentPoll {
    /// The Agent is closed.  No further progress will be made.
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event).
    WaitUntilNanos(i64),
    /// Connect from the specified interface to the specified address.  Reply (success or failure)
    /// should be notified using `rice_stream_handle_allocated_socket()`.
    AllocateSocket(RiceAgentSocket),
    /// It is possible to remove the specified 5-tuple. The socket will not be referenced any
    /// further.
    RemoveSocket(RiceAgentSocket),
    /// A new pair has been selected for a component.
    SelectedPair(RiceAgentSelectedPair),
    /// A [`Component`](crate::component::Component) has changed state.
    ComponentStateChange(RiceAgentComponentStateChange),
    /// A [`Component`](crate::component::Component) has gathered a candidate.
    GatheredCandidate(RiceAgentGatheredCandidate),
    /// A [`Component`](crate::component::Component) has completed gathering.
    GatheringComplete(RiceAgentGatheringComplete),
}

impl RiceAgentPoll {
    fn into_c_full(poll: AgentPoll) -> Self {
        match poll {
            AgentPoll::Closed => Self::Closed,
            AgentPoll::WaitUntil(instant) => Self::WaitUntilNanos(instant.as_nanos()),
            AgentPoll::AllocateSocket(connect) => {
                Self::AllocateSocket(RiceAgentSocket::into_c_full(connect))
            }
            AgentPoll::RemoveSocket(connect) => {
                Self::RemoveSocket(RiceAgentSocket::into_c_full(connect))
            }
            AgentPoll::SelectedPair(pair) => {
                Self::SelectedPair(RiceAgentSelectedPair::into_c_full(pair))
            }
            AgentPoll::ComponentStateChange(state) => Self::ComponentStateChange(state.into()),
            AgentPoll::GatheredCandidate(gathered) => {
                Self::GatheredCandidate(RiceAgentGatheredCandidate::into_c_full(gathered))
            }
            AgentPoll::GatheringComplete(complete) => Self::GatheringComplete(complete.into()),
        }
    }
}

/// A pointer to a sequence of bytes and size.
#[derive(Debug)]
#[repr(C)]
pub enum RiceData {
    /// The data is borrowed and will not be freed on destruction.
    Borrowed(RiceDataImpl),
    /// The data is owned and will be freed on destruction.
    Owned(RiceDataImpl),
}

/// A pointer to a sequence of bytes and the associated size.
#[derive(Debug)]
#[repr(C)]
pub struct RiceDataImpl {
    /// A pointer to a sequence of bytes.
    ptr: *mut u8,
    /// Number of bytes pointed to in `ptr`.
    size: usize,
}

impl RiceDataImpl {
    unsafe fn owned_from_c(self) -> Box<[u8]> {
        unsafe { Box::from_raw(core::slice::from_raw_parts_mut(self.ptr, self.size)) }
    }

    fn owned_to_c(val: Box<[u8]>) -> Self {
        let size = val.len();
        let ptr = Box::into_raw(val) as *mut _;
        Self { ptr, size }
    }

    unsafe fn borrowed_from_c<'a>(self) -> &'a [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    fn borrowed_to_c(val: &[u8]) -> Self {
        Self {
            ptr: mut_override(val.as_ptr()),
            size: val.len(),
        }
    }
}

impl Default for RiceDataImpl {
    fn default() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            size: 0,
        }
    }
}

impl<'a> From<Data<'a>> for RiceData {
    fn from(value: Data<'a>) -> Self {
        match value {
            Data::Borrowed(slice) => Self::Borrowed(RiceDataImpl::borrowed_to_c(&slice)),
            Data::Owned(owned) => Self::Owned(RiceDataImpl::owned_to_c(owned.into())),
        }
    }
}

impl<'a> From<RiceData> for Data<'a> {
    fn from(value: RiceData) -> Self {
        unsafe {
            match value {
                RiceData::Borrowed(imp) => Self::Borrowed(DataSlice::from(imp.borrowed_from_c())),
                RiceData::Owned(imp) => Self::Owned(DataOwned::from(imp.owned_from_c())),
            }
        }
    }
}

/// The number of bytes in a `RiceData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_data_len(data: *const RiceData) -> usize {
    match &*data {
        RiceData::Borrowed(imp) => imp.size,
        RiceData::Owned(imp) => imp.size,
    }
}

/// The data pointer for a `RiceData`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_data_ptr(data: *const RiceData) -> *mut u8 {
    match &*data {
        RiceData::Borrowed(imp) => imp.ptr,
        RiceData::Owned(imp) => imp.ptr,
    }
}

/// Transmit the data using the specified 5-tuple.
#[derive(Debug)]
#[repr(C)]
pub struct RiceTransmit {
    /// The associated stream identifier.
    stream_id: usize,
    /// The transport type for the transmission.
    transport: RiceTransportType,
    /// The socket source address to send from.
    from: *const RiceAddress,
    /// The socket destination address to send to.
    to: *const RiceAddress,
    /// The data to send.
    data: RiceDataImpl,
}

impl Default for RiceTransmit {
    fn default() -> Self {
        Self {
            stream_id: 0,
            transport: RiceTransportType::Udp,
            from: core::ptr::null(),
            to: core::ptr::null(),
            data: RiceDataImpl::default(),
        }
    }
}

impl RiceTransmit {
    fn into_c_full(value: crate::agent::AgentTransmit) -> Self {
        let from = Box::new(RiceAddress::new(value.transmit.from));
        let to = Box::new(RiceAddress::new(value.transmit.to));
        Self {
            stream_id: value.stream_id,
            transport: transport_type_to_c(value.transmit.transport),
            from: Box::into_raw(from),
            to: Box::into_raw(to),
            data: RiceDataImpl::owned_to_c(value.transmit.data),
        }
    }
}

/// Free any resources allocated within a `RiceTransmit`.
///
/// The `RiceTransmit` must have been previously initialized with `rice_transmit_init()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_transmit_clear(transmit: *mut RiceTransmit) {
    unsafe {
        if !(*transmit).from.is_null() {
            let _from = RiceAddress::into_rice_full((*transmit).from);
            (*transmit).from = core::ptr::null_mut();
        }
        if !(*transmit).to.is_null() {
            let _to = RiceAddress::into_rice_full((*transmit).to);
            (*transmit).to = core::ptr::null_mut();
        }
        let mut data = RiceDataImpl::default();
        core::mem::swap(&mut data, &mut (*transmit).data);
        if !data.ptr.is_null() {
            let _data = RiceDataImpl::owned_from_c(data);
        }
    }
}

/// Initialize a `RiceTransmit` with default values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_transmit_init(transmit: *mut MaybeUninit<RiceTransmit>) {
    unsafe { (*transmit).write(RiceTransmit::default()) };
}

/// A socket with the specified network 5-tuple.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentSocket {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
    /// The transport type to allocate.
    pub transport: RiceTransportType,
    /// The source address to allocate from.
    pub from: *const RiceAddress,
    /// The destination address to connect to.
    pub to: *const RiceAddress,
}

impl RiceAgentSocket {
    fn into_c_full(value: crate::agent::AgentSocket) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            transport: transport_type_to_c(value.transport),
            from: Box::into_raw(Box::new(RiceAddress::new(value.from))),
            to: Box::into_raw(Box::new(RiceAddress::new(value.to))),
        }
    }
}

/// A new pair has been selected for a component.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentSelectedPair {
    /// The ICE stream id.
    stream_id: usize,
    /// The ICE component id.
    component_id: usize,
    /// The local candidate of a selected pair.
    local: RiceCandidate,
    /// The remote candidate of a selected pair.
    remote: RiceCandidate,
    /// The local TURN transport type (if any).
    local_turn_transport: RiceTransportType,
    /// The local TURN address to send data from.
    local_turn_local_addr: *const RiceAddress,
    /// The local TURN address to send data to.
    local_turn_remote_addr: *const RiceAddress,
}

impl RiceAgentSelectedPair {
    fn into_c_full(value: crate::agent::AgentSelectedPair) -> Self {
        let pair = value.selected.candidate_pair().clone();
        let (local_turn_transport, local_turn_local_addr, local_turn_remote_addr) =
            if let Some(turn) = value.selected.local_turn() {
                (
                    transport_type_to_c(turn.transport()),
                    RiceAddress::into_c_full(RiceAddress::new(turn.local_addr())),
                    RiceAddress::into_c_full(RiceAddress::new(turn.remote_addr())),
                )
            } else {
                (RiceTransportType::Udp, core::ptr::null(), core::ptr::null())
            };
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            local: RiceCandidate::into_c_full(pair.local),
            remote: RiceCandidate::into_c_full(pair.remote),
            local_turn_transport,
            local_turn_local_addr,
            local_turn_remote_addr,
        }
    }
}

/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentComponentStateChange {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
    /// The new state of the component.
    pub state: ComponentConnectionState,
}

impl From<crate::agent::AgentComponentStateChange> for RiceAgentComponentStateChange {
    fn from(value: crate::agent::AgentComponentStateChange) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            state: value.state,
        }
    }
}

impl From<RiceAgentComponentStateChange> for crate::agent::AgentComponentStateChange {
    fn from(value: RiceAgentComponentStateChange) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            state: value.state,
        }
    }
}

/// A [`Component`](crate::component::Component) has gathered a candidate.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentGatheredCandidate {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The candidate gathered.
    pub gathered: RiceGatheredCandidate,
}

impl RiceAgentGatheredCandidate {
    fn into_c_full(value: crate::agent::AgentGatheredCandidate) -> Self {
        Self {
            stream_id: value.stream_id,
            gathered: RiceGatheredCandidate::into_c_full(value.gathered),
        }
    }
}

/// A [`Component`](crate::component::Component) has completed gathering.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentGatheringComplete {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
}

impl From<crate::agent::AgentGatheringComplete> for RiceAgentGatheringComplete {
    fn from(value: crate::agent::AgentGatheringComplete) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
        }
    }
}

impl From<RiceAgentGatheringComplete> for crate::agent::AgentGatheringComplete {
    fn from(value: RiceAgentGatheringComplete) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
        }
    }
}

/// Initialize a `RiceAgentPoll` with a default value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_poll_init(poll: *mut MaybeUninit<RiceAgentPoll>) {
    unsafe { (*poll).write(RiceAgentPoll::Closed) };
}

/// Clear a `RiceAgentPoll` of any allocated values.
///
/// `rice_agent_poll_init()` must have been called previously.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_poll_clear(poll: *mut RiceAgentPoll) {
    unsafe {
        let mut other = RiceAgentPoll::Closed;
        core::ptr::swap(&mut other, poll);
        match other {
            RiceAgentPoll::Closed
            | RiceAgentPoll::ComponentStateChange(_)
            | RiceAgentPoll::WaitUntilNanos(_)
            | RiceAgentPoll::GatheringComplete(_) => (),
            RiceAgentPoll::AllocateSocket(mut connect) => {
                let mut from = core::ptr::null();
                core::mem::swap(&mut from, &mut connect.from);
                let _from = RiceAddress::into_rice_full(from);
                let mut to = core::ptr::null();
                core::mem::swap(&mut to, &mut connect.to);
                let _to = RiceAddress::into_rice_full(to);
            }
            RiceAgentPoll::RemoveSocket(mut connect) => {
                let mut from = core::ptr::null();
                core::mem::swap(&mut from, &mut connect.from);
                let _from = RiceAddress::into_rice_full(from);
                let mut to = core::ptr::null();
                core::mem::swap(&mut to, &mut connect.to);
                let _to = RiceAddress::into_rice_full(to);
            }
            RiceAgentPoll::SelectedPair(mut pair) => {
                rice_candidate_clear(&mut pair.local);
                rice_candidate_clear(&mut pair.remote);
                if !pair.local_turn_local_addr.is_null() {
                    rice_address_free(mut_override(pair.local_turn_local_addr));
                    pair.local_turn_local_addr = core::ptr::null();
                }
                if !pair.local_turn_remote_addr.is_null() {
                    rice_address_free(mut_override(pair.local_turn_remote_addr));
                    pair.local_turn_remote_addr = core::ptr::null();
                }
            }
            RiceAgentPoll::GatheredCandidate(mut gathered) => {
                let turn = gathered.gathered.turn_agent;
                gathered.gathered.turn_agent = core::ptr::null_mut();
                let _turn_agent = if turn.is_null() {
                    None
                } else {
                    Some(Box::from_raw(turn as *mut TurnClient))
                };
                rice_candidate_clear(&mut gathered.gathered.candidate);
            }
        }
    }
}

/// Poll the `RiceAgent` for further progress.
///
/// The returned value indicates what should be done to continue making progress.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_poll(
    agent: *mut RiceAgent,
    now_nanos: i64,
    poll: *mut RiceAgentPoll,
) {
    unsafe {
        let agent = Arc::from_raw(agent);
        let mut proto_agent = agent.proto_agent.lock().unwrap();
        let now = Instant::from_nanos(now_nanos);
        let ret = proto_agent.poll(now);
        if let AgentPoll::SelectedPair(ref pair) = ret {
            if let Some(mut stream) = proto_agent.mut_stream(pair.stream_id) {
                if let Some(mut component) = stream.mut_component(pair.component_id) {
                    component.set_selected_pair_with_agent((*pair.selected).clone());
                }
            }
        }
        *poll = RiceAgentPoll::into_c_full(ret);

        drop(proto_agent);
        core::mem::forget(agent);
    }
}

/// Poll the `RiceAgent` for a transmission to send.
///
/// If there is no transmission, then `transmit` will be filled with empty data.
///
/// `rice_transmit_init()` or `rice_transmit_clear()` must be called before this function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_poll_transmit(
    agent: *mut RiceAgent,
    now_nanos: i64,
    transmit: *mut RiceTransmit,
) {
    unsafe {
        let agent = Arc::from_raw(agent);
        let mut proto_agent = agent.proto_agent.lock().unwrap();
        let now = Instant::from_nanos(now_nanos);
        if let Some(ret) = proto_agent.poll_transmit(now) {
            *transmit = RiceTransmit::into_c_full(ret);
        } else {
            *transmit = RiceTransmit::default();
        }

        drop(proto_agent);
        core::mem::forget(agent);
    }
}

/// Add a STUN server to this `RiceAgent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_add_stun_server(
    agent: *const RiceAgent,
    transport: RiceTransportType,
    addr: *const RiceAddress,
) {
    unsafe {
        let agent = Arc::from_raw(agent);
        let addr = Box::from_raw(mut_override(addr));
        let mut inner = agent.inner.lock().unwrap();
        inner
            .stun_servers
            .push((transport_type_from_c(transport), **addr));
        drop(inner);
        core::mem::forget(addr);
        core::mem::forget(agent);
    }
}

/// Configuration for accessing a TURN server.
#[derive(Debug, Clone)]
pub struct RiceTurnConfig(TurnConfig);

impl RiceTurnConfig {
    /// Create a new `RiceTurnConfig`.
    pub fn new(config: TurnConfig) -> Self {
        Self(config)
    }

    /// Convert this `RiceTurnConfig` into it's C API equivalent.
    ///
    /// The returned value should be converted back into the Rust equivalent using
    /// `RiceTurnConfig::into_rust_full()` in order to free the resource.
    pub fn into_c_full(self) -> *const RiceTurnConfig {
        Arc::into_raw(Arc::new(self))
    }

    /// Consume a C representation of a `RiceTurnConfig` into the Rust equivalent.
    pub unsafe fn into_rice_full(value: *mut RiceTurnConfig) -> Arc<Self> {
        unsafe { Arc::from_raw(value) }
    }

    /// Copy a C representation of a `RiceTurnConfig` into the Rust equivalent.
    pub unsafe fn into_rice_none(value: *const RiceTurnConfig) -> Self {
        unsafe {
            let boxed = Arc::from_raw(mut_override(value));
            let ret = (*boxed).clone();
            core::mem::forget(boxed);
            ret
        }
    }

    /// The inner representation of the [`RiceTurnConfig`].
    pub fn inner(self) -> TurnConfig {
        self.0
    }
}

/// Create a new TURN configuration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_new(
    transport: RiceTransportType,
    addr: *const RiceAddress,
    credentials: *const RiceCredentials,
    allocation_transport: RiceTransportType,
    n_families: usize,
    families: *const RiceAddressFamily,
    tls_config: *mut RiceTlsConfig,
) -> *mut RiceTurnConfig {
    unsafe {
        let creds = Box::from_raw(mut_override(credentials));
        let addr = Box::from_raw(mut_override(addr));
        let families = core::slice::from_raw_parts(families, n_families);
        let families = families
            .iter()
            .map(|family| family.into_rice())
            .collect::<Vec<_>>();

        let mut turn_config = TurnConfig::new(
            transport_type_from_c(transport),
            **addr,
            TurnCredentials::new(&creds.credentials.ufrag, &creds.credentials.passwd),
            transport_type_from_c(allocation_transport),
            &families,
        );
        if !tls_config.is_null() {
            let tls_config = Arc::from_raw(tls_config);
            turn_config = turn_config.with_tls_config(tls_config.variant.clone());
        }
        core::mem::forget(addr);
        core::mem::forget(creds);
        mut_override(Arc::into_raw(Arc::new(RiceTurnConfig::new(turn_config))))
    }
}

/// Increase the reference count of the [`RiceTurnConfig`].
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_ref(
    config: *const RiceTurnConfig,
) -> *mut RiceTurnConfig {
    unsafe {
        Arc::increment_strong_count(config);
        mut_override(config)
    }
}

/// Decrease the reference count of a[`RiceTurnConfig`].
///
/// If this is the last reference, then the [`RiceTurnConfig`] is freed.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_unref(config: *mut RiceTurnConfig) {
    unsafe { Arc::decrement_strong_count(config) }
}

/// The address of the TURN server.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_get_addr(
    config: *const RiceTurnConfig,
) -> *mut RiceAddress {
    unsafe {
        let config = RiceTurnConfig::into_rice_none(config).inner();
        mut_override(RiceAddress::new(config.addr()).into_c_full())
    }
}

/// The transport to connect to the TURN server.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_get_client_transport(
    config: *const RiceTurnConfig,
) -> RiceTransportType {
    unsafe {
        let config = RiceTurnConfig::into_rice_none(config).inner();
        transport_type_to_c(config.client_transport())
    }
}

fn turn_credentials_to_c(credentials: &TurnCredentials) -> *mut RiceCredentials {
    Box::into_raw(Box::new(RiceCredentials {
        credentials: Credentials::new(
            credentials.username().to_owned(),
            credentials.password().to_owned(),
        ),
    }))
}

/// The credentials to use for accessing the TURN server.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_get_credentials(
    config: *const RiceTurnConfig,
) -> *mut RiceCredentials {
    unsafe {
        let config = RiceTurnConfig::into_rice_none(config).inner();
        turn_credentials_to_c(config.credentials())
    }
}

/// The transport to connect to the TURN server.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_get_families(
    config: *const RiceTurnConfig,
    n_families: *mut usize,
    families: *mut RiceAddressFamily,
) {
    unsafe {
        let config = RiceTurnConfig::into_rice_none(config).inner();
        let output_len = *n_families;
        *n_families = config.families().len();
        if families.is_null() {
            return;
        }
        let families = core::slice::from_raw_parts_mut(families, output_len);
        for (i, family) in config.families().iter().enumerate() {
            *n_families = i;
            if i >= output_len {
                break;
            }
            families[i] = RiceAddressFamily::from_rice(*family);
        }
    }
}

/// The TLS config associated with this TURN configuration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_turn_config_get_tls_config(
    config: *const RiceTurnConfig,
) -> *mut RiceTlsConfig {
    unsafe {
        let config = RiceTurnConfig::into_rice_none(config).inner();
        if let Some(variant) = config.tls_config().cloned() {
            mut_override(Arc::into_raw(Arc::new(RiceTlsConfig { variant })))
        } else {
            core::ptr::null_mut()
        }
    }
}

/// TLS configuration data.
#[derive(Debug, Clone)]
pub struct RiceTlsConfig {
    variant: TurnTlsConfig,
}

/// Increase the reference count of the `RiceTlsConfig`.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_tls_config_ref(config: *const RiceTlsConfig) -> *mut RiceTlsConfig {
    unsafe {
        Arc::increment_strong_count(config);
        mut_override(config)
    }
}

/// Decrease the reference count of the `RiceTlsConfig`.
///
/// If this is the last reference, then the `RiceTlsConfig` is freed.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_tls_config_unref(config: *mut RiceTlsConfig) {
    unsafe { Arc::decrement_strong_count(config) }
}

/// The TLS variant.
#[derive(Debug)]
#[repr(u32)]
pub enum RiceTlsVariant {
    /// Openssl.
    Openssl = 1,
    /// Rustls.
    Rustls = 2,
}

/// The TLS variant for a [`RiceTlsConfig`]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_tls_config_variant(config: *const RiceTlsConfig) -> RiceTlsVariant {
    unsafe {
        let config = Arc::from_raw(config);
        let ret = match config.variant {
            #[cfg(feature = "rustls")]
            TurnTlsConfig::Rustls(_) => RiceTlsVariant::Rustls,
            #[cfg(feature = "openssl")]
            TurnTlsConfig::Openssl(_) => RiceTlsVariant::Openssl,
        };
        core::mem::forget(config);
        ret
    }
}

/// Construct a new TLS configuration using Openssl.
#[unsafe(no_mangle)]
#[cfg(feature = "openssl")]
pub unsafe extern "C" fn rice_tls_config_new_openssl(
    transport: RiceTransportType,
) -> *mut RiceTlsConfig {
    unsafe {
        let method = match transport_type_from_c(transport) {
            TransportType::Udp => openssl::ssl::SslMethod::dtls_client(),
            TransportType::Tcp => openssl::ssl::SslMethod::tls_client(),
        };
        let Ok(ctx) = openssl::ssl::SslConnector::builder(method) else {
            return core::ptr::null_mut();
        };
        mut_override(Arc::into_raw(Arc::new(RiceTlsConfig {
            variant: OpensslTurnConfig::new(ctx.build().into_context()).into(),
        })))
    }
}

/// Construct a new TLS configuration using Rustls.
#[unsafe(no_mangle)]
#[cfg(feature = "rustls")]
pub unsafe extern "C" fn rice_tls_config_new_rustls_with_dns(
    server_name: *const c_char,
) -> *mut RiceTlsConfig {
    unsafe {
        use rustls_platform_verifier::ConfigVerifierExt;
        let Ok(server_name) = string_from_c(server_name).try_into() else {
            return core::ptr::null_mut();
        };
        let verifier = match rustls::ClientConfig::with_platform_verifier() {
            Ok(verifier) => verifier,
            Err(e) => {
                warn!("Failed to create Rustls platform verifier: {e:?}");
                return core::ptr::null_mut();
            }
        };
        mut_override(Arc::into_raw(Arc::new(RiceTlsConfig {
            variant: RustlsTurnConfig::new(Arc::new(verifier), server_name).into(),
        })))
    }
}

/// Construct a new TLS configuration using Rustls.
#[unsafe(no_mangle)]
#[cfg(feature = "rustls")]
pub unsafe extern "C" fn rice_tls_config_new_rustls_with_ip(
    addr: *const RiceAddress,
) -> *mut RiceTlsConfig {
    unsafe {
        use rustls_platform_verifier::ConfigVerifierExt;
        let addr = RiceAddress::into_rice_none(addr);
        let verifier = match rustls::ClientConfig::with_platform_verifier() {
            Ok(verifier) => verifier,
            Err(e) => {
                warn!("Failed to create Rustls platform verifier: {e:?}");
                return core::ptr::null_mut();
            }
        };
        mut_override(Arc::into_raw(Arc::new(RiceTlsConfig {
            variant: RustlsTurnConfig::new(Arc::new(verifier), addr.inner().ip().into()).into(),
        })))
    }
}

/// A data stream in a `RiceAgent`.
#[derive(Debug)]
pub struct RiceStream {
    proto_agent: Arc<Mutex<Agent>>,
    weak_agent: Weak<RiceAgent>,
    inner: Arc<Mutex<RiceStreamInner>>,
    stream_id: usize,
}

#[derive(Debug)]
struct RiceStreamInner {
    components: Vec<Arc<RiceComponent>>,
}

/// Add an ICE stream to the `RiceAgent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_add_stream(agent: *mut RiceAgent) -> *mut RiceStream {
    unsafe {
        let agent = Arc::from_raw(agent);
        let mut proto_agent = agent.proto_agent.lock().unwrap();
        let stream_id = proto_agent.add_stream();
        let stream = Arc::new(RiceStream {
            proto_agent: agent.proto_agent.clone(),
            weak_agent: Arc::downgrade(&agent),
            inner: Arc::new(Mutex::new(RiceStreamInner { components: vec![] })),
            stream_id,
        });
        drop(proto_agent);

        let mut inner = agent.inner.lock().unwrap();
        inner.streams.push(stream.clone());

        drop(inner);
        core::mem::forget(agent);
        mut_override(Arc::into_raw(stream))
    }
}

/// Retrieve a previously added stream from the `RiceAgent`.
///
/// Will return `NULL` if the stream does not exist.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_agent_get_stream(
    agent: *const RiceAgent,
    stream_id: usize,
) -> *mut RiceStream {
    unsafe {
        let agent = Arc::from_raw(agent);
        let inner = agent.inner.lock().unwrap();
        let ret = if let Some(stream) = inner.streams.get(stream_id) {
            mut_override(Arc::into_raw(stream.clone()))
        } else {
            mut_override(core::ptr::null::<RiceStream>())
        };

        drop(inner);
        core::mem::forget(agent);
        ret
    }
}

/// Increase the reference count of the `RiceStream`.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_ref(stream: *const RiceStream) -> *mut RiceStream {
    unsafe {
        Arc::increment_strong_count(stream);
        mut_override(stream)
    }
}

/// Decrease the reference count of the `RiceStream`.
///
/// If this is the last reference, then the `RiceStream` is freed (but will still be referenced by
/// the `RiceAgent`).
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_unref(stream: *mut RiceStream) {
    unsafe { Arc::decrement_strong_count(stream) }
}

/// Retrieve the stream id of the `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_get_id(stream: *const RiceStream) -> usize {
    unsafe {
        let stream = Arc::from_raw(stream);
        let ret = stream.stream_id;
        core::mem::forget(stream);
        ret
    }
}

/// Retrieve the `RiceAgent` of the `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_get_agent(stream: *const RiceStream) -> *mut RiceAgent {
    unsafe {
        let stream = Arc::from_raw(stream);
        let Some(ret) = stream.weak_agent.upgrade() else {
            core::mem::forget(stream);
            return core::ptr::null_mut();
        };
        core::mem::forget(stream);
        mut_override(Arc::into_raw(ret))
    }
}

/// Notify success or failure to create a socket to the `RiceStream`.
///
/// `socket_addr` can be `NULL` to indicate failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_handle_allocated_socket(
    stream: *mut RiceStream,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    socket_addr: *mut RiceAddress,
    now_nanos: i64,
) {
    unsafe {
        let stream = Arc::from_raw(stream);
        let now = Instant::from_nanos(now_nanos);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

        let from = RiceAddress::into_rice_none(from);
        let to = RiceAddress::into_rice_none(to);
        let socket = if socket_addr.is_null() {
            Err(StunError::ResourceNotFound)
        } else {
            Ok(**RiceAddress::into_rice_full(socket_addr))
        };
        proto_stream.allocated_socket(
            component_id,
            transport_type_from_c(transport),
            from.inner(),
            to.inner(),
            socket,
            now,
        );

        drop(proto_agent);
        core::mem::forget(stream);
    }
}

/// ICE/TURN credentials.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct RiceCredentials {
    credentials: Credentials,
}

/// Construct a new set of ICE/TURN credentials.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_credentials_new(
    ufrag: *const c_char,
    passwd: *const c_char,
) -> *mut RiceCredentials {
    unsafe {
        let ufrag = string_from_c(ufrag);
        let passwd = string_from_c(passwd);
        Box::into_raw(Box::new(RiceCredentials {
            credentials: Credentials::new(ufrag, passwd),
        }))
    }
}

/// Construct a new set of ICE/TURN credentials.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_credentials_copy(
    creds: *const RiceCredentials,
) -> *mut RiceCredentials {
    unsafe {
        let creds = Box::from_raw(mut_override(creds));
        let ret = creds.clone();
        core::mem::forget(creds);
        Box::into_raw(ret)
    }
}

/// Free a set of ICE/TURN credentials.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_credentials_free(credentials: *mut RiceCredentials) {
    unsafe {
        let _ = Box::from_raw(credentials);
    }
}

/// Retrieve the `RiceCandidate` ufrag attribute bytes.
/// The pre-allocated array should be 256 bytes at most.
///
/// Returns the actual length of the ufrag attribute.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_credentials_get_ufrag_bytes(
    credentials: *const RiceCredentials,
    ptr: *mut c_char,
) -> usize {
    unsafe {
        let creds = Box::from_raw(mut_override(credentials));
        let bytes = creds.credentials.ufrag.as_bytes();
        let len = bytes.len();
        std::ptr::copy(bytes.as_ptr().cast(), ptr, len);
        std::ptr::write(ptr.offset(len as isize) as *mut u8, 0u8);
        core::mem::forget(creds);
        len
    }
}

/// Compare two sets of Credentials.
///
/// This function is NULL safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_credentials_eq(
    creds1: *const RiceCredentials,
    creds2: *const RiceCredentials,
) -> bool {
    unsafe {
        match (creds1.is_null(), creds2.is_null()) {
            (true, true) => true,
            (true, false) => false,
            (false, true) => false,
            (false, false) => {
                let creds1 = Box::from_raw(mut_override(creds1));
                let creds2 = Box::from_raw(mut_override(creds2));

                let ret = creds1.credentials == creds2.credentials;

                core::mem::forget(creds1);
                core::mem::forget(creds2);
                ret
            }
        }
    }
}

fn credentials_to_c(credentials: Credentials) -> *mut RiceCredentials {
    Box::into_raw(Box::new(RiceCredentials { credentials }))
}

/// Retrieve the local ICE credentials currently set on the `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_get_local_credentials(
    stream: *const RiceStream,
) -> *mut RiceCredentials {
    unsafe {
        let stream = Arc::from_raw(stream);
        let proto_agent = stream.proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(stream.stream_id).unwrap();

        let ret = if let Some(credentials) = proto_stream.local_credentials() {
            credentials_to_c(credentials)
        } else {
            mut_override(core::ptr::null::<RiceCredentials>())
        };

        drop(proto_agent);
        core::mem::forget(stream);
        ret
    }
}

/// Retrieve the remote ICE credentials currently set on the `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_get_remote_credentials(
    stream: *const RiceStream,
) -> *mut RiceCredentials {
    unsafe {
        let stream = Arc::from_raw(stream);
        let proto_agent = stream.proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(stream.stream_id).unwrap();

        let ret = if let Some(credentials) = proto_stream.remote_credentials() {
            credentials_to_c(credentials)
        } else {
            mut_override(core::ptr::null::<RiceCredentials>())
        };

        drop(proto_agent);
        core::mem::forget(stream);
        ret
    }
}

unsafe fn string_from_c(cstr: *const c_char) -> String {
    CStr::from_ptr(cstr).to_str().unwrap().to_owned()
}

unsafe fn owned_string_from_c(cstr: *mut c_char) -> CString {
    unsafe { CString::from_raw(cstr) }
}

/// Set the local credentials to use for this `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_set_local_credentials(
    stream: *mut RiceStream,
    credentials: *const RiceCredentials,
) {
    unsafe {
        let creds = Box::from_raw(mut_override(credentials));

        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        proto_stream.set_local_credentials(creds.credentials.clone());
        drop(proto_agent);
        core::mem::forget(stream);
        core::mem::forget(creds);
    }
}

/// Set the remote credentials to use for this `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_set_remote_credentials(
    stream: *mut RiceStream,
    credentials: *const RiceCredentials,
) {
    unsafe {
        let creds = Box::from_raw(mut_override(credentials));

        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        proto_stream.set_remote_credentials(creds.credentials.clone());
        drop(proto_agent);
        core::mem::forget(stream);
        core::mem::forget(creds);
    }
}

/// The type of the TCP candidate.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceTcpType {
    /// Not a TCP candidate.
    None,
    /// The candidate address will connect to a remote address.
    Active,
    /// The candidate will listen for incominng TCP connections.
    Passive,
    /// Simultaneous open.  The candidate will both listen for incoming connections, and connect to
    /// remote addresses.
    So,
}

impl From<Option<crate::candidate::TcpType>> for RiceTcpType {
    fn from(value: Option<crate::candidate::TcpType>) -> Self {
        match value {
            None => RiceTcpType::None,
            Some(crate::candidate::TcpType::Active) => RiceTcpType::Active,
            Some(crate::candidate::TcpType::Passive) => RiceTcpType::Passive,
            Some(crate::candidate::TcpType::So) => RiceTcpType::So,
        }
    }
}

impl From<RiceTcpType> for Option<crate::candidate::TcpType> {
    fn from(value: RiceTcpType) -> Self {
        match value {
            RiceTcpType::None => None,
            RiceTcpType::Active => Some(crate::candidate::TcpType::Active),
            RiceTcpType::Passive => Some(crate::candidate::TcpType::Passive),
            RiceTcpType::So => Some(crate::candidate::TcpType::So),
        }
    }
}

/// The type of the candidate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceCandidateType {
    /// The candidate is a local network interface
    Host,
    /// The candidate was discovered from incoming data
    PeerReflexive,
    /// The candidate was discovered by asking an external server (STUN/TURN)
    ServerReflexive,
    /// The candidate will relay all data through an external server (TURN).
    Relayed,
}

impl From<CandidateType> for RiceCandidateType {
    fn from(value: CandidateType) -> Self {
        match value {
            CandidateType::Host => RiceCandidateType::Host,
            CandidateType::PeerReflexive => RiceCandidateType::PeerReflexive,
            CandidateType::ServerReflexive => RiceCandidateType::ServerReflexive,
            CandidateType::Relayed => RiceCandidateType::Relayed,
        }
    }
}
impl From<RiceCandidateType> for CandidateType {
    fn from(value: RiceCandidateType) -> Self {
        match value {
            RiceCandidateType::Host => CandidateType::Host,
            RiceCandidateType::PeerReflexive => CandidateType::PeerReflexive,
            RiceCandidateType::ServerReflexive => CandidateType::ServerReflexive,
            RiceCandidateType::Relayed => CandidateType::Relayed,
        }
    }
}

/// An ICE candidate.
#[derive(Debug)]
#[repr(C)]
pub struct RiceCandidate {
    component_id: usize,
    candidate_type: RiceCandidateType,
    transport_type: RiceTransportType,
    foundation: *const c_char,
    priority: u32,
    address: *const RiceAddress,
    base_address: *const RiceAddress,
    related_address: *const RiceAddress,
    tcp_type: RiceTcpType,
    extensions: *mut *mut c_char,
    extensions_len: usize,
}

impl RiceCandidate {
    fn zero() -> Self {
        Self {
            component_id: 0,
            candidate_type: RiceCandidateType::Host,
            transport_type: RiceTransportType::Udp,
            foundation: core::ptr::null(),
            priority: 0,
            address: core::ptr::null(),
            base_address: core::ptr::null(),
            related_address: core::ptr::null(),
            tcp_type: RiceTcpType::None,
            extensions: core::ptr::null_mut(),
            extensions_len: 0,
        }
    }

    fn as_rice_none(&self) -> crate::candidate::Candidate {
        unsafe {
            let related_address = if !self.related_address.is_null() {
                Some(RiceAddress::into_rice_none(self.related_address).inner())
            } else {
                None
            };
            let foundation = string_from_c(self.foundation);
            crate::candidate::Candidate {
                component_id: self.component_id,
                candidate_type: self.candidate_type.into(),
                transport_type: transport_type_from_c(self.transport_type),
                foundation,
                priority: self.priority,
                address: RiceAddress::into_rice_none(self.address).inner(),
                base_address: RiceAddress::into_rice_none(self.base_address).inner(),
                related_address,
                tcp_type: self.tcp_type.into(),
                // FIXME
                extensions: vec![],
            }
        }
    }

    fn into_rice_full(self) -> crate::candidate::Candidate {
        unsafe {
            let related_address = if !self.related_address.is_null() {
                Some(RiceAddress::into_rice_full(self.related_address).inner())
            } else {
                None
            };
            let foundation = owned_string_from_c(mut_override(self.foundation));
            crate::candidate::Candidate {
                component_id: self.component_id,
                candidate_type: self.candidate_type.into(),
                transport_type: transport_type_from_c(self.transport_type),
                foundation: foundation.to_str().unwrap().to_owned(),
                priority: self.priority,
                address: RiceAddress::into_rice_full(self.address).inner(),
                base_address: RiceAddress::into_rice_full(self.base_address).inner(),
                related_address,
                tcp_type: self.tcp_type.into(),
                // FIXME
                extensions: vec![],
            }
        }
    }

    fn into_c_full(value: crate::candidate::Candidate) -> Self {
        let address = Box::new(RiceAddress::new(value.address));
        let base_address = Box::new(RiceAddress::new(value.base_address));
        let related_address = if let Some(addr) = value.related_address {
            Box::into_raw(Box::new(RiceAddress::new(addr)))
        } else {
            core::ptr::null()
        };
        Self {
            component_id: value.component_id,
            candidate_type: value.candidate_type.into(),
            transport_type: transport_type_to_c(value.transport_type),
            foundation: CString::new(value.foundation).unwrap().into_raw(),
            priority: value.priority,
            address: Box::into_raw(address),
            base_address: Box::into_raw(base_address),
            related_address,
            tcp_type: value.tcp_type.into(),
            // FIXME
            extensions: core::ptr::null_mut(),
            extensions_len: 0,
        }
    }
}

impl PartialEq<RiceCandidate> for RiceCandidate {
    fn eq(&self, other: &RiceCandidate) -> bool {
        unsafe {
            self.component_id == other.component_id
                && self.candidate_type == other.candidate_type
                && self.transport_type == other.transport_type
                && core::ffi::CStr::from_ptr(self.foundation)
                    == core::ffi::CStr::from_ptr(other.foundation)
                && self.priority == other.priority
                && rice_address_cmp(self.address, other.address) == 0
                && rice_address_cmp(self.base_address, other.base_address) == 0
                && rice_address_cmp(self.related_address, other.related_address) == 0
                && self.tcp_type == other.tcp_type
            // FIXME extensions
        }
    }
}

/// Errors produced when parsing a candidate
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum RiceParseCandidateError {
    /// No error.
    Success = 0,
    /// Not a candidate message.
    NotCandidate = -1,
    /// Invalid foundation value.
    BadFoundation = -2,
    /// Invalid component id.
    BadComponentId = -3,
    /// Invalid transport type.
    BadTransportType = -4,
    /// Invalid priority value.
    BadPriority = -5,
    /// Invalid network address.
    BadAddress = -6,
    /// Invalid candidate type.
    BadCandidateType = -7,
    /// Invalid extension format.
    BadExtension = -8,
    /// Data is not well formed.
    Malformed = -9,
}

impl From<crate::candidate::ParseCandidateError> for RiceParseCandidateError {
    fn from(value: crate::candidate::ParseCandidateError) -> Self {
        match value {
            crate::candidate::ParseCandidateError::NotCandidate => Self::NotCandidate,
            crate::candidate::ParseCandidateError::BadFoundation => Self::BadFoundation,
            crate::candidate::ParseCandidateError::BadComponentId => Self::BadComponentId,
            crate::candidate::ParseCandidateError::BadTransportType => Self::BadTransportType,
            crate::candidate::ParseCandidateError::BadPriority => Self::BadPriority,
            crate::candidate::ParseCandidateError::BadAddress => Self::BadAddress,
            crate::candidate::ParseCandidateError::BadCandidateType => Self::BadCandidateType,
            crate::candidate::ParseCandidateError::BadExtension => Self::BadExtension,
            crate::candidate::ParseCandidateError::Malformed => Self::Malformed,
        }
    }
}

/// Construct a `RiceCandidate` from a string as formatted in an SDP and specified in RFC5245
/// Section 15.1.
///
/// Takes the form 'a=candidate:foundation 1 UDP 12345 127.0.0.1 23456 typ host'.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_new_from_sdp_string(
    cand_str: *const c_char,
) -> *mut RiceCandidate {
    unsafe {
        let candidate = mut_override(Box::into_raw(Box::new(RiceCandidate::zero())));
        let ret = rice_candidate_init_from_sdp_string(candidate, cand_str);
        if ret == RiceParseCandidateError::Success {
            candidate
        } else {
            let _candidate = Box::from_raw(candidate);
            core::ptr::null_mut()
        }
    }
}

/// Construct a `RiceCandidate` from a string as formatted in an SDP and specified in RFC5245
/// Section 15.1.
///
/// Takes the form 'a=candidate:foundation 1 UDP 12345 127.0.0.1 23456 typ host'.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_init_from_sdp_string(
    candidate: *mut RiceCandidate,
    cand_str: *const c_char,
) -> RiceParseCandidateError {
    unsafe {
        let Ok(cand_str) = CStr::from_ptr(cand_str).to_str() else {
            return RiceParseCandidateError::Malformed;
        };
        let r_candidate = match Candidate::from_str(cand_str) {
            Ok(c) => c,
            Err(e) => return e.into(),
        };
        *candidate = RiceCandidate::into_c_full(r_candidate);
        RiceParseCandidateError::Success
    }
}

/// Return a SDP candidate string as specified in RFC5245 Section 15.1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_to_sdp_string(
    candidate: *const RiceCandidate,
) -> *mut c_char {
    unsafe {
        let candidate = Box::from_raw(mut_override(candidate));
        let cand = (*candidate).as_rice_none();
        let ret = CString::new(cand.to_sdp_string()).unwrap();
        core::mem::forget(candidate);
        // FIXME: need to provide a way to free this c string
        ret.into_raw()
    }
}

/// Free an allocated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_string_free(string: *mut c_char) {
    unsafe {
        let _s = CString::from_raw(string);
    }
}

/// Construct a new `RiceCandidate` with the provided values.
///
/// Will return NULL on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_new(
    component_id: usize,
    ctype: RiceCandidateType,
    ttype: RiceTransportType,
    foundation: *const c_char,
    address: *mut RiceAddress,
) -> *mut RiceCandidate {
    unsafe {
        let candidate = mut_override(Box::into_raw(Box::new(RiceCandidate::zero())));
        let ret = rice_candidate_init(candidate, component_id, ctype, ttype, foundation, address);
        if ret == RiceError::Success {
            candidate
        } else {
            let _candidate = Box::from_raw(candidate);
            core::ptr::null_mut()
        }
    }
}

/// Construct a new `RiceCandidate` with the provided values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_init(
    candidate: *mut RiceCandidate,
    component_id: usize,
    ctype: RiceCandidateType,
    ttype: RiceTransportType,
    foundation: *const c_char,
    address: *mut RiceAddress,
) -> RiceError {
    unsafe {
        if foundation.is_null() || address.is_null() {
            return RiceError::Failed;
        }
        let foundation = CStr::from_ptr(foundation);
        let Ok(foundation) = foundation.to_str() else {
            return RiceError::Failed;
        };
        let Ok(foundation_s) = CString::new(foundation) else {
            return RiceError::Failed;
        };
        let foundation = foundation_s.as_ptr();
        core::mem::forget(foundation_s);
        *candidate = RiceCandidate {
            component_id,
            candidate_type: ctype,
            transport_type: ttype,
            foundation,
            priority: 0,
            address: rice_address_copy(address),
            base_address: address,
            related_address: core::ptr::null_mut(),
            tcp_type: RiceTcpType::None,
            extensions: core::ptr::null_mut(),
            extensions_len: 0,
        };
        RiceError::Success
    }
}

/// Set the base address of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_set_priority(candidate: *mut RiceCandidate, priority: u32) {
    unsafe {
        let mut candidate = Box::from_raw(candidate);
        candidate.priority = priority;
        core::mem::forget(candidate);
    }
}

/// Set the base address of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_set_base_address(
    candidate: *mut RiceCandidate,
    base_address: *mut RiceAddress,
) {
    unsafe {
        let mut candidate = Box::from_raw(candidate);
        let old = candidate.base_address;
        candidate.base_address = base_address;
        rice_address_free(mut_override(old));
        core::mem::forget(candidate);
    }
}

/// Set the related address of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_set_related_address(
    candidate: *mut RiceCandidate,
    related_address: *mut RiceAddress,
) {
    unsafe {
        let mut candidate = Box::from_raw(candidate);
        let old = candidate.related_address;
        candidate.related_address = related_address;
        rice_address_free(mut_override(old));
        core::mem::forget(candidate);
    }
}

/// Set the tcp type of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_set_tcp_type(
    candidate: *mut RiceCandidate,
    tcp_type: RiceTcpType,
) {
    unsafe {
        let mut candidate = Box::from_raw(candidate);
        candidate.tcp_type = tcp_type;
        core::mem::forget(candidate);
    }
}

/// Perform a deep copy of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_copy(
    candidate: *const RiceCandidate,
) -> *mut RiceCandidate {
    unsafe {
        if candidate.is_null() {
            return core::ptr::null_mut();
        }
        let ret = mut_override(Box::into_raw(Box::new(RiceCandidate::zero())));
        rice_candidate_copy_into(candidate, ret);
        ret
    }
}

/// Perform a deep copy of a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_copy_into(
    candidate: *const RiceCandidate,
    ret: *mut RiceCandidate,
) {
    unsafe {
        if candidate.is_null() {
            return;
        }
        let candidate = Box::from_raw(mut_override(candidate));
        let foundation = CString::from_raw(mut_override(candidate.foundation));
        *ret = RiceCandidate {
            component_id: candidate.component_id,
            candidate_type: candidate.candidate_type,
            transport_type: candidate.transport_type,
            foundation: foundation.clone().into_raw(),
            priority: candidate.priority,
            address: rice_address_copy(candidate.address),
            base_address: rice_address_copy(candidate.base_address),
            related_address: if candidate.related_address.is_null() {
                core::ptr::null()
            } else {
                rice_address_copy(candidate.related_address)
            },
            tcp_type: candidate.tcp_type,
            // FIXME: extensions
            extensions: core::ptr::null_mut(),
            extensions_len: candidate.extensions_len,
        };
        core::mem::forget(candidate);
        core::mem::forget(foundation);
    }
}

/// Clear any resources allocated within a `RiceCandidate`.
///
/// Useful for stack-allocated `RiceCandidate`s or when embedded in other structures.
///
/// This function is NULL safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_clear(candidate: *mut RiceCandidate) {
    unsafe {
        if candidate.is_null() {
            return;
        }
        if !(*candidate).foundation.is_null() {
            let _foundation = CString::from_raw(mut_override((*candidate).foundation));
        }
        if !(*candidate).address.is_null() {
            let _address = RiceAddress::into_rice_full((*candidate).address);
        }
        if !(*candidate).base_address.is_null() {
            let _base_address = RiceAddress::into_rice_full((*candidate).base_address);
        }
        if !(*candidate).related_address.is_null() {
            let _related_address = RiceAddress::into_rice_full((*candidate).related_address);
        }
        rice_candidate_zero(&mut *candidate);
        // FIXME extensions
    }
}

fn rice_candidate_zero(candidate: &mut RiceCandidate) {
    candidate.foundation = core::ptr::null_mut();
    candidate.address = core::ptr::null_mut();
    candidate.base_address = core::ptr::null_mut();
    candidate.related_address = core::ptr::null_mut();
    // FIXME extensions
}

/// Free a `RiceCandidate`.
///
/// This function is NULL safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_free(candidate: *mut RiceCandidate) {
    unsafe {
        if candidate.is_null() {
            return;
        }
        rice_candidate_clear(candidate);
        let _cand = Box::from_raw(candidate);
    }
}

/// Free a `RiceCandidate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_candidate_eq(
    candidate: *const RiceCandidate,
    other: *const RiceCandidate,
) -> bool {
    unsafe {
        let cand = Box::from_raw(mut_override(candidate));
        let other = Box::from_raw(mut_override(other));

        let ret = *candidate == *other;

        core::mem::forget(cand);
        core::mem::forget(other);

        ret
    }
}

/// A local candidate that has been gathered.
#[derive(Debug)]
#[repr(C)]
pub struct RiceGatheredCandidate {
    candidate: RiceCandidate,
    turn_agent: *mut c_void,
}

impl RiceGatheredCandidate {
    fn zero() -> Self {
        Self {
            candidate: RiceCandidate::zero(),
            turn_agent: core::ptr::null_mut(),
        }
    }

    fn into_rice_full(self) -> GatheredCandidate {
        unsafe {
            let candidate = self.candidate.into_rice_full();
            let turn_agent = if self.turn_agent.is_null() {
                None
            } else {
                Some(Box::from_raw(self.turn_agent as *mut TurnClient))
            };
            GatheredCandidate {
                candidate,
                turn_agent,
            }
        }
    }

    fn into_c_full(value: GatheredCandidate) -> Self {
        let candidate = RiceCandidate::into_c_full(value.candidate);
        let turn_agent = if let Some(turn_agent) = value.turn_agent {
            Box::into_raw(turn_agent)
        } else {
            core::ptr::null_mut()
        };
        Self {
            candidate,
            turn_agent: turn_agent as *mut c_void,
        }
    }
}

/// Add a local `RiceGatheredCandidate` to a `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_add_local_gathered_candidate(
    stream: *mut RiceStream,
    candidate: *const RiceGatheredCandidate,
) -> bool {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        let candidate = mut_override(candidate);
        let mut swapped = RiceGatheredCandidate::zero();
        core::ptr::swap(&mut swapped, candidate);

        let ret = proto_stream.add_local_gathered_candidate(swapped.into_rice_full());
        drop(proto_agent);
        core::mem::forget(stream);
        ret
    }
}

/// Add a remote candidate to the `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_add_remote_candidate(
    stream: *mut RiceStream,
    candidate: *const RiceCandidate,
) {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        let candidate = Box::from_raw(mut_override(candidate));

        proto_stream.add_remote_candidate((*candidate).as_rice_none());
        drop(proto_agent);
        core::mem::forget(stream);
        core::mem::forget(candidate);
    }
}

/// Signal the end of a set of local candidates.
///
/// Any local candidates provided after calling this function will result in an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_end_of_local_candidates(stream: *mut RiceStream) {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

        proto_stream.end_of_local_candidates();
        drop(proto_agent);
        core::mem::forget(stream);
    }
}

/// Signal the end of a set of remote candidates.
///
/// Any remote candidates provided after calling this function will result in an error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_end_of_remote_candidates(stream: *mut RiceStream) {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

        proto_stream.end_of_remote_candidates();
        drop(proto_agent);
        core::mem::forget(stream);
    }
}

/// Return value for `rice_stream_handle_incoming_data()`.
#[derive(Debug)]
#[repr(C)]
pub struct RiceStreamIncomingData {
    /// The data was handled internally. `rice_agent_poll()` should be called at the
    /// next earliest opportunity.
    handled: bool,
    /// Whether there is more data to pull using `rice_stream_poll_recv()`.
    have_more_data: bool,
    /// The data pointer. If non-NULL, this is the same value as provided to
    /// `rice_stream_handle_incoming_data()` and has the same lifetime contraints as that original
    /// data pointer.
    data: RiceDataImpl,
}

/// Provide data to the `RiceStream` for processing.
///
/// The returned value contains what processing was completed on the provided data and any
/// application data that needs to be handled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_handle_incoming_data(
    stream: *mut RiceStream,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    data: *const u8,
    data_len: usize,
    now_nanos: i64,
    ret: *mut MaybeUninit<RiceStreamIncomingData>,
) {
    unsafe {
        let stream = Arc::from_raw(stream);
        let now = Instant::from_nanos(now_nanos);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        let from = Box::from_raw(mut_override(from));
        let to = Box::from_raw(mut_override(to));

        let transmit = Transmit {
            transport: transport_type_from_c(transport),
            from: **from,
            to: **to,
            data: Data::Borrowed(DataSlice::from(core::slice::from_raw_parts(data, data_len))),
        };
        core::mem::forget(from);
        core::mem::forget(to);

        let stream_ret = proto_stream.handle_incoming_data(component_id, transmit, now);
        let data = if let Some(_data_and_range) = stream_ret.data {
            RiceDataImpl {
                ptr: mut_override(data),
                size: data_len,
            }
        } else {
            RiceDataImpl {
                ptr: core::ptr::null_mut(),
                size: 0,
            }
        };

        (*ret).write(RiceStreamIncomingData {
            handled: stream_ret.handled,
            have_more_data: stream_ret.have_more_data,
            data,
        });

        drop(proto_agent);
        core::mem::forget(stream);
    }
}

/// Poll for further application data that has been received.
///
/// Free the returned data with `rice_free_data()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_poll_recv(
    stream: *mut RiceStream,
    component_id: *mut usize,
    data_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

        let ret = if let Some(data) = proto_stream.poll_recv() {
            *data_len = data.data.len();
            *component_id = data.component_id;
            Box::into_raw(data.data.into_boxed_slice()) as *mut _
        } else {
            *data_len = 0;
            *component_id = 0;
            core::ptr::null_mut::<u8>()
        };

        drop(proto_agent);
        core::mem::forget(stream);

        ret
    }
}

/// Free allocated data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_free_data(data: *mut u8) {
    unsafe {
        let _ = Box::from_raw(data);
    }
}

/// Return the component ids currently in use by a `RiceStream`.
///
/// `ret` can be NULL to discover the length of the data that would be provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_component_ids(
    stream: *mut RiceStream,
    len: *mut usize,
    ret: *mut usize,
) {
    unsafe {
        let stream = Arc::from_raw(stream);

        let proto_agent = stream.proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(stream.stream_id).unwrap();

        if ret.is_null() {
            *len = proto_stream.component_ids_iter().count()
        } else if *len > 0 {
            let output = core::slice::from_raw_parts_mut(ret, *len);
            *len = 0;
            for component in proto_stream.component_ids_iter() {
                output[*len] = component;
                if *len + 1 > output.len() {
                    break;
                }
                *len += 1;
            }
        }

        drop(proto_agent);
        core::mem::forget(stream);
    }
}

// TODO:
// - local_candidates

/// An ICE component within a `RiceStream`.
#[derive(Debug)]
pub struct RiceComponent {
    proto_agent: Arc<Mutex<Agent>>,
    weak_agent: Weak<RiceAgent>,
    stream_id: usize,
    component_id: usize,
}

/// Add an ICE component to a `RiceStream`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_add_component(stream: *mut RiceStream) -> *mut RiceComponent {
    unsafe {
        let stream = Arc::from_raw(stream);
        let mut proto_agent = stream.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
        let component_id = proto_stream.add_component().unwrap();
        let component = Arc::new(RiceComponent {
            proto_agent: stream.proto_agent.clone(),
            weak_agent: stream.weak_agent.clone(),
            stream_id: stream.stream_id,
            component_id,
        });
        drop(proto_agent);

        let mut inner = stream.inner.lock().unwrap();
        inner.components.push(component.clone());

        drop(inner);
        core::mem::forget(stream);
        mut_override(Arc::into_raw(component))
    }
}

/// Increase the reference count of the `RiceComponent`.
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_ref(component: *const RiceComponent) -> *mut RiceComponent {
    unsafe {
        Arc::increment_strong_count(component);
        mut_override(component)
    }
}

/// Decrease the reference count of the `RiceComponent`.
///
/// If this is the last reference, then the `RiceComponent` is freed (but will still be referenced by
/// the `RiceStream`).
///
/// This function is multi-threading safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_unref(component: *mut RiceComponent) {
    unsafe { Arc::decrement_strong_count(component) }
}

/// Retrieve the component id of the `RiceComponent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_get_id(component: *const RiceComponent) -> usize {
    unsafe {
        let component = Arc::from_raw(mut_override(component));
        let ret = component.component_id;
        core::mem::forget(component);
        ret
    }
}

/// Retrieve the component id of the `RiceComponent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_get_stream(
    component: *const RiceComponent,
) -> *mut RiceStream {
    unsafe {
        let component = Arc::from_raw(mut_override(component));
        let Some(agent) = component.weak_agent.upgrade() else {
            core::mem::forget(component);
            return core::ptr::null_mut();
        };
        let inner = agent.inner.lock().unwrap();
        let Some(stream) = inner
            .streams
            .iter()
            .find(|stream| component.stream_id == stream.stream_id)
            .cloned()
        else {
            core::mem::forget(component);
            return core::ptr::null_mut();
        };
        drop(inner);
        core::mem::forget(component);
        mut_override(Arc::into_raw(stream))
    }
}

/// Retrieve the component connection state of the `RiceComponent`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_get_state(
    component: *const RiceComponent,
) -> ComponentConnectionState {
    unsafe {
        let component = Arc::from_raw(mut_override(component));
        let proto_agent = component.proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(component.stream_id).unwrap();
        let proto_component = proto_stream.component(component.component_id).unwrap();
        let ret = proto_component.state();
        drop(proto_agent);
        core::mem::forget(component);
        ret
    }
}

/// Retrieve the ICE candidates selected pair of the `RiceComponent`.
///
/// Before the pair has been selected through ICE, `local` and `remote` will be zeroed to signal
/// unset.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_selected_pair(
    component: *const RiceComponent,
    local: *mut RiceCandidate,
    remote: *mut RiceCandidate,
) {
    unsafe {
        let component = Arc::from_raw(mut_override(component));
        let proto_agent = component.proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(component.stream_id).unwrap();
        let proto_component = proto_stream.component(component.component_id).unwrap();
        if let Some(pair) = proto_component.selected_pair().cloned() {
            *local = RiceCandidate::into_c_full(pair.local);
            *remote = RiceCandidate::into_c_full(pair.remote);
        } else {
            *local = RiceCandidate::zero();
            *remote = RiceCandidate::zero();
        };
        drop(proto_agent);
        core::mem::forget(component);
    }
}

/// Retrieve a previously added `RiceComponent`.
///
/// If the `RiceComponent` does not exist, `NULL` is returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_stream_get_component(
    stream: *const RiceStream,
    component_id: usize,
) -> *mut RiceComponent {
    unsafe {
        if component_id < 1 {
            return mut_override(core::ptr::null::<RiceComponent>());
        }
        let stream = Arc::from_raw(stream);
        let inner = stream.inner.lock().unwrap();
        let ret = if let Some(component) = inner.components.get(component_id - 1) {
            mut_override(Arc::into_raw(component.clone()))
        } else {
            return mut_override(core::ptr::null::<RiceComponent>());
        };

        drop(inner);
        core::mem::forget(stream);
        ret
    }
}

/// Start gathering candidates for a component with the provided local socket addresses.
///
/// - `component`: The component to start gathering.
/// - `sockets_len`: The number of entries in both `sockets_addr` and `sockets_transports`.
/// - `sockets_addr`: An array of addresses for producing host and STUN server-reflexive
///   candidates.
/// - `sockets_transports`: An array of transport types for producing host and STUN
///   server-reflexive candidates.
/// - `turn_len`: the number of entries in both `turn_sockets` and `turn_config`.
/// - `turn_sockets`: An array of local addresses for producing TURN candidates.
/// - `turn_config`: An array of TURN server configurations.
///
/// Candidates will be generated as follows (if they succeed):
///
/// 1. A host candidate for each `(sockets_transports[i], socket_addr[i])`. If TCP, then both an
///    active and passive host candidate will be generated.
/// 2. For each configured STUN server, a reflexive candidate for each
///    `(sockets_transports[i], socket_addr[i])` if different from any other candidate
///    produced. The local address for each STUN server connection will be one of the entries
///    provided in `sockets_addr`.
/// 3. For each `(turn_sockets[i], turn_config[i])` a TURN allocation will be attempted and a
///    relayed candidate produced on success.  If you would like multiple options for relayed
///    candidates, e.g. UDP, TCP, TCP/TLS, then provide each options as different entries in the
///    provided array. The `turn_sockets[i]` value is the local address to communicate with the
///    TURN server in `turn_config[i]` and should be different than any value provided through
///    `sockets_addr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_gather_candidates(
    component: *mut RiceComponent,
    sockets_len: usize,
    sockets_addr: *const *const RiceAddress,
    sockets_transports: *const RiceTransportType,
    turn_len: usize,
    turn_sockets: *const *const RiceAddress,
    turn_config: *const *mut RiceTurnConfig,
) -> RiceError {
    unsafe {
        let component = Arc::from_raw(component);
        let stun_servers = {
            let Some(agent) = component.weak_agent.upgrade() else {
                core::mem::forget(component);
                return RiceError::ResourceNotFound;
            };
            let agent = agent.inner.lock().unwrap();
            agent.stun_servers.clone()
        };
        debug!("stun_servers: {stun_servers:?}");
        let mut proto_agent = component.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(component.stream_id).unwrap();
        let mut proto_component = proto_stream.mut_component(component.component_id).unwrap();

        let sockets_addr = core::slice::from_raw_parts(sockets_addr, sockets_len);
        let sockets_transport = core::slice::from_raw_parts(sockets_transports, sockets_len);

        let sockets = sockets_transport
            .iter()
            .zip(sockets_addr.iter())
            .map(|(&transport, addr)| {
                let socket_addr = RiceAddress::into_rice_none(*addr).inner();
                (transport_type_from_c(transport), socket_addr)
            })
            .collect::<Vec<_>>();

        debug!("sockets: {sockets:?}");

        let turn_sockets = if turn_len > 0 {
            core::slice::from_raw_parts(turn_sockets, turn_len)
        } else {
            &[]
        };
        let turn_configs = if turn_len > 0 {
            core::slice::from_raw_parts(turn_config, turn_len)
                .iter()
                .map(|config| RiceTurnConfig::into_rice_full(*config))
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let turn_servers = turn_sockets
            .iter()
            .zip(turn_configs.iter())
            .map(|(socket, config)| {
                let turn_addr = RiceAddress::into_rice_none(*socket);
                (turn_addr.inner(), &config.0)
            })
            .collect::<Vec<_>>();
        debug!("turn_servers: {turn_servers:?}");

        let ret =
            proto_component.gather_candidates(&sockets, &stun_servers, turn_servers.as_slice());
        drop(proto_agent);
        core::mem::forget(component);

        match ret {
            Ok(()) => RiceError::Success,
            Err(AgentError::AlreadyInProgress) => RiceError::AlreadyInProgress,
            Err(AgentError::ResourceNotFound) => RiceError::ResourceNotFound,
            Err(_) => RiceError::Failed,
        }
    }
}

/// Send data to the connected peer.
///
/// This will fail before a connection is successfully completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_send(
    component: *mut RiceComponent,
    data: *mut u8,
    len: usize,
    now_nanos: i64,
    transmit: *mut RiceTransmit,
) -> RiceError {
    unsafe {
        let component = Arc::from_raw(component);
        let now = Instant::from_nanos(now_nanos);

        let mut proto_agent = component.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(component.stream_id).unwrap();
        let mut proto_component = proto_stream.mut_component(component.component_id).unwrap();

        let bytes = Data::from(core::slice::from_raw_parts(data, len));
        let ret = match proto_component.send(bytes, now) {
            Ok(stun_transmit) => {
                *transmit = RiceTransmit {
                    stream_id: component.stream_id,
                    transport: transport_type_to_c(stun_transmit.transport),
                    from: Box::into_raw(Box::new(RiceAddress::new(stun_transmit.from))),
                    to: Box::into_raw(Box::new(RiceAddress::new(stun_transmit.to))),
                    data: RiceDataImpl::owned_to_c(stun_transmit.data),
                };
                RiceError::Success
            }
            Err(e) => {
                warn!("Failed to send data: {e:?}");
                RiceError::Failed
            }
        };

        drop(proto_agent);
        core::mem::forget(component);

        ret
    }
}

/// Start gathering candidates for a component with the provided local socket addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_component_set_selected_pair(
    component: *mut RiceComponent,
    local: *const RiceCandidate,
    remote: *const RiceCandidate,
) -> RiceError {
    unsafe {
        let component = Arc::from_raw(component);

        let local = Box::from_raw(mut_override(local));
        let remote = Box::from_raw(mut_override(remote));

        let mut proto_agent = component.proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(component.stream_id).unwrap();
        let mut proto_component = proto_stream.mut_component(component.component_id).unwrap();

        let ret = proto_component.set_selected_pair(CandidatePair::new(
            (*local).as_rice_none(),
            (*remote).as_rice_none(),
        ));

        drop(proto_agent);
        core::mem::forget(component);
        core::mem::forget(local);
        core::mem::forget(remote);

        if ret.is_err() {
            RiceError::Failed
        } else {
            RiceError::Success
        }
    }
}

// TODO:
// - selected_pair

/// Create a `RiceAddress` from a string representation of the socket address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_new_from_string(string: *const c_char) -> *mut RiceAddress {
    unsafe { rice_ctypes::rice_address_new_from_string(string) }
}

/// The address family.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceAddressFamily {
    /// IP version 4.
    Ipv4 = 1,
    /// IP version 6.
    Ipv6,
}

impl RiceAddressFamily {
    fn from_rice(family: AddressFamily) -> Self {
        match family {
            AddressFamily::IPV4 => Self::Ipv4,
            AddressFamily::IPV6 => Self::Ipv6,
        }
    }

    fn into_rice(self) -> AddressFamily {
        match self {
            Self::Ipv4 => AddressFamily::IPV4,
            Self::Ipv6 => AddressFamily::IPV6,
        }
    }
}

/// Construct a `RiceAddress` from a sequence of bytes.
///
/// The number of bytes required depends on the address family being constructed:
/// - IPv4 -> 4.
/// - IPv6 -> 16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_new_from_bytes(
    family: RiceAddressFamily,
    bytes: *const u8,
    port: u16,
) -> *mut RiceAddress {
    unsafe {
        let ip_addr = match family {
            RiceAddressFamily::Ipv4 => {
                let bytes = core::slice::from_raw_parts(bytes, 4);
                IpAddr::V4(Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            RiceAddressFamily::Ipv6 => {
                let bytes = core::slice::from_raw_parts(bytes, 16);
                IpAddr::V6(Ipv6Addr::from([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                    bytes[15],
                ]))
            }
        };
        Box::into_raw(Box::new(RiceAddress::new(SocketAddr::new(ip_addr, port))))
    }
}

/// The address family of the `RiceAddress`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_get_family(addr: *const RiceAddress) -> RiceAddressFamily {
    unsafe {
        let addr = RiceAddress::into_rice_none(addr);
        match addr.inner() {
            SocketAddr::V4(_) => RiceAddressFamily::Ipv4,
            SocketAddr::V6(_) => RiceAddressFamily::Ipv6,
        }
    }
}

/// Retrieve the bytes of a `RiceAddress`.
///
/// The number of bytes required depends on the address family being constructed:
/// - IPv4 -> 4.
/// - IPv6 -> 16.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_get_address_bytes(
    addr: *const RiceAddress,
    bytes: *mut u8,
) -> usize {
    unsafe {
        let addr = RiceAddress::into_rice_none(addr);
        let ret = match addr.inner().ip() {
            IpAddr::V4(ip) => {
                let bytes = core::slice::from_raw_parts_mut(bytes, 4);
                for (i, octet) in ip.octets().into_iter().enumerate() {
                    bytes[i] = octet;
                }
                4
            }
            IpAddr::V6(ip) => {
                let bytes = core::slice::from_raw_parts_mut(bytes, 16);
                for (i, octet) in ip.octets().into_iter().enumerate() {
                    bytes[i] = octet;
                }
                16
            }
        };
        ret
    }
}

/// Retrieve the port of a `RiceAddress`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_get_port(addr: *const RiceAddress) -> u16 {
    unsafe {
        let addr = RiceAddress::into_rice_none(addr);
        addr.inner().port()
    }
}

/// Compare whether two `RiceAddress`es are equal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_cmp(
    addr: *const RiceAddress,
    other: *const RiceAddress,
) -> c_int {
    unsafe { rice_ctypes::rice_address_cmp(addr, other) }
}

/// Copy a `RiceAddress`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_copy(addr: *const RiceAddress) -> *mut RiceAddress {
    unsafe {
        if addr.is_null() {
            return core::ptr::null_mut();
        }
        let addr = RiceAddress::into_rice_none(mut_override(addr));
        mut_override(RiceAddress::new(addr.inner()).into_c_full())
    }
}

/// Free a `RiceAddress`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_address_free(addr: *mut RiceAddress) {
    unsafe { rice_ctypes::rice_address_free(addr) }
}

/// Generate a random sequence of characters suitable for username fragments and passwords.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rice_random_string(length: usize) -> *mut c_char {
    unsafe {
        if length == 0 {
            return core::ptr::null_mut();
        }
        CString::new(crate::random_string(length))
            .unwrap()
            .into_raw()
    }
}

fn mut_override<T>(val: *const T) -> *mut T {
    val as *mut T
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{Candidate, TcpType};

    use alloc::string::ToString;

    use std::eprintln;

    #[test]
    fn test_rice_version() {
        unsafe {
            let mut major = 0;
            let mut minor = 0;
            let mut patch = 0;
            rice_version(&mut major, &mut minor, &mut patch);
            eprintln!("Rice version: {major}.{minor}.{patch}");
        }
    }

    #[test]
    fn rice_address() {
        unsafe {
            let s = CString::new("127.0.0.1:2000").unwrap();
            let addr = rice_address_new_from_string(s.as_ptr());
            let addr2 = rice_address_copy(addr);
            rice_address_free(addr);
            rice_address_free(addr2);
        }
    }

    #[test]
    fn rice_candidate() {
        let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Tcp,
            "foundation",
            addr,
        )
        .related_address(addr)
        .priority(1234)
        .tcp_type(TcpType::Passive)
        .build();
        let rcand = RiceCandidate::into_c_full(candidate.clone());
        let cpy = unsafe { rice_candidate_copy(&rcand) };
        let new_cand: Candidate = rcand.into_rice_full();
        assert_eq!(candidate, new_cand);
        unsafe { rice_candidate_free(cpy) };
    }

    #[test]
    fn rice_agent_properties() {
        unsafe {
            let agent = rice_agent_new(true, false);
            assert!(rice_agent_get_controlling(agent));
            rice_agent_unref(agent);
        }
    }

    #[test]
    fn rice_refs() {
        unsafe {
            let agent = rice_agent_new(true, false);
            let agent = rice_agent_ref(agent);
            let stream = rice_agent_add_stream(agent);
            rice_stream_unref(stream);
            let stream = rice_agent_get_stream(agent, 0);
            let stream = rice_stream_ref(stream);
            let component = rice_stream_add_component(stream);
            rice_component_unref(component);
            let component = rice_stream_get_component(stream, 1);
            let component = rice_component_ref(component);
            rice_agent_unref(agent);
            rice_agent_unref(agent);
            rice_stream_unref(stream);
            rice_stream_unref(stream);
            rice_component_unref(component);
            rice_component_unref(component);
        }
    }

    #[test]
    fn rice_agent_gather() {
        unsafe {
            let addr: SocketAddr = "192.168.0.1:1000".parse().unwrap();
            let addr = RiceAddress::new(addr).into_c_full();
            let stun_addr: SocketAddr = "102.168.0.200:2000".parse().unwrap();
            let stun_addr = RiceAddress::new(stun_addr).into_c_full();
            let agent = rice_agent_new(true, false);
            let stream = rice_agent_add_stream(agent);
            let component = rice_stream_add_component(stream);
            let transport = TransportType::Tcp;
            let local_credentials =
                credentials_to_c(Credentials::new("luser".to_string(), "lpass".to_string()));
            let remote_credentials =
                credentials_to_c(Credentials::new("ruser".to_string(), "rpass".to_string()));

            rice_agent_add_stun_server(agent, transport_type_to_c(transport), stun_addr);
            rice_address_free(mut_override(stun_addr));
            rice_stream_set_local_credentials(stream, local_credentials);
            rice_credentials_free(local_credentials);
            rice_stream_set_remote_credentials(stream, remote_credentials);
            rice_credentials_free(remote_credentials);
            rice_component_gather_candidates(
                component,
                1,
                &addr,
                &transport_type_to_c(transport),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            rice_address_free(mut_override(addr));

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            let RiceAgentPoll::AllocateSocket(ref alloc) = poll else {
                unreachable!()
            };
            let to = rice_address_copy(alloc.to);
            let from = rice_address_copy(alloc.from);
            let component_id = alloc.component_id;
            rice_agent_poll_clear(&mut poll);

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            let RiceAgentPoll::GatheredCandidate(ref _candidate) = poll else {
                unreachable!()
            };
            rice_agent_poll_clear(&mut poll);

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            let RiceAgentPoll::GatheredCandidate(ref _candidate) = poll else {
                unreachable!()
            };
            rice_agent_poll_clear(&mut poll);

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            let RiceAgentPoll::WaitUntilNanos(_now) = poll else {
                unreachable!()
            };
            rice_agent_poll_clear(&mut poll);

            let tcp_from_addr = "192.168.200.4:3000".parse().unwrap();
            let tcp_from_addr = mut_override(RiceAddress::new(tcp_from_addr).into_c_full());
            rice_stream_handle_allocated_socket(
                stream,
                component_id,
                RiceTransportType::Tcp,
                from,
                to,
                tcp_from_addr,
                0,
            );
            rice_address_free(from);
            rice_address_free(to);

            let mut transmit = RiceTransmit::default();
            rice_agent_poll_transmit(agent, 0, &mut transmit);
            rice_transmit_clear(&mut transmit);

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            rice_agent_poll_clear(&mut poll);

            let mut ret = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut ret);
            rice_agent_poll_clear(&mut ret);

            rice_component_unref(component);
            rice_stream_unref(stream);
            rice_agent_unref(agent);
        }
    }

    #[test]
    fn rice_agent_poll_transmit_null() {
        unsafe {
            let agent = rice_agent_new(true, false);
            let stream = rice_agent_add_stream(agent);

            let mut transmit = RiceTransmit::default();
            rice_agent_poll_transmit(agent, 0, &mut transmit);
            assert!(transmit.from.is_null());
            assert!(transmit.to.is_null());
            assert!(transmit.data.ptr.is_null());
            rice_agent_unref(agent);
            rice_stream_unref(stream);
        }
    }

    #[test]
    fn rice_credentials_accessors() {
        unsafe {
            let credentials =
                credentials_to_c(Credentials::new("luser".to_string(), "lpass".to_string()));
            let mut bytes = [0; 256];
            let len = rice_credentials_get_ufrag_bytes(credentials, bytes.as_mut_ptr());
            let c_str = CStr::from_ptr(bytes.as_ptr());
            let s = c_str.to_str().expect("Bad encoding!");
            assert_eq!(s, "luser");
            assert_eq!(len, 5);
            rice_credentials_free(credentials);
        }
    }
}
