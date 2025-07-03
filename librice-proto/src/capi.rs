// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// everything will be unsafe since this is a FFI
#![allow(clippy::missing_safety_doc)]
#![deny(improper_ctypes_definitions)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use core::mem::MaybeUninit;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once, Weak};
use std::time::{Duration, Instant};

use crate::agent::Agent;
pub use crate::agent::AgentPoll;
use crate::agent::TurnCredentials;
use crate::candidate::{Candidate, CandidateType, TransportType};
pub use crate::component::ComponentConnectionState;
use crate::gathering::GatheredCandidate;
use crate::stream::Credentials;
use stun_proto::agent::{StunError, Transmit};
use stun_proto::types::data::{Data, DataOwned, DataSlice};
use turn_client_proto::TurnClient;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

static TRACING: Once = Once::new();

fn init_logs() {
    TRACING.call_once(|| {
        let level_filter = std::env::var("RICE_LOG")
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
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

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RiceError {
    Success = 0,
    Failed = -1,
    NotFound = -2,
}

/// The transport family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceTransportType {
    /// The UDP transport
    Udp,
    /// The TCP transport
    Tcp,
}

impl From<TransportType> for RiceTransportType {
    fn from(value: TransportType) -> Self {
        match value {
            TransportType::Udp => Self::Udp,
            TransportType::Tcp => Self::Tcp,
        }
    }
}

impl From<RiceTransportType> for TransportType {
    fn from(value: RiceTransportType) -> Self {
        match value {
            RiceTransportType::Udp => Self::Udp,
            RiceTransportType::Tcp => Self::Tcp,
        }
    }
}

#[derive(Debug)]
struct RiceAgentInner {
    stun_servers: Vec<(TransportType, SocketAddr)>,
    turn_servers: Vec<(TransportType, SocketAddr, TurnCredentials)>,
    streams: Vec<Arc<RiceStream>>,
}

/// The Rice Agent used for interacting with the ICE process.
#[derive(Debug)]
pub struct RiceAgent {
    proto_agent: Arc<Mutex<Agent>>,
    inner: Arc<Mutex<RiceAgentInner>>,
    base_instant: Instant,
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_new(controlling: bool, trickle_ice: bool) -> *mut RiceAgent {
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
            turn_servers: vec![],
            streams: vec![],
        })),
        base_instant: Instant::now(),
    });

    mut_override(Arc::into_raw(agent))
}

/// Increase the reference count of the `RiceAgent`.
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_ref(agent: *mut RiceAgent) -> *mut RiceAgent {
    Arc::increment_strong_count(agent);
    agent
}

/// Decrease the reference count of the `RiceAgent`.
///
/// If this is the last reference, then the `RiceAgent` is freed.
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_unref(agent: *mut RiceAgent) {
    Arc::decrement_strong_count(agent)
}

/// Close the `RiceAgent`.
///
/// Closure does involve closing network resources (signalled through calls to
/// `rice_agent_poll()`) and will only succesfully complete once `rice_agent_poll`() returns
/// `Closed`.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_close(agent: *mut RiceAgent) {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    proto_agent.close().unwrap();

    drop(proto_agent);
    core::mem::forget(agent);
}

/// Get the controlling state of the `RiceAgent`.
///
/// A return value of `true` indicates the `RiceAgent` is in controlling mode, false the controlled
/// mode.  This value can change during ICE processing.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_get_controlling(agent: *mut RiceAgent) -> bool {
    let agent = Arc::from_raw(agent);
    let proto_agent = agent.proto_agent.lock().unwrap();
    let ret = proto_agent.controlling();

    drop(proto_agent);
    core::mem::forget(agent);
    ret
}

/// Return value of `rice_agent_poll()`.
#[derive(Debug)]
#[repr(C)]
pub enum RiceAgentPoll {
    /// The Agent is closed.  No further progress will be made.
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event)
    WaitUntilMicros(u64),
    /// Connect from the specified interface to the specified address.  Reply (success or failure)
    /// should be notified using [`rice_agent_allocated_socket`] with the same parameters.
    AllocateSocket(RiceAgentAllocateSocket),
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
    fn from_rust(poll: AgentPoll, base_instant: Instant) -> Self {
        match poll {
            AgentPoll::Closed => Self::Closed,
            AgentPoll::WaitUntil(instant) => Self::WaitUntilMicros(
                instant.saturating_duration_since(base_instant).as_micros() as u64,
            ),
            AgentPoll::AllocateSocket(connect) => Self::AllocateSocket(connect.into()),
            AgentPoll::SelectedPair(pair) => Self::SelectedPair(pair.into()),
            AgentPoll::ComponentStateChange(state) => Self::ComponentStateChange(state.into()),
            AgentPoll::GatheredCandidate(gathered) => Self::GatheredCandidate(gathered.into()),
            AgentPoll::GatheringComplete(complete) => Self::GatheringComplete(complete.into()),
        }
    }
}

/// A sequence of bytes and size.
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
        Box::from_raw(core::slice::from_raw_parts_mut(self.ptr, self.size))
    }

    fn owned_to_c(val: Box<[u8]>) -> Self {
        let size = val.len();
        let ptr = Box::into_raw(val) as *mut _;
        Self { ptr, size }
    }

    unsafe fn borrowed_from_c<'a>(self) -> &'a [u8] {
        core::slice::from_raw_parts_mut(self.ptr, self.size)
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
#[no_mangle]
pub unsafe extern "C" fn rice_data_len(data: *const RiceData) -> usize {
    let len = match &*data {
        RiceData::Borrowed(imp) => imp.size,
        RiceData::Owned(imp) => imp.size,
    };

    len
}

/// The data pointer for a `RiceData`.
#[no_mangle]
pub unsafe extern "C" fn rice_data_ptr(data: *const RiceData) -> *mut u8 {
    let ptr = match &*data {
        RiceData::Borrowed(imp) => imp.ptr,
        RiceData::Owned(imp) => imp.ptr,
    };

    ptr
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
    data: RiceData,
}

impl Default for RiceTransmit {
    fn default() -> Self {
        Self {
            stream_id: 0,
            transport: RiceTransportType::Udp,
            from: core::ptr::null(),
            to: core::ptr::null(),
            data: RiceData::Borrowed(RiceDataImpl {
                ptr: core::ptr::null_mut(),
                size: 0,
            }),
        }
    }
}

impl From<crate::agent::AgentTransmit> for RiceTransmit {
    fn from(value: crate::agent::AgentTransmit) -> Self {
        let from = Box::new(RiceAddress::new(value.transmit.from));
        let to = Box::new(RiceAddress::new(value.transmit.to));
        Self {
            stream_id: value.stream_id,
            transport: value.transmit.transport.into(),
            from: Box::into_raw(from),
            to: Box::into_raw(to),
            data: value.transmit.data.into(),
        }
    }
}

/// Free any resources allocated within a `RiceTransmit`.
///
/// The `RiceTransmit` must have been previously initialized with `rice_transmit_init()`.
#[no_mangle]
pub unsafe extern "C" fn rice_transmit_clear(transmit: *mut RiceTransmit) {
    if !(*transmit).from.is_null() {
        let _from = RiceAddress::from_c((*transmit).from);
        (*transmit).from = core::ptr::null_mut();
    }
    if !(*transmit).to.is_null() {
        let _to = RiceAddress::from_c((*transmit).to);
        (*transmit).to = core::ptr::null_mut();
    }
    let mut data = RiceData::Borrowed(RiceDataImpl::default());
    core::mem::swap(&mut data, &mut (*transmit).data);
    if !rice_data_ptr(&data).is_null() {
        let _data = Data::from(data);
    }
}

/// Initialize a `RiceTransmit` with default values.
#[no_mangle]
pub unsafe extern "C" fn rice_transmit_init(transmit: *mut MaybeUninit<RiceTransmit>) {
    (*transmit).write(RiceTransmit::default());
}

/// Connect from the specified interface to the specified address.  Reply (success or failure)
/// should be notified using [`rice_agent_allocated_socket`] with the same parameters.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentAllocateSocket {
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

impl From<crate::agent::AgentAllocateSocket> for RiceAgentAllocateSocket {
    fn from(value: crate::agent::AgentAllocateSocket) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            transport: value.transport.into(),
            from: Box::into_raw(Box::new(RiceAddress::new(value.from))),
            to: Box::into_raw(Box::new(RiceAddress::new(value.to))),
        }
    }
}

impl From<RiceAgentAllocateSocket> for crate::agent::AgentAllocateSocket {
    fn from(value: RiceAgentAllocateSocket) -> Self {
        unsafe {
            Self {
                stream_id: value.stream_id,
                component_id: value.component_id,
                transport: value.transport.into(),
                from: **RiceAddress::from_c(value.from),
                to: **RiceAddress::from_c(value.to),
            }
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
    /// The transport type of the selected pair.
    transport: RiceTransportType,
    /// The source address to send data from.
    from: *const RiceAddress,
    /// The destination address to send data to.
    to: *const RiceAddress,
}

impl From<crate::agent::AgentSelectedPair> for RiceAgentSelectedPair {
    fn from(value: crate::agent::AgentSelectedPair) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            transport: value.selected.candidate_pair().local.transport_type.into(),
            from: RiceAddress::new(value.selected.candidate_pair().local.base_address).to_c(),
            to: RiceAddress::new(value.selected.candidate_pair().remote.address).to_c(),
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

impl From<crate::agent::AgentGatheredCandidate> for RiceAgentGatheredCandidate {
    fn from(value: crate::agent::AgentGatheredCandidate) -> Self {
        Self {
            stream_id: value.stream_id,
            gathered: value.gathered.into(),
        }
    }
}

impl From<RiceAgentGatheredCandidate> for crate::agent::AgentGatheredCandidate {
    fn from(value: RiceAgentGatheredCandidate) -> Self {
        Self {
            stream_id: value.stream_id,
            gathered: value.gathered.into(),
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
#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll_init(poll: *mut MaybeUninit<RiceAgentPoll>) {
    (*poll).write(RiceAgentPoll::Closed);
}

/// Clear a `RiceAgentPoll` of any allocated values.
///
/// `rice_agent_poll_init()` must have been called previously.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll_clear(poll: *mut RiceAgentPoll) {
    let mut other = RiceAgentPoll::Closed;
    core::mem::swap(&mut other, &mut *poll);
    match other {
        RiceAgentPoll::Closed
        | RiceAgentPoll::ComponentStateChange(_)
        | RiceAgentPoll::WaitUntilMicros(_)
        | RiceAgentPoll::GatheringComplete(_) => (),
        RiceAgentPoll::AllocateSocket(mut connect) => {
            let mut from = core::ptr::null();
            core::mem::swap(&mut from, &mut connect.from);
            let _from = RiceAddress::from_c(from);
            let mut to = core::ptr::null();
            core::mem::swap(&mut to, &mut connect.to);
            let _to = RiceAddress::from_c(to);
        }
        RiceAgentPoll::SelectedPair(mut pair) => {
            let mut from = core::ptr::null();
            core::mem::swap(&mut from, &mut pair.from);
            let _from = RiceAddress::from_c(from);
            let mut to = core::ptr::null();
            core::mem::swap(&mut to, &mut pair.to);
            let _to = RiceAddress::from_c(to);
        }
        RiceAgentPoll::GatheredCandidate(mut gathered) => {
            let mut turn = core::ptr::null();
            core::mem::swap(&mut turn, &mut const_override(gathered.gathered.turn_agent));
            let turn_agent = if turn.is_null() {
                None
            } else {
                Some(Box::from_raw(turn as *mut TurnClient))
            };
            rice_candidate_clear(&mut gathered.gathered.candidate);
        }
    }
}

/// Poll the `RiceAgent` for further progress.
///
/// The returned value indicates what should be done to continue making progress.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll(
    agent: *mut RiceAgent,
    now_micros: u64,
    poll: *mut RiceAgentPoll,
) {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    let now = agent.base_instant + Duration::from_micros(now_micros);
    let ret = proto_agent.poll(now);
    if let AgentPoll::SelectedPair(ref pair) = ret {
        if let Some(mut stream) = proto_agent.mut_stream(pair.stream_id) {
            if let Some(mut component) = stream.mut_component(pair.component_id) {
                component.set_selected_pair_with_agent((*pair.selected).clone());
            }
        }
    }
    *poll = RiceAgentPoll::from_rust(ret, agent.base_instant);

    drop(proto_agent);
    core::mem::forget(agent);
}

/// Poll the `RiceAgent` for a transmission to send.
///
/// If there is no transmission, then `transmit` will be filled with empty data.
///
/// `rice_transmit_init()` or `rice_transmit_clear()` must be called before this function.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll_transmit(
    agent: *mut RiceAgent,
    now_micros: u64,
    transmit: *mut RiceTransmit,
) {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    let now = agent.base_instant + Duration::from_micros(now_micros);
    if let Some(ret) = proto_agent.poll_transmit(now) {
        *transmit = ret.into();
    } else {
        *transmit = RiceTransmit::default();
    }

    drop(proto_agent);
    core::mem::forget(agent);
}

/// Add a STUN server to this `RiceAgent`.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_add_stun_server(
    agent: *mut RiceAgent,
    transport: RiceTransportType,
    addr: *const RiceAddress,
) {
    let agent = Arc::from_raw(agent);
    let addr = Box::from_raw(mut_override(addr));
    let mut inner = agent.inner.lock().unwrap();
    inner.stun_servers.push((transport.into(), **addr));
    drop(inner);
    core::mem::forget(addr);
    core::mem::forget(agent);
}

/// Add a TURN server to this `RiceAgent`.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_add_turn_server(
    agent: *mut RiceAgent,
    transport: RiceTransportType,
    addr: *const RiceAddress,
    credentials: *const RiceCredentials,
) {
    let username = string_from_c((*credentials).ufrag);
    let password = string_from_c((*credentials).passwd);

    let agent = Arc::from_raw(agent);
    let addr = Box::from_raw(mut_override(addr));
    let mut inner = agent.inner.lock().unwrap();
    inner.turn_servers.push((
        transport.into(),
        **addr,
        TurnCredentials::new(&username, &password),
    ));
    drop(inner);
    core::mem::forget(addr);
    core::mem::forget(agent);
}

/// Get the current time in microseconds of the `RiceAgent`.
///
/// The returned value can be passed to functions that require the current time.
///
/// This value is the same as `rice_stream_now()`.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_now(agent: *mut RiceAgent) -> u64 {
    let agent = Arc::from_raw(agent);
    let ret = Instant::now()
        .saturating_duration_since(agent.base_instant)
        .as_micros() as u64;
    core::mem::forget(agent);
    ret
}

/// A data stream in a `RiceAgent`.
#[derive(Debug)]
pub struct RiceStream {
    proto_agent: Arc<Mutex<Agent>>,
    weak_agent: Weak<Mutex<RiceAgentInner>>,
    inner: Arc<Mutex<RiceStreamInner>>,
    base_instant: Instant,
    stream_id: usize,
}

#[derive(Debug)]
struct RiceStreamInner {
    components: Vec<Arc<RiceComponent>>,
}

/// Add a data stream to the `RiceAgent`.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_add_stream(agent: *mut RiceAgent) -> *mut RiceStream {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    let stream_id = proto_agent.add_stream();
    let stream = Arc::new(RiceStream {
        proto_agent: agent.proto_agent.clone(),
        weak_agent: Arc::downgrade(&agent.inner),
        inner: Arc::new(Mutex::new(RiceStreamInner { components: vec![] })),
        base_instant: agent.base_instant,
        stream_id,
    });
    drop(proto_agent);

    let mut inner = agent.inner.lock().unwrap();
    inner.streams.push(stream.clone());

    drop(inner);
    core::mem::forget(agent);
    mut_override(Arc::into_raw(stream))
}

/// Retrieve a previously added stream from the `RiceAgent`.
///
/// Will return `NULL` if the stream does not exist.
#[no_mangle]
pub unsafe extern "C" fn rice_agent_get_stream(
    agent: *mut RiceAgent,
    stream_id: usize,
) -> *mut RiceStream {
    let agent = Arc::from_raw(agent);
    let inner = agent.inner.lock().unwrap();
    let ret = if let Some(stream) = inner.streams.get(stream_id) {
        mut_override(Arc::into_raw(stream.clone()))
    } else {
        mut_override(std::ptr::null::<RiceStream>())
    };

    drop(inner);
    core::mem::forget(agent);
    ret
}

/// Increase the reference count of the `RiceStream`.
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_ref(stream: *mut RiceStream) -> *mut RiceStream {
    Arc::increment_strong_count(stream);
    stream
}

/// Decrease the reference count of the `RiceStream`.
///
/// If this is the last reference, then the `RiceStream` is freed (but will still be referenced by
/// the `RiceAgent`).
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_unref(stream: *mut RiceStream) {
    Arc::decrement_strong_count(stream)
}

/// Retrieve the stream id of the `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_get_id(stream: *mut RiceStream) -> usize {
    let stream = Arc::from_raw(stream);
    let ret = stream.stream_id;
    core::mem::forget(stream);
    ret
}

/// Notify success or failure to create a socket to the `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_handle_allocated_socket(
    stream: *mut RiceStream,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    socket_addr: *mut RiceAddress,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    let from = RiceAddress::from_c(from);
    let to = RiceAddress::from_c(to);
    let socket = if socket_addr.is_null() {
        Err(StunError::ResourceNotFound)
    } else {
        Ok(**RiceAddress::from_c(socket_addr))
    };
    proto_stream.allocated_socket(component_id, transport.into(), **from, **to, socket);

    drop(proto_agent);
    core::mem::forget(from);
    core::mem::forget(to);
    core::mem::forget(stream);
}

/// Get the current time in microseconds of the `RiceStream`.
///
/// The returned value can be passed to functions that require the current time.
///
/// This value is the same as `rice_agent_now()`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_now(stream: *mut RiceStream) -> u64 {
    let stream = Arc::from_raw(stream);
    let ret = Instant::now()
        .saturating_duration_since(stream.base_instant)
        .as_micros() as u64;
    core::mem::forget(stream);
    ret
}

/// ICE/TURN credentials.
#[derive(Debug)]
pub struct RiceCredentials {
    /// The username.
    pub ufrag: *mut c_char,
    /// The password.
    pub passwd: *mut c_char,
}

/// Construct a new set of ICE/TURN credentials.
#[no_mangle]
pub unsafe extern "C" fn rice_credentials_new(
    ufrag: *mut c_char,
    passwd: *mut c_char,
) -> *mut RiceCredentials {
    Box::into_raw(Box::new(RiceCredentials { ufrag, passwd }))
}

/// Free a set of ICE/TURN credentials.
#[no_mangle]
pub unsafe extern "C" fn rice_credentials_free(credentials: *mut RiceCredentials) {
    let creds = Box::from_raw(credentials);
    let _ufrag = CString::from_raw(creds.ufrag);
    let _passwd = CString::from_raw(creds.passwd);
}

fn credentials_to_c(credentials: Credentials) -> *mut RiceCredentials {
    let creds = Box::new(RiceCredentials {
        ufrag: CString::new(credentials.ufrag).unwrap().into_raw(),
        passwd: CString::new(credentials.passwd).unwrap().into_raw(),
    });
    Box::into_raw(creds)
}

/// Retrieve the local ICE credentials currently set on the `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_get_local_credentials(
    stream: *mut RiceStream,
) -> *mut RiceCredentials {
    let stream = Arc::from_raw(stream);
    let proto_agent = stream.proto_agent.lock().unwrap();
    let proto_stream = proto_agent.stream(stream.stream_id).unwrap();

    let ret = if let Some(credentials) = proto_stream.local_credentials() {
        credentials_to_c(credentials)
    } else {
        mut_override(std::ptr::null::<RiceCredentials>())
    };

    drop(proto_agent);
    core::mem::forget(stream);
    ret
}

/// Retrieve the remote ICE credentials currently set on the `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_get_remote_credentials(
    stream: *mut RiceStream,
) -> *mut RiceCredentials {
    let stream = Arc::from_raw(stream);
    let proto_agent = stream.proto_agent.lock().unwrap();
    let proto_stream = proto_agent.stream(stream.stream_id).unwrap();

    let ret = if let Some(credentials) = proto_stream.remote_credentials() {
        credentials_to_c(credentials)
    } else {
        mut_override(std::ptr::null::<RiceCredentials>())
    };

    drop(proto_agent);
    core::mem::forget(stream);
    ret
}

unsafe fn string_from_c(cstr: *const c_char) -> String {
    CStr::from_ptr(cstr).to_str().unwrap().to_owned()
}

/// Set the local credentials to use for this `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_set_local_credentials(
    stream: *mut RiceStream,
    credentials: *const RiceCredentials,
) {
    let ufrag = string_from_c((*credentials).ufrag);
    let passwd = string_from_c((*credentials).passwd);

    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    proto_stream.set_local_credentials(Credentials { ufrag, passwd });
    drop(proto_agent);
    core::mem::forget(stream);
}

/// Set the remote credentials to use for this `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_set_remote_credentials(
    stream: *mut RiceStream,
    credentials: *const RiceCredentials,
) {
    let ufrag = string_from_c((*credentials).ufrag);
    let passwd = string_from_c((*credentials).passwd);

    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    proto_stream.set_remote_credentials(Credentials { ufrag, passwd });
    drop(proto_agent);
    core::mem::forget(stream);
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

impl From<crate::candidate::Candidate> for RiceCandidate {
    fn from(value: crate::candidate::Candidate) -> Self {
        let address = Box::new(RiceAddress(value.address));
        let base_address = Box::new(RiceAddress(value.base_address));
        let related_address = if let Some(addr) = value.related_address {
            Box::into_raw(Box::new(RiceAddress(addr)))
        } else {
            std::ptr::null()
        };
        Self {
            component_id: value.component_id,
            candidate_type: value.candidate_type.into(),
            transport_type: value.transport_type.into(),
            foundation: CString::new(value.foundation).unwrap().into_raw(),
            priority: value.priority,
            address: Box::into_raw(address),
            base_address: Box::into_raw(base_address),
            related_address,
            tcp_type: value.tcp_type.into(),
            // FIXME
            extensions: std::ptr::null_mut(),
            extensions_len: 0,
        }
    }
}

impl From<&RiceCandidate> for crate::candidate::Candidate {
    fn from(value: &RiceCandidate) -> Self {
        unsafe {
            let related_address = if !value.related_address.is_null() {
                Some(RiceAddress::from_c_none(value.related_address).0)
            } else {
                None
            };
            let foundation = string_from_c(value.foundation);
            Self {
                component_id: value.component_id,
                candidate_type: value.candidate_type.into(),
                transport_type: value.transport_type.into(),
                foundation,
                priority: value.priority,
                address: RiceAddress::from_c_none(value.address).0,
                base_address: RiceAddress::from_c_none(value.base_address).0,
                related_address,
                tcp_type: value.tcp_type.into(),
                // FIXME
                extensions: vec![],
            }
        }
    }
}

/// Construct a `RiceCandidate` from a string as formatted in an SDP and specified in RFC5245
/// Section 15.1.
///
/// Takes the form 'a=candidate:foundation 1 UDP 12345 127.0.0.1 23456 typ host'.
#[no_mangle]
pub unsafe extern "C" fn rice_candidate_new_from_sdp_string(
    cand_str: *const c_char,
) -> *mut RiceCandidate {
    let Ok(cand_str) = CStr::from_ptr(cand_str).to_str() else {
        return mut_override(std::ptr::null());
    };
    let Ok(candidate) = Candidate::from_str(cand_str) else {
        return mut_override(std::ptr::null());
    };
    Box::into_raw(Box::new(RiceCandidate::from(candidate)))
}

/// Return a SDP candidate string as specified in RFC5245 Section 15.1.
#[no_mangle]
pub unsafe extern "C" fn rice_candidate_to_sdp_string(
    candidate: *const RiceCandidate,
) -> *mut c_char {
    let candidate = Box::from_raw(mut_override(candidate));
    let cand: crate::candidate::Candidate = candidate.as_ref().into();
    let ret = CString::new(cand.to_sdp_string()).unwrap();
    core::mem::forget(candidate);
    ret.into_raw()
}

/// Perform a deep copy of a `RiceCandidate`.
#[no_mangle]
pub unsafe extern "C" fn rice_candidate_copy(
    candidate: *const RiceCandidate,
) -> *mut RiceCandidate {
    let candidate = Box::from_raw(mut_override(candidate));
    let foundation = CString::from_raw(mut_override(candidate.foundation));
    let cand_clone = Box::new(RiceCandidate {
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
    });
    core::mem::forget(candidate);
    core::mem::forget(foundation);
    Box::into_raw(cand_clone)
}

unsafe fn rice_candidate_clear(candidate: &mut RiceCandidate) {
    let _foundation = CString::from_raw(mut_override(candidate.foundation));
    candidate.foundation = core::ptr::null_mut();
    let _address = RiceAddress::from_c(candidate.address);
    candidate.address = core::ptr::null_mut();
    let _base_address = RiceAddress::from_c(candidate.base_address);
    candidate.base_address = core::ptr::null_mut();
    if !candidate.related_address.is_null() {
        let _related_address = RiceAddress::from_c(candidate.related_address);
        candidate.related_address = core::ptr::null_mut();
    }
}

/// Free a `RiceCandidate`.
#[no_mangle]
pub unsafe extern "C" fn rice_candidate_free(candidate: *mut RiceCandidate) {
    let mut cand = Box::from_raw(candidate);
    rice_candidate_clear(&mut cand);
    // FIXME extensions
}

/// A local candidate that has been gathered.
#[derive(Debug)]
#[repr(C)]
pub struct RiceGatheredCandidate {
    candidate: RiceCandidate,
    turn_agent: *mut c_void,
}

impl From<RiceGatheredCandidate> for GatheredCandidate {
    fn from(value: RiceGatheredCandidate) -> Self {
        unsafe {
            let candidate = (&value.candidate).into();
            let turn_agent = if value.turn_agent.is_null() {
                None
            } else {
                Some(Box::from_raw(value.turn_agent as *mut TurnClient))
            };
            Self {
                candidate,
                turn_agent,
            }
        }
    }
}

impl From<GatheredCandidate> for RiceGatheredCandidate {
    fn from(value: GatheredCandidate) -> Self {
        let candidate = value.candidate.into();
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
#[no_mangle]
pub unsafe extern "C" fn rice_stream_add_local_gathered_candidate(
    stream: *mut RiceStream,
    candidate: *mut RiceGatheredCandidate,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let gathered = Box::from_raw(mut_override(candidate));

    proto_stream.add_local_gathered_candidate((*gathered).into());
    (*candidate).turn_agent = core::ptr::null_mut();
    rice_candidate_clear(&mut (*candidate).candidate);
    drop(proto_agent);
    core::mem::forget(stream);
}

/// Add a remote candidate to the `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_add_remote_candidate(
    stream: *mut RiceStream,
    candidate: *const RiceCandidate,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let candidate = Box::from_raw(mut_override(candidate));

    proto_stream.add_remote_candidate(candidate.as_ref().into());
    drop(proto_agent);
    core::mem::forget(stream);
    core::mem::forget(candidate);
}

/// Signal the end of a set of local candidates.
///
/// Any local candidates provided after calling this function will result in an error.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_end_of_local_candidates(stream: *mut RiceStream) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    proto_stream.end_of_local_candidates();
    drop(proto_agent);
    core::mem::forget(stream);
}

/// Signal the end of a set of remote candidates.
///
/// Any remote candidates provided after calling this function will result in an error.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_end_of_remote_candidates(stream: *mut RiceStream) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    proto_stream.end_of_remote_candidates();
    drop(proto_agent);
    core::mem::forget(stream);
}

/// Return value for `rice_stream_handle_incoming_data()`.
#[derive(Debug)]
#[repr(C)]
pub struct RiceStreamIncomingData {
    /// The data was handled internally. `rice_agent_poll()` should be called at the
    /// next earliest opportunity.
    data_handled: bool,
    /// Number of data pointers provided.
    data_len: usize,
    /// The length of each data pointer.
    data_data_lens: *const usize,
    /// An array of a sequence of data pointers.
    data: *const *const u8,
}

/// Free a `RiceStreamIncomingData`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_incoming_data_free(incoming: *mut RiceStreamIncomingData) {
    let incoming = Box::from_raw(incoming);
    if !incoming.data.is_null() {
        let data = std::slice::from_raw_parts(incoming.data, incoming.data_len);
        for d in data {
            let _data = Box::from_raw(mut_override(*d));
        }
    }
    if !incoming.data_data_lens.is_null() {
        let _data_lens = Box::from_raw(mut_override(incoming.data_data_lens));
    }
    if !incoming.data.is_null() {
        let _data_ = Box::from_raw(incoming.data as *mut *const u8);
    }
}

/// Provide data to the `RiceStream` for processing.
///
/// The returned value contains what processing was completed on the provided data and any
/// application data that needs to be handled.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_handle_incoming_data(
    stream: *mut RiceStream,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    data: *const u8,
    data_len: usize,
    now_micros: u64,
) -> *mut RiceStreamIncomingData {
    let stream = Arc::from_raw(stream);
    let now = stream.base_instant + Duration::from_micros(now_micros);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let from = Box::from_raw(mut_override(from));
    let to = Box::from_raw(mut_override(to));

    let transmit = Transmit {
        transport: transport.into(),
        from: **from,
        to: **to,
        data: Data::Borrowed(DataSlice::from(std::slice::from_raw_parts(data, data_len))),
    };
    core::mem::forget(from);
    core::mem::forget(to);

    let ret = proto_stream.handle_incoming_data(component_id, transmit, now);
    let (data, data_len, data_data_lens) = if ret.data.is_empty() {
        (core::ptr::null(), 0, core::ptr::null())
    } else {
        let data_len = ret.data.len();
        let data_data_lens = ret.data.iter().map(|d| d.len()).collect::<Vec<_>>();
        let data_data_lens = Box::into_raw(data_data_lens.into_boxed_slice()) as *const _;
        let data = ret
            .data
            .into_iter()
            .map(|d| Box::into_raw(d.into_boxed_slice()) as *const _)
            .collect::<Vec<_>>();
        let data = Box::into_raw(data.into_boxed_slice()) as *const _;
        (data, data_len, data_data_lens)
    };

    drop(proto_agent);
    core::mem::forget(stream);
    Box::into_raw(Box::new(RiceStreamIncomingData {
        data_handled: ret.data_handled,
        data,
        data_len,
        data_data_lens,
    }))
}

// TODO:
// - local_candidates
// - component_ids_iter

/// An ICE component within a `RiceStream`.
#[derive(Debug)]
pub struct RiceComponent {
    proto_agent: Arc<Mutex<Agent>>,
    weak_agent: Weak<Mutex<RiceAgentInner>>,
    stream_id: usize,
    component_id: usize,
    base_instant: Instant,
}

/// Add an ICE component to a `RiceStream`.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_add_component(stream: *mut RiceStream) -> *mut RiceComponent {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let component_id = proto_stream.add_component().unwrap();
    let component = Arc::new(RiceComponent {
        proto_agent: stream.proto_agent.clone(),
        weak_agent: stream.weak_agent.clone(),
        stream_id: stream.stream_id,
        component_id,
        base_instant: stream.base_instant,
    });
    drop(proto_agent);

    let mut inner = stream.inner.lock().unwrap();
    inner.components.push(component.clone());

    drop(inner);
    core::mem::forget(stream);
    mut_override(Arc::into_raw(component))
}

/// Increase the reference count of the `RiceComponent`.
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_component_ref(component: *mut RiceComponent) -> *mut RiceComponent {
    Arc::increment_strong_count(component);
    component
}

/// Decrease the reference count of the `RiceComponent`.
///
/// If this is the last reference, then the `RiceComponent` is freed (but will still be referenced by
/// the `RiceStream`).
///
/// This function is multi-threading safe.
#[no_mangle]
pub unsafe extern "C" fn rice_component_unref(component: *mut RiceComponent) {
    Arc::decrement_strong_count(component)
}

/// Retrieve a previously added `RiceComponent`.
///
/// If the `RiceComponent` does not exist, `NULL` is returned.
#[no_mangle]
pub unsafe extern "C" fn rice_stream_get_component(
    stream: *mut RiceStream,
    component_id: usize,
) -> *mut RiceComponent {
    if component_id < 1 {
        return mut_override(std::ptr::null::<RiceComponent>());
    }
    let stream = Arc::from_raw(stream);
    let inner = stream.inner.lock().unwrap();
    let ret = if let Some(component) = inner.components.get(component_id - 1) {
        mut_override(Arc::into_raw(component.clone()))
    } else {
        return mut_override(std::ptr::null::<RiceComponent>());
    };

    drop(inner);
    core::mem::forget(stream);
    ret
}

/// Start gathering candidates for a component with the provided local socket addresses.
#[no_mangle]
pub unsafe extern "C" fn rice_component_gather_candidates(
    component: *mut RiceComponent,
    sockets_len: usize,
    sockets_addr: *const *mut RiceAddress,
    sockets_transports: *const RiceTransportType,
) {
    let component = Arc::from_raw(component);
    let (stun_servers, turn_servers) = {
        let Some(agent) = component.weak_agent.upgrade() else {
            return;
        };
        let agent = agent.lock().unwrap();
        (agent.stun_servers.clone(), agent.turn_servers.clone())
    };
    debug!("stun_servers: {stun_servers:?}");
    let mut proto_agent = component.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(component.stream_id).unwrap();
    let mut proto_component = proto_stream.mut_component(component.component_id).unwrap();

    let sockets_addr = std::slice::from_raw_parts(sockets_addr, sockets_len);
    let sockets_transport = std::slice::from_raw_parts(sockets_transports, sockets_len);

    let sockets = sockets_transport
        .iter()
        .zip(sockets_addr.iter())
        .map(|(&transport, addr)| {
            let addr = RiceAddress::from_c(*addr);
            let socket_addr = **addr;
            core::mem::forget(addr);
            (transport.into(), socket_addr)
        })
        .collect::<Vec<_>>();

    debug!("sockets: {sockets:?}");

    proto_component
        .gather_candidates(sockets, stun_servers, turn_servers)
        .unwrap();
    drop(proto_agent);
    core::mem::forget(component);
}

/// Send data to the connected peer.
///
/// This will fail before a connection is successfully completed.
#[no_mangle]
pub unsafe extern "C" fn rice_component_send(
    component: *mut RiceComponent,
    data: *mut u8,
    len: usize,
    now_micros: u64,
    transmit: *mut RiceTransmit,
) -> RiceError {
    let component = Arc::from_raw(component);
    let now = component.base_instant + Duration::from_micros(now_micros);

    let mut proto_agent = component.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(component.stream_id).unwrap();
    let mut proto_component = proto_stream.mut_component(component.component_id).unwrap();

    let bytes = Data::from(core::slice::from_raw_parts(data, len));
    match proto_component.send(bytes, now) {
        Ok(stun_transmit) => {
            *transmit = RiceTransmit {
                stream_id: component.stream_id,
                transport: stun_transmit.transport.into(),
                from: Box::into_raw(Box::new(RiceAddress::new(stun_transmit.from))),
                to: Box::into_raw(Box::new(RiceAddress::new(stun_transmit.to))),
                data: stun_transmit.data.into(),
            };
            RiceError::Success
        }
        Err(e) => {
            warn!("Failed to send data: {e:?}");
            RiceError::Failed
        }
    }
}

// TODO:
// - id
// - state
// - selected_pair

/// A socket address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct RiceAddress(SocketAddr);

impl RiceAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    pub fn to_c(self) -> *const RiceAddress {
        const_override(Box::into_raw(Box::new(self)))
    }

    pub unsafe fn from_c(value: *const RiceAddress) -> Box<Self> {
        Box::from_raw(mut_override(value))
    }

    pub unsafe fn from_c_none(value: *const RiceAddress) -> Self {
        let boxed = Box::from_raw(mut_override(value));
        let ret = *boxed;
        core::mem::forget(boxed);
        ret
    }
}

impl std::ops::Deref for RiceAddress {
    type Target = SocketAddr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Create a `RiceAddress` from a string representation of the socket address.
#[no_mangle]
pub unsafe extern "C" fn rice_address_new_from_string(string: *const c_char) -> *mut RiceAddress {
    let Ok(string) = CStr::from_ptr(string).to_str() else {
        return mut_override(std::ptr::null::<RiceAddress>());
    };
    let Ok(saddr) = SocketAddr::from_str(string) else {
        return mut_override(std::ptr::null::<RiceAddress>());
    };

    mut_override(RiceAddress::to_c(RiceAddress(saddr)))
}

/// The address family.
#[repr(u32)]
pub enum RiceAddressFamily {
    Ipv4 = 1,
    Ipv6,
}

/// Construct a `RiceAddress` from a sequence of bytes.
///
/// The number of bytes required depends on the address family being constructed:
/// - IPv4 -> 4.
/// - IPv6 -> 16.
#[no_mangle]
pub unsafe extern "C" fn rice_address_new_from_bytes(
    family: RiceAddressFamily,
    bytes: *const u8,
    port: u16,
) -> *mut RiceAddress {
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
    Box::into_raw(Box::new(RiceAddress(SocketAddr::new(ip_addr, port))))
}

/// The address family of the `RiceAddress`.
#[no_mangle]
pub unsafe extern "C" fn rice_address_get_family(addr: *const RiceAddress) -> RiceAddressFamily {
    let addr = RiceAddress::from_c(addr);
    let ret = match addr.0 {
        SocketAddr::V4(_) => RiceAddressFamily::Ipv4,
        SocketAddr::V6(_) => RiceAddressFamily::Ipv6,
    };
    core::mem::forget(addr);
    ret
}

/// Retrieve the bytes of a `RiceAddress`.
///
/// The number of bytes required depends on the address family being constructed:
/// - IPv4 -> 4.
/// - IPv6 -> 16.
#[no_mangle]
pub unsafe extern "C" fn rice_address_get_address_bytes(
    addr: *const RiceAddress,
    bytes: *mut u8,
) -> usize {
    let addr = RiceAddress::from_c(addr);
    let ret = match addr.0.ip() {
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
    core::mem::forget(addr);
    ret
}

/// Retrieve the port of a `RiceAddress`.
#[no_mangle]
pub unsafe extern "C" fn rice_address_get_port(addr: *const RiceAddress) -> u16 {
    let addr = RiceAddress::from_c(addr);
    let ret = addr.0.port();
    core::mem::forget(addr);
    ret
}

/// Compare whether two `RiceAddress`es are equal.
#[no_mangle]
pub unsafe extern "C" fn rice_address_cmp(
    addr: *const RiceAddress,
    other: *const RiceAddress,
) -> c_int {
    let addr = RiceAddress::from_c(addr);
    let other = RiceAddress::from_c(other);
    let ret = addr.cmp(&other) as c_int;
    core::mem::forget(addr);
    core::mem::forget(other);
    ret
}

/// Copy a `RiceAddress`.
#[no_mangle]
pub unsafe extern "C" fn rice_address_copy(addr: *const RiceAddress) -> *mut RiceAddress {
    let addr = RiceAddress::from_c(mut_override(addr));
    let ret = mut_override(RiceAddress(addr.0).to_c());
    core::mem::forget(addr);
    ret
}

/// Free a `RiceAddress`.
#[no_mangle]
pub unsafe extern "C" fn rice_address_free(addr: *mut RiceAddress) {
    let _addr = Box::from_raw(addr);
}

fn mut_override<T>(val: *const T) -> *mut T {
    val as *mut T
}

fn const_override<T>(val: *mut T) -> *const T {
    val as *const T
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{Candidate, TcpType};

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
        let mut rcand: RiceCandidate = candidate.clone().into();
        let new_cand: Candidate = (&rcand).into();
        assert_eq!(candidate, new_cand);
        let cpy = unsafe { rice_candidate_copy(&rcand) };
        unsafe { rice_candidate_clear(&mut rcand) };
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
            let addr = RiceAddress::new(addr).to_c();
            let stun_addr: SocketAddr = "102.168.0.200:2000".parse().unwrap();
            let stun_addr = RiceAddress::new(stun_addr).to_c();
            let agent = rice_agent_new(true, false);
            let stream = rice_agent_add_stream(agent);
            let component = rice_stream_add_component(stream);
            let transport = TransportType::Tcp;
            let local_credentials =
                credentials_to_c(Credentials::new("luser".to_string(), "lpass".to_string()));
            let remote_credentials =
                credentials_to_c(Credentials::new("ruser".to_string(), "rpass".to_string()));

            rice_agent_add_stun_server(agent, transport.into(), stun_addr);
            rice_address_free(mut_override(stun_addr));
            rice_stream_set_local_credentials(stream, local_credentials);
            rice_credentials_free(local_credentials);
            rice_stream_set_remote_credentials(stream, remote_credentials);
            rice_credentials_free(remote_credentials);
            rice_component_gather_candidates(component, 1, &mut_override(addr), &transport.into());
            rice_address_free(mut_override(addr));

            let mut poll = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut poll);
            let RiceAgentPoll::AllocateSocket(ref alloc) = poll else {
                unreachable!()
            };
            let to = alloc.to;
            let from = alloc.from;
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
            let RiceAgentPoll::WaitUntilMicros(_now) = poll else {
                unreachable!()
            };
            rice_agent_poll_clear(&mut poll);

            let tcp_from_addr = "192.168.200.4:3000".parse().unwrap();
            let tcp_from_addr = mut_override(RiceAddress::new(tcp_from_addr).to_c());
            rice_stream_handle_allocated_socket(
                stream,
                component_id,
                RiceTransportType::Tcp,
                from,
                to,
                tcp_from_addr,
            );

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
            assert!(rice_data_ptr(&transmit.data).is_null());
        }
    }
}
