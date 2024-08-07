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
use std::os::raw::{c_char, c_int};

use core::mem::MaybeUninit;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once, Weak};
use std::time::{Duration, Instant};

use crate::agent::Agent;
pub use crate::agent::AgentPoll;
use crate::candidate::{Candidate, CandidateType, TransportType};
pub use crate::component::ComponentConnectionState;
use crate::gathering::GatherPoll;
use crate::stream::Credentials;
use stun_proto::agent::{StunAgent, StunError, Transmit};
use stun_proto::types::data::{Data, DataOwned, DataSlice};

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
    streams: Vec<Arc<RiceStream>>,
}

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
            streams: vec![],
        })),
        base_instant: Instant::now(),
    });

    mut_override(Arc::into_raw(agent))
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_ref(agent: *mut RiceAgent) -> *mut RiceAgent {
    Arc::increment_strong_count(agent);
    agent
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_unref(agent: *mut RiceAgent) {
    Arc::decrement_strong_count(agent)
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_close(agent: *mut RiceAgent) {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    proto_agent.close().unwrap();

    drop(proto_agent);
    core::mem::forget(agent);
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_get_controlling(agent: *mut RiceAgent) -> bool {
    let agent = Arc::from_raw(agent);
    let proto_agent = agent.proto_agent.lock().unwrap();
    let ret = proto_agent.controlling();

    drop(proto_agent);
    core::mem::forget(agent);
    ret
}

#[derive(Debug)]
#[repr(C)]
pub enum RiceAgentPoll {
    /// The Agent is closed.  No further progress will be made.
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event)
    WaitUntilMicros(u64),
    /// Transmit data using the specified 5-tuple
    Transmit(RiceTransmit),
    /// Connect from the specified interface to the specified address.  Reply (success or failure)
    /// should be notified using [`StreamMut::handle_tcp_connect`] with the same parameters.
    TcpConnect(RiceAgentTcpConnect),
    /// A new pair has been selected for a component.
    SelectedPair(RiceAgentSelectedPair),
    /// A [`Component`](crate::component::Component) has changed state.
    ComponentStateChange(RiceAgentComponentStateChange),
}

impl RiceAgentPoll {
    fn from_rust(poll: AgentPoll, base_instant: Instant) -> Self {
        match poll {
            AgentPoll::Closed => Self::Closed,
            AgentPoll::WaitUntil(instant) => Self::WaitUntilMicros(
                instant.saturating_duration_since(base_instant).as_micros() as u64,
            ),
            AgentPoll::Transmit(transmit) => Self::Transmit(transmit.into()),
            AgentPoll::TcpConnect(connect) => Self::TcpConnect(connect.into()),
            AgentPoll::SelectedPair(pair) => Self::SelectedPair(pair.into()),
            AgentPoll::ComponentStateChange(state) => Self::ComponentStateChange(state.into()),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum RiceData {
    Borrowed(RiceDataImpl),
    Owned(RiceDataImpl),
}

#[derive(Debug)]
#[repr(C)]
pub struct RiceDataImpl {
    ptr: *mut u8,
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

#[no_mangle]
pub unsafe extern "C" fn rice_data_len(data: *const RiceData) -> usize {
    let len = match &*data {
        RiceData::Borrowed(imp) => imp.size,
        RiceData::Owned(imp) => imp.size,
    };

    len
}

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
    stream_id: usize,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    data: RiceData,
}

impl<'a> From<crate::agent::AgentTransmit<'a>> for RiceTransmit {
    fn from(value: crate::agent::AgentTransmit<'a>) -> Self {
        let from = Box::new(RiceAddress::new(value.transmit.from));
        let to = Box::new(RiceAddress::new(value.transmit.to));
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            transport: value.transmit.transport.into(),
            from: Box::into_raw(from),
            to: Box::into_raw(to),
            data: value.transmit.data.into(),
        }
    }
}

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
    let mut data = RiceData::Borrowed(RiceDataImpl {
        ptr: core::ptr::null_mut(),
        size: 0,
    });
    core::mem::swap(&mut data, &mut (*transmit).data);
    let _data = Data::from(data);
}

#[no_mangle]
pub unsafe extern "C" fn rice_transmit_init(transmit: *mut MaybeUninit<RiceTransmit>) {
    (*transmit).write(RiceTransmit {
        stream_id: 0,
        component_id: 0,
        transport: RiceTransportType::Udp,
        from: core::ptr::null(),
        to: core::ptr::null(),
        data: RiceData::Borrowed(RiceDataImpl {
            ptr: core::ptr::null_mut(),
            size: 0,
        }),
    });
}

fn transmit_from_rust_gather(
    stream_id: usize,
    component_id: usize,
    transmit: Transmit,
) -> RiceTransmit {
    let from = Box::new(RiceAddress::new(transmit.from));
    let to = Box::new(RiceAddress::new(transmit.to));
    let ret = RiceTransmit {
        stream_id,
        component_id,
        transport: transmit.transport.into(),
        from: Box::into_raw(from),
        to: Box::into_raw(to),
        data: transmit.data.into(),
    };
    ret
}

/// Connect from the specified interface to the specified address.  Reply (success or failure)
/// should be notified using [`rice_agent_handle_tcp_connect`] with the same parameters.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentTcpConnect {
    pub stream_id: usize,
    pub component_id: usize,
    pub from: *const RiceAddress,
    pub to: *const RiceAddress,
}

impl From<crate::agent::AgentTcpConnect> for RiceAgentTcpConnect {
    fn from(value: crate::agent::AgentTcpConnect) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
            from: Box::into_raw(Box::new(RiceAddress::new(value.from))),
            to: Box::into_raw(Box::new(RiceAddress::new(value.to))),
        }
    }
}

impl From<RiceAgentTcpConnect> for crate::agent::AgentTcpConnect {
    fn from(value: RiceAgentTcpConnect) -> Self {
        unsafe {
            Self {
                stream_id: value.stream_id,
                component_id: value.component_id,
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
    stream_id: usize,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
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
/*
impl From<RiceAgentSelectedPair> for crate::agent::AgentSelectedPair {
    fn from(value: RiceAgentSelectedPair) -> Self {
        Self {
            stream_id: value.stream_id,
            component_id: value.component_id,
        }
    }
}
*/
/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct RiceAgentComponentStateChange {
    pub stream_id: usize,
    pub component_id: usize,
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

#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll_init(poll: *mut MaybeUninit<RiceAgentPoll>) {
    (*poll).write(RiceAgentPoll::Closed);
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll_clear(poll: *mut RiceAgentPoll) {
    let mut other = RiceAgentPoll::Closed;
    core::mem::swap(&mut other, &mut *poll);
    match other {
        RiceAgentPoll::Closed
        | RiceAgentPoll::ComponentStateChange(_)
        | RiceAgentPoll::WaitUntilMicros(_) => (),
        RiceAgentPoll::Transmit(mut transmit) => {
            rice_transmit_clear(&mut transmit);
        }
        RiceAgentPoll::TcpConnect(mut connect) => {
            let mut from = core::ptr::null();
            core::mem::swap(&mut from, &mut connect.from);
            let _from = RiceAddress::from_c(from);
            let mut to = core::ptr::null();
            core::mem::swap(&mut to, &mut connect.to);
            let _to = RiceAddress::from_c(connect.to);
        }
        RiceAgentPoll::SelectedPair(mut pair) => {
            let mut from = core::ptr::null();
            core::mem::swap(&mut from, &mut pair.from);
            let _from = RiceAddress::from_c(from);
            let mut to = core::ptr::null();
            core::mem::swap(&mut to, &mut pair.to);
            let _to = RiceAddress::from_c(to);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rice_agent_poll(
    agent: *mut RiceAgent,
    now_micros: u64,
    poll: *mut RiceAgentPoll,
) {
    let agent = Arc::from_raw(agent);
    let mut proto_agent = agent.proto_agent.lock().unwrap();
    let now = agent.base_instant + Duration::from_micros(now_micros);
    let ret = proto_agent.poll(now).into_owned();
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

#[no_mangle]
pub unsafe extern "C" fn rice_agent_now(agent: *mut RiceAgent) -> u64 {
    let agent = Arc::from_raw(agent);
    let ret = Instant::now()
        .saturating_duration_since(agent.base_instant)
        .as_micros() as u64;
    core::mem::forget(agent);
    ret
}

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

#[no_mangle]
pub unsafe extern "C" fn rice_stream_ref(stream: *mut RiceStream) -> *mut RiceStream {
    Arc::increment_strong_count(stream);
    stream
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_unref(stream: *mut RiceStream) {
    Arc::decrement_strong_count(stream)
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_get_id(stream: *mut RiceStream) -> usize {
    let stream = Arc::from_raw(stream);
    let ret = stream.stream_id;
    core::mem::forget(stream);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_now(stream: *mut RiceStream) -> u64 {
    let stream = Arc::from_raw(stream);
    let ret = Instant::now()
        .saturating_duration_since(stream.base_instant)
        .as_micros() as u64;
    core::mem::forget(stream);
    ret
}

#[derive(Debug)]
pub struct RiceCredentials {
    pub ufrag: *mut c_char,
    pub passwd: *mut c_char,
}

#[no_mangle]
pub unsafe extern "C" fn rice_credentials_new(
    ufrag: *mut c_char,
    passwd: *mut c_char,
) -> *mut RiceCredentials {
    Box::into_raw(Box::new(RiceCredentials { ufrag, passwd }))
}

#[no_mangle]
pub unsafe extern "C" fn rice_credentials_free(credentials: *mut RiceCredentials) {
    let creds = Box::from_raw(credentials);
    let _ufrag = CString::from_raw(creds.ufrag);
    let _passwd = CString::from_raw(creds.passwd);
}

pub fn credentials_to_c(credentials: Credentials) -> *mut RiceCredentials {
    let creds = Box::new(RiceCredentials {
        ufrag: CString::new(credentials.ufrag).unwrap().into_raw(),
        passwd: CString::new(credentials.passwd).unwrap().into_raw(),
    });
    Box::into_raw(creds)
}

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum RiceTcpType {
    None,
    Active,
    Passive,
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

#[no_mangle]
pub unsafe extern "C" fn rice_candidate_free(candidate: *mut RiceCandidate) {
    let cand = Box::from_raw(candidate);
    let _foundation = CString::from_raw(mut_override(cand.foundation));
    let _address = RiceAddress::from_c(cand.address);
    let _base_address = RiceAddress::from_c(cand.base_address);
    if !cand.related_address.is_null() {
        let _related_address = RiceAddress::from_c(cand.related_address);
    }
    // FIXME extensions
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_add_local_candidate(
    stream: *mut RiceStream,
    candidate: *const RiceCandidate,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let candidate = Box::from_raw(mut_override(candidate));

    proto_stream.add_local_candidate(candidate.as_ref().into());
    drop(proto_agent);
    core::mem::forget(stream);
    core::mem::forget(candidate);
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_add_remote_candidate(
    stream: *mut RiceStream,
    candidate: *const RiceCandidate,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let candidate = Box::from_raw(mut_override(candidate));

    proto_stream
        .add_remote_candidate(candidate.as_ref().into())
        .unwrap();
    drop(proto_agent);
    core::mem::forget(stream);
    core::mem::forget(candidate);
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_end_of_local_candidates(stream: *mut RiceStream) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    proto_stream.end_of_local_candidates();
    drop(proto_agent);
    core::mem::forget(stream);
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_end_of_remote_candidates(stream: *mut RiceStream) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    proto_stream.end_of_remote_candidates();
    drop(proto_agent);
    core::mem::forget(stream);
}

#[derive(Debug)]
#[repr(C)]
pub enum RiceGatherPoll {
    NeedAgent(RiceGatherPollNeedAgent),
    SendData(RiceTransmit),
    WaitUntilMicros(u64),
    NewCandidate(*mut RiceCandidate),
    Complete,
}

#[no_mangle]
pub unsafe extern "C" fn rice_gather_poll_init(poll: *mut MaybeUninit<RiceGatherPoll>) {
    (*poll).write(RiceGatherPoll::Complete);
}

#[no_mangle]
pub unsafe extern "C" fn rice_gather_poll_clear(poll: *mut RiceGatherPoll) {
    let mut other = RiceGatherPoll::Complete;
    core::mem::swap(&mut other, &mut *poll);
    match other {
        RiceGatherPoll::Complete => (),
        RiceGatherPoll::WaitUntilMicros(_instant) => (),
        RiceGatherPoll::NeedAgent(need_agent) => need_agent.clear_c(),
        RiceGatherPoll::SendData(mut transmit) => {
            rice_transmit_clear(&mut transmit);
        }
        RiceGatherPoll::NewCandidate(candidate) => {
            rice_candidate_free(candidate);
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct RiceGatherPollNeedAgent {
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
}

impl RiceGatherPollNeedAgent {
    fn from_rust(
        component_id: usize,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Self {
        Self {
            component_id,
            transport: transport.into(),
            from: Box::into_raw(Box::new(RiceAddress::new(from))),
            to: Box::into_raw(Box::new(RiceAddress::new(to))),
        }
    }

    unsafe fn clear_c(self) {
        let _from = RiceAddress::from_c(self.from);
        let _to = RiceAddress::from_c(self.to);
    }
}

impl RiceGatherPoll {
    fn from_rust(value: GatherPoll, stream_id: usize, base_instant: Instant) -> Self {
        match value {
            GatherPoll::Complete => Self::Complete,
            GatherPoll::WaitUntil(instant) => Self::WaitUntilMicros(
                instant.saturating_duration_since(base_instant).as_micros() as u64,
            ),
            GatherPoll::NeedAgent(component_id, transport, from, to) => Self::NeedAgent(
                RiceGatherPollNeedAgent::from_rust(component_id, transport, from, to),
            ),
            GatherPoll::SendData(component_id, transmit) => {
                Self::SendData(transmit_from_rust_gather(stream_id, component_id, transmit))
            }
            GatherPoll::NewCandidate(cand) => {
                Self::NewCandidate(Box::into_raw(Box::new(cand.into())))
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_poll_gather(
    stream: *mut RiceStream,
    now_micros: u64,
    poll: *mut RiceGatherPoll,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();
    let now = stream.base_instant + Duration::from_micros(now_micros);

    *poll = RiceGatherPoll::from_rust(
        proto_stream.poll_gather(now).unwrap(),
        stream.stream_id,
        stream.base_instant,
    );

    drop(proto_agent);
    core::mem::forget(stream);
}

#[no_mangle]
pub unsafe extern "C" fn rice_stream_handle_gather_tcp_connect(
    stream: *mut RiceStream,
    component_id: usize,
    from: *const RiceAddress,
    to: *const RiceAddress,
    stun_agent: *mut RiceStunAgent,
) {
    let stream = Arc::from_raw(stream);
    let mut proto_agent = stream.proto_agent.lock().unwrap();
    let mut proto_stream = proto_agent.mut_stream(stream.stream_id).unwrap();

    let from = RiceAddress::from_c(from);
    let to = RiceAddress::from_c(to);

    let stun_agent = if stun_agent.is_null() {
        Err(StunError::ResourceNotFound)
    } else {
        Ok(Box::from_raw(stun_agent).0)
    };

    proto_stream.handle_gather_tcp_connect(component_id, **from, **to, stun_agent);

    drop(proto_agent);
    core::mem::forget(from);
    core::mem::forget(to);
    core::mem::forget(stream);
}

#[derive(Debug)]
#[repr(C)]
pub struct RiceStreamIncomingData {
    gather_handled: bool,
    conncheck_handled: bool,
    data_len: usize,
    data_data_lens: *const usize,
    data: *const *const u8,
}

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

#[no_mangle]
pub unsafe extern "C" fn rice_stream_handle_incoming_data(
    stream: *mut RiceStream,
    component_id: usize,
    transport: RiceTransportType,
    from: *const RiceAddress,
    to: *const RiceAddress,
    data: *const u8,
    data_len: usize,
) -> *mut RiceStreamIncomingData {
    let stream = Arc::from_raw(stream);
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

    let ret = proto_stream.handle_incoming_data(component_id, transmit);
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
        gather_handled: ret.gather_handled,
        conncheck_handled: ret.conncheck_handled,
        data,
        data_len,
        data_data_lens,
    }))
}

// TODO:
// - local_candidates
// - component_ids_iter
// - handle_gather_tcp_connect
// - handle_tcp_connect

#[derive(Debug)]
pub struct RiceComponent {
    proto_agent: Arc<Mutex<Agent>>,
    weak_agent: Weak<Mutex<RiceAgentInner>>,
    stream_id: usize,
    component_id: usize,
}

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
    });
    drop(proto_agent);

    let mut inner = stream.inner.lock().unwrap();
    inner.components.push(component.clone());

    drop(inner);
    core::mem::forget(stream);
    mut_override(Arc::into_raw(component))
}

#[no_mangle]
pub unsafe extern "C" fn rice_component_ref(component: *mut RiceComponent) -> *mut RiceComponent {
    Arc::increment_strong_count(component);
    component
}

#[no_mangle]
pub unsafe extern "C" fn rice_component_unref(component: *mut RiceComponent) {
    Arc::decrement_strong_count(component)
}

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

#[no_mangle]
pub unsafe extern "C" fn rice_component_gather_candidates(
    component: *mut RiceComponent,
    sockets_len: usize,
    sockets_addr: *const *mut RiceAddress,
    sockets_transports: *const RiceTransportType,
) {
    let component = Arc::from_raw(component);
    let stun_servers = {
        let Some(agent) = component.weak_agent.upgrade() else {
            return;
        };
        let agent = agent.lock().unwrap();
        agent.stun_servers.clone()
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
        .gather_candidates(sockets, stun_servers)
        .unwrap();
    drop(proto_agent);
    core::mem::forget(component);
}

#[no_mangle]
pub unsafe extern "C" fn rice_component_send(
    component: *mut RiceComponent,
    data: *mut u8,
    len: usize,
    transmit: *mut RiceTransmit,
) -> RiceError {
    let component = Arc::from_raw(component);

    let proto_agent = component.proto_agent.lock().unwrap();
    let proto_stream = proto_agent.stream(component.stream_id).unwrap();
    let proto_component = proto_stream.component(component.component_id).unwrap();

    let bytes = core::slice::from_raw_parts(data, len);
    match proto_component.send(bytes) {
        Ok(stun_transmit) => {
            *transmit = RiceTransmit {
                stream_id: component.stream_id,
                component_id: component.component_id,
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

#[repr(u32)]
pub enum RiceAddressFamily {
    Ipv4 = 1,
    Ipv6,
}

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

#[no_mangle]
pub unsafe extern "C" fn rice_address_get_port(addr: *const RiceAddress) -> u16 {
    let addr = RiceAddress::from_c(addr);
    let ret = addr.0.port();
    core::mem::forget(addr);
    ret
}

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

#[no_mangle]
pub unsafe extern "C" fn rice_address_copy(addr: *const RiceAddress) -> *mut RiceAddress {
    let addr = RiceAddress::from_c(mut_override(addr));
    let ret = mut_override(RiceAddress(addr.0).to_c());
    core::mem::forget(addr);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn rice_address_free(addr: *mut RiceAddress) {
    let _addr = Box::from_raw(addr);
}

#[derive(Debug)]
pub struct RiceStunAgent(StunAgent);

#[no_mangle]
pub unsafe extern "C" fn rice_stun_agent_new(
    transport: RiceTransportType,
    local_addr: *const RiceAddress,
    remote_addr: *const RiceAddress,
) -> *mut RiceStunAgent {
    let local_addr = RiceAddress::from_c(local_addr);
    let mut builder = StunAgent::builder(transport.into(), **local_addr);
    core::mem::forget(local_addr);

    if !remote_addr.is_null() {
        let remote_addr = RiceAddress::from_c(remote_addr);
        builder = builder.remote_addr(**remote_addr);
        core::mem::forget(remote_addr);
    }

    let ret = Box::new(RiceStunAgent(builder.build()));

    Box::into_raw(ret)
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

    fn udp_host_candidate() -> Candidate {
        let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
        Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .related_address(addr)
        .build()
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
        let rcand: RiceCandidate = candidate.clone().into();
        let new_cand: Candidate = (&rcand).into();
        assert_eq!(candidate, new_cand);
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

            let mut poll = RiceGatherPoll::Complete;
            rice_stream_poll_gather(stream, 0, &mut poll);
            let RiceGatherPoll::NewCandidate(_candidate) = poll else {
                unreachable!()
            };
            rice_gather_poll_clear(&mut poll);

            rice_stream_poll_gather(stream, 0, &mut poll);
            let RiceGatherPoll::NewCandidate(_candidate) = poll else {
                unreachable!()
            };
            rice_gather_poll_clear(&mut poll);

            rice_stream_poll_gather(stream, 0, &mut poll);
            let RiceGatherPoll::NeedAgent(ref need_agent) = poll else {
                unreachable!()
            };

            let mut poll_wait = RiceGatherPoll::Complete;
            rice_stream_poll_gather(stream, 0, &mut poll_wait);
            let RiceGatherPoll::WaitUntilMicros(now) = poll_wait else {
                unreachable!()
            };
            rice_gather_poll_clear(&mut poll_wait);

            let tcp_from_addr = "192.168.200.4:3000".parse().unwrap();
            let tcp_from_addr = RiceAddress::new(tcp_from_addr).to_c();
            let stun_agent =
                rice_stun_agent_new(TransportType::Tcp.into(), tcp_from_addr, need_agent.to);
            let _tcp_from_addr = RiceAddress::from_c(tcp_from_addr);
            rice_stream_handle_gather_tcp_connect(
                stream,
                need_agent.component_id,
                need_agent.from,
                need_agent.to,
                stun_agent,
            );
            rice_gather_poll_clear(&mut poll);

            rice_stream_poll_gather(stream, 0, &mut poll);
            let RiceGatherPoll::SendData(ref _send) = poll else {
                unreachable!()
            };
            rice_gather_poll_clear(&mut poll);

            let mut poll = RiceGatherPoll::Complete;
            rice_stream_poll_gather(stream, now, &mut poll);
            rice_gather_poll_clear(&mut poll);

            let mut ret = RiceAgentPoll::Closed;
            rice_agent_poll(agent, 0, &mut ret);
            rice_agent_poll_clear(&mut ret);

            rice_component_unref(component);
            rice_stream_unref(stream);
            rice_agent_unref(agent);
        }
    }
}
