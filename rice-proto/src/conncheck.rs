// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Connectivity check module for checking a set of candidates for an appropriate candidate pair to
//! transfer data with.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::net::{IpAddr, SocketAddr};
use core::ops::Range;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use crate::candidate::{Candidate, CandidatePair, CandidateType, TcpType, TransportType};
use crate::component::ComponentConnectionState;
use crate::gathering::GatheredCandidate;
use crate::rand::generate_random_ice_string;
use crate::tcp::TcpBuffer;
use byteorder::{BigEndian, ByteOrder};
use rice_stun_types::attribute::{IceControlled, IceControlling, Priority, UseCandidate};
use stun_proto::agent::{HandleStunReply, StunAgent, StunAgentPollRet, StunError, Transmit};
use stun_proto::types::attribute::*;
use stun_proto::types::data::Data;
use stun_proto::types::message::*;
use stun_proto::Instant;
use turn_client_proto::api::{TransmitBuild, TurnEvent, TurnPollRet, TurnRecvRet};
use turn_client_proto::client::TurnClient;
use turn_client_proto::prelude::*;

use tracing::{debug, error, info, trace, warn};

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StunAgentId(usize);

impl core::ops::Deref for StunAgentId {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StunAgentId {
    fn generate() -> Self {
        let stun_agent_id = STUN_AGENT_COUNT.fetch_add(1, Ordering::SeqCst);
        Self(stun_agent_id)
    }
}

impl core::fmt::Display for StunAgentId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// ICE Credentials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The username fragment.
    pub ufrag: String,
    /// The password.
    pub passwd: String,
}

impl From<Credentials> for ShortTermCredentials {
    fn from(cred: Credentials) -> Self {
        ShortTermCredentials::new(cred.passwd)
    }
}

impl Credentials {
    /// Constructs a new set of [`Credentials`]
    pub fn new(username: String, password: String) -> Self {
        // TODO: validate contents
        Self {
            ufrag: username,
            passwd: password,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SelectedTurn {
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl SelectedTurn {
    pub fn transport(&self) -> TransportType {
        self.transport
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// A pair that has been selected for a component
#[derive(Debug, Clone)]
pub struct SelectedPair {
    candidate_pair: CandidatePair,
    local_stun_agent: StunAgentId,
    turn: Option<SelectedTurn>,
}

impl SelectedPair {
    /// Create a new [`SelectedPair`].  The pair and stun agent must be compatible.
    pub(crate) fn new(
        candidate_pair: CandidatePair,
        local_stun_agent: StunAgentId,
        turn: Option<SelectedTurn>,
    ) -> Self {
        Self {
            candidate_pair,
            local_stun_agent,
            turn,
        }
    }

    /// The pair for this [`SelectedPair`]
    pub fn candidate_pair(&self) -> &CandidatePair {
        &self.candidate_pair
    }

    /// Any TURN connection the local candidate must be connected through.
    pub fn local_turn(&self) -> Option<&SelectedTurn> {
        self.turn.as_ref()
    }

    /// The local STUN agent for this [`SelectedPair`]
    pub(crate) fn stun_agent_id(&self) -> StunAgentId {
        self.local_stun_agent
    }
}

/// Return value when handling received data
#[derive(Debug)]
pub struct HandleRecvReply<T: AsRef<[u8]> + core::fmt::Debug> {
    pub handled: bool,
    pub have_more_data: bool,
    pub data: Option<DataAndRange<T>>,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> core::fmt::Display for HandleRecvReply<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HandleRecvReply {{")?;
        let mut need_comma = false;
        if self.handled {
            write!(f, "handled, ")?;
            need_comma = true;
        }
        if let Some(data) = self.data.as_ref() {
            if need_comma {
                write!(f, ", ")?;
            }
            write!(f, "{} bytes", data.as_ref().len())?;
        }
        write!(f, "}}")
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> Default for HandleRecvReply<T> {
    fn default() -> Self {
        Self {
            handled: false,
            have_more_data: false,
            data: None,
        }
    }
}

#[derive(Debug)]
pub struct DataAndRange<T: AsRef<[u8]> + core::fmt::Debug> {
    data: T,
    range: Range<usize>,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> AsRef<[u8]> for DataAndRange<T> {
    fn as_ref(&self) -> &[u8] {
        &self.data.as_ref()[self.range.start..self.range.end]
    }
}

/// Events that can be produced during the connectivity check process
#[derive(Debug)]
pub enum ConnCheckEvent {
    /// The state of a component has changed
    ComponentState(usize, ComponentConnectionState),
    /// A component has chosen a pair.  This pair should be used to send and receive data from.
    SelectedPair(usize, Box<SelectedPair>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

impl core::fmt::Display for CandidatePairState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.pad(&alloc::format!("{self:?}"))
    }
}

static CONN_CHECK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
struct TcpConnCheck {
    agent: Option<StunAgentId>,
}

#[derive(Debug, Clone)]
enum ConnCheckVariant {
    Agent(StunAgentId),
    Tcp(TcpConnCheck),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
struct ConnCheckId(usize);

impl core::ops::Deref for ConnCheckId {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConnCheckId {
    fn generate() -> Self {
        let conncheck_id = CONN_CHECK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self(conncheck_id)
    }
}

impl core::fmt::Display for ConnCheckId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
struct ConnCheck {
    conncheck_id: ConnCheckId,
    checklist_id: usize,
    nominate: bool,
    pair: CandidatePair,
    variant: ConnCheckVariant,
    controlling: bool,
    state: CandidatePairState,
    stun_request: Option<TransactionId>,
    remote_credentials: Credentials,
}

impl ConnCheck {
    fn new(
        checklist_id: usize,
        pair: CandidatePair,
        agent: StunAgentId,
        nominate: bool,
        controlling: bool,
        remote_credentials: Credentials,
    ) -> Self {
        Self {
            conncheck_id: ConnCheckId::generate(),
            checklist_id,
            pair,
            state: CandidatePairState::Frozen,
            stun_request: None,
            variant: ConnCheckVariant::Agent(agent),
            nominate,
            controlling,
            remote_credentials,
        }
    }

    fn new_tcp(
        checklist_id: usize,
        pair: CandidatePair,
        nominate: bool,
        controlling: bool,
        remote_credentials: Credentials,
    ) -> Self {
        Self {
            conncheck_id: ConnCheckId::generate(),
            checklist_id,
            pair,
            state: CandidatePairState::Frozen,
            stun_request: None,
            variant: ConnCheckVariant::Tcp(TcpConnCheck { agent: None }),
            nominate,
            controlling,
            remote_credentials,
        }
    }

    fn agent_id(&self) -> Option<StunAgentId> {
        match &self.variant {
            ConnCheckVariant::Agent(agent) => Some(*agent),
            ConnCheckVariant::Tcp(tcp) => tcp.agent,
        }
    }

    fn state(&self) -> CandidatePairState {
        self.state
    }

    #[tracing::instrument(
        name = "set_check_state",
        level = "debug",
        skip(self, state),
        fields(
            ?self.conncheck_id,
        )
    )]
    fn set_state(&mut self, state: CandidatePairState) {
        // TODO: validate state change
        if self.state != state {
            debug!(old_state = ?self.state, new_state = ?state, "updating state");
            self.state = state;
        }
    }

    fn nominate(&self) -> bool {
        self.nominate
    }

    fn generate_stun_request(
        pair: &CandidatePair,
        nominate: bool,
        controlling: bool,
        tie_breaker: u64,
        local_credentials: Credentials,
        remote_credentials: Credentials,
    ) -> Result<MessageWriteVec, StunError> {
        let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;

        // XXX: this needs to be the priority as if the candidate was peer-reflexive
        let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
        let priority = Priority::new(pair.local.priority);
        msg.add_attribute(&priority)?;
        let control = IceControlling::new(tie_breaker);
        let controlled = IceControlled::new(tie_breaker);
        if controlling {
            msg.add_attribute(&control)?;
        } else {
            msg.add_attribute(&controlled)?;
        }
        let use_cand = UseCandidate::new();
        if nominate {
            msg.add_attribute(&use_cand)?;
        }
        let username = Username::new(&username)?;
        msg.add_attribute(&username)?;
        msg.add_message_integrity(
            &MessageIntegrityCredentials::ShortTerm(remote_credentials.clone().into()),
            IntegrityAlgorithm::Sha1,
        )?;
        msg.add_fingerprint()?;
        Ok(msg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CheckListState {
    Running,
    Completed,
    Failed,
}

static CONN_CHECK_LIST_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct CheckStunAgent {
    id: StunAgentId,
    agent: StunAgent,
}

/// A list of connectivity checks for an ICE stream
#[derive(Debug)]
pub struct ConnCheckList {
    checklist_id: usize,
    state: CheckListState,
    component_ids: Vec<(usize, ComponentConnectionState)>,
    local_credentials: Credentials,
    remote_credentials: Credentials,
    local_candidates: Vec<ConnCheckLocalCandidate>,
    remote_candidates: Vec<Candidate>,
    // TODO: move to BinaryHeap or similar
    triggered: VecDeque<ConnCheckId>,
    pairs: VecDeque<ConnCheck>,
    valid: Vec<ConnCheckId>,
    nominated: Vec<ConnCheckId>,
    controlling: bool,
    trickle_ice: bool,
    local_end_of_candidates: bool,
    remote_end_of_candidates: bool,
    events: VecDeque<ConnCheckEvent>,
    agents: Vec<CheckStunAgent>,
    turn_clients: Vec<(StunAgentId, TurnClient)>,
    pending_delete_turn_clients: Vec<(StunAgentId, TurnClient)>,
    tcp_buffers: BTreeMap<(SocketAddr, SocketAddr), TcpBuffer>,
    pending_turn_permissions: VecDeque<(StunAgentId, TransportType, IpAddr)>,
    pending_recv: VecDeque<PendingRecv>,
}

fn candidate_is_same_connection(a: &Candidate, b: &Candidate) -> bool {
    if a.component_id != b.component_id {
        return false;
    }
    if a.transport_type != b.transport_type {
        return false;
    }
    if a.base_address != b.base_address {
        return false;
    }
    if a.address != b.address {
        return false;
    }
    // TODO: active vs passive vs simultaneous open
    if a.tcp_type != b.tcp_type {
        return false;
    }
    // XXX: extensions?
    true
}

fn candidate_pair_is_same_connection(a: &CandidatePair, b: &CandidatePair) -> bool {
    if !candidate_is_same_connection(&a.local, &b.local) {
        return false;
    }
    if !candidate_is_same_connection(&a.remote, &b.remote) {
        return false;
    }
    true
}

fn candidate_agent_local_address(candidate: &Candidate) -> SocketAddr {
    if candidate.candidate_type == CandidateType::Relayed {
        candidate.address
    } else {
        candidate.base_address
    }
}

#[derive(Debug)]
enum LocalCandidateVariant {
    Agent(StunAgentId),
    TcpListener,
    TcpActive,
}

#[derive(Debug)]
struct ConnCheckLocalCandidate {
    candidate: Candidate,
    variant: LocalCandidateVariant,
}

fn response_add_credentials<O, B: MessageWrite<Output = O>>(
    mut response: B,
    local_credentials: MessageIntegrityCredentials,
) -> Result<B, StunError> {
    response.add_message_integrity(&local_credentials, IntegrityAlgorithm::Sha1)?;
    response.add_fingerprint()?;
    Ok(response)
}
fn binding_success_response(
    msg: &Message<'_>,
    from: SocketAddr,
    local_credentials: MessageIntegrityCredentials,
) -> MessageWriteVec {
    let mut response = Message::builder_success(msg, MessageWriteVec::new());
    let xor_addr = XorMappedAddress::new(from, msg.transaction_id());
    response.add_attribute(&xor_addr).unwrap();
    response_add_credentials(response, local_credentials).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Nominate {
    True,
    False,
    DontCare,
}

impl PartialEq<Nominate> for Nominate {
    fn eq(&self, other: &Nominate) -> bool {
        matches!(self, &Nominate::DontCare)
            || matches!(other, &Nominate::DontCare)
            || (matches!(self, Nominate::True) && matches!(other, Nominate::True))
            || (matches!(self, Nominate::False) && matches!(other, Nominate::False))
    }
}
impl PartialEq<bool> for Nominate {
    fn eq(&self, other: &bool) -> bool {
        matches!(self, Nominate::DontCare)
            || (*other && self.eq(&Nominate::True))
            || (!*other && self.eq(&Nominate::False))
    }
}

fn generate_random_credentials() -> Credentials {
    let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/".as_bytes();
    let user = generate_random_ice_string(alphabet, 4);
    let pass = generate_random_ice_string(alphabet, 22);
    Credentials::new(user, pass)
}

impl ConnCheckList {
    fn new(checklist_id: usize, controlling: bool, trickle_ice: bool) -> Self {
        Self {
            checklist_id,
            state: CheckListState::Running,
            component_ids: Vec::new(),
            local_credentials: generate_random_credentials(),
            remote_credentials: generate_random_credentials(),
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            triggered: VecDeque::new(),
            pairs: VecDeque::new(),
            valid: Vec::new(),
            nominated: Vec::new(),
            controlling,
            trickle_ice,
            local_end_of_candidates: false,
            remote_end_of_candidates: false,
            events: VecDeque::new(),
            agents: Vec::new(),
            turn_clients: Vec::new(),
            pending_delete_turn_clients: Vec::new(),
            tcp_buffers: BTreeMap::default(),
            pending_turn_permissions: VecDeque::new(),
            pending_recv: VecDeque::new(),
        }
    }

    fn state(&self) -> CheckListState {
        self.state
    }

    /// Set the local [`Credentials`] for this checklist
    pub fn set_local_credentials(&mut self, credentials: Credentials) {
        trace!(
            "changing local credentials from {:?} to {credentials:?}",
            self.remote_credentials
        );
        for agent in self.agents.iter_mut() {
            agent
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    credentials.clone().into(),
                ));
        }
        self.local_credentials = credentials;
    }

    /// Set the remote [`Credentials`] for this checklist
    pub fn set_remote_credentials(&mut self, credentials: Credentials) {
        trace!(
            "changing remote credentials from {:?} to {credentials:?}",
            self.remote_credentials
        );
        for agent in self.agents.iter_mut() {
            agent
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    credentials.clone().into(),
                ));
        }

        // If we already have checks that are using old or outdated credentials, replace them with
        // new checks that use the new remote credentials
        let mut request_cancels = Vec::new();
        let new_pairs = self
            .pairs
            .drain(..)
            .map(|mut check| {
                if check.remote_credentials != credentials {
                    if let Some((agent_id, request_id)) =
                        check.agent_id().zip(check.stun_request.take())
                    {
                        request_cancels.push((agent_id, request_id));
                        let mut check = ConnCheck::new(
                            check.checklist_id,
                            check.pair.clone(),
                            agent_id,
                            check.nominate(),
                            check.controlling,
                            credentials.clone(),
                        );
                        if check.state != CandidatePairState::Frozen {
                            check.set_state(CandidatePairState::Waiting);
                        }
                        if let ConnCheckVariant::Tcp(ref mut tcp) = check.variant {
                            tcp.agent.take();
                        }
                        check
                    } else {
                        check
                    }
                } else {
                    check
                }
            })
            .collect::<VecDeque<_>>();
        self.pairs = new_pairs;
        self.sort_pairs();

        for (agent_id, request_id) in request_cancels {
            let Some(agent) = self.mut_agent_by_id(agent_id) else {
                continue;
            };
            let Some(mut request) = agent.mut_request_transaction(request_id) else {
                continue;
            };
            request.cancel();
        }

        self.remote_credentials = credentials;
    }

    /// Add a component id to this checklist
    pub fn add_component(&mut self, component_id: usize) {
        if self
            .component_ids
            .iter()
            .any(|(cid, _state)| component_id == *cid)
        {
            panic!("Component with ID {component_id} already exists in checklist!");
        };
        self.component_ids
            .push((component_id, ComponentConnectionState::New));
    }

    fn poll_event(&mut self) -> Option<ConnCheckEvent> {
        self.events.pop_back()
    }

    pub(crate) fn poll_recv(&mut self) -> Option<PendingRecv> {
        self.pending_recv.pop_front()
    }

    pub(crate) fn add_agent_for_5tuple(
        &mut self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> (StunAgentId, usize) {
        let mut agent = StunAgent::builder(transport, local);
        if transport == TransportType::Tcp {
            agent = agent.remote_addr(remote);
        }
        let agent = agent.build();
        self.add_agent(agent)
    }

    fn add_agent(&mut self, agent: StunAgent) -> (StunAgentId, usize) {
        let agent_id = StunAgentId::generate();
        self.agents.push(CheckStunAgent {
            id: agent_id,
            agent,
        });
        (agent_id, self.agents.len() - 1)
    }

    pub(crate) fn mut_agent_for_5tuple(
        &mut self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<(StunAgentId, &mut StunAgent)> {
        self.agents.iter_mut().find_map(|a| {
            let matched = match transport {
                TransportType::Udp => {
                    a.agent.local_addr() == local && a.agent.transport() == TransportType::Udp
                }
                TransportType::Tcp => {
                    a.agent.local_addr() == local
                        && a.agent.transport() == TransportType::Tcp
                        && a.agent.remote_addr().unwrap() == remote
                }
            };
            if matched {
                Some((a.id, &mut a.agent))
            } else {
                None
            }
        })
    }

    pub(crate) fn find_agent_for_5tuple(
        &self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<(StunAgentId, &StunAgent)> {
        self.agents.iter().find_map(|a| {
            let matched = match transport {
                TransportType::Udp => {
                    a.agent.local_addr() == local && a.agent.transport() == TransportType::Udp
                }
                TransportType::Tcp => {
                    a.agent.local_addr() == local
                        && a.agent.transport() == TransportType::Tcp
                        && a.agent.remote_addr().unwrap() == remote
                }
            };
            if matched {
                Some((a.id, &a.agent))
            } else {
                None
            }
        })
    }

    pub(crate) fn agent_by_id(&self, id: StunAgentId) -> Option<&StunAgent> {
        self.agents.iter().find_map(|agent| {
            if id == agent.id {
                Some(&agent.agent)
            } else {
                None
            }
        })
    }

    pub(crate) fn mut_agent_by_id(&mut self, id: StunAgentId) -> Option<&mut StunAgent> {
        self.agents.iter_mut().find_map(|agent| {
            if id == agent.id {
                Some(&mut agent.agent)
            } else {
                None
            }
        })
    }

    pub(crate) fn find_or_create_udp_agent(
        &mut self,
        candidate: &Candidate,
        local_credentials: &Credentials,
        remote_credentials: &Credentials,
    ) -> (StunAgentId, &StunAgent) {
        if let Some(agent_id) = self
            .agents
            .iter()
            .find(|a| {
                let a = &a.agent;
                match candidate.transport_type {
                    TransportType::Udp => {
                        a.local_addr() == candidate_agent_local_address(candidate)
                            && a.transport() == TransportType::Udp
                    }
                    _ => false,
                }
            })
            .map(|a| a.id)
        {
            return (agent_id, self.agent_by_id(agent_id).unwrap());
        }
        let mut agent = StunAgent::builder(
            candidate.transport_type,
            candidate_agent_local_address(candidate),
        )
        .build();
        agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
            local_credentials.clone().into(),
        ));
        agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
            remote_credentials.clone().into(),
        ));
        let (agent_id, agent_idx) = self.add_agent(agent);
        (agent_id, &self.agents[agent_idx].agent)
    }

    fn mut_turn_client_by_id(&mut self, id: StunAgentId) -> Option<&mut TurnClient> {
        self.turn_clients
            .iter_mut()
            .chain(self.pending_delete_turn_clients.iter_mut())
            .find_map(|(needle, client)| if id == *needle { Some(client) } else { None })
    }

    fn remove_turn_client_by_id(&mut self, id: StunAgentId) -> Option<TurnClient> {
        if let Some(position) = self
            .turn_clients
            .iter()
            .position(|(needle, _client)| id == *needle)
        {
            Some(self.turn_clients.remove(position).1)
        } else {
            None
        }
    }

    fn turn_client_by_allocated_address(
        &self,
        transport: TransportType,
        allocated: SocketAddr,
    ) -> Option<(StunAgentId, &TurnClient)> {
        self.turn_clients.iter().find_map(|(id, client)| {
            if client
                .relayed_addresses()
                .any(|(relayed_transport, relayed)| {
                    relayed_transport == transport && relayed == allocated
                })
            {
                Some((*id, client))
            } else {
                None
            }
        })
    }

    pub(crate) fn mut_turn_client_by_allocated_address(
        &mut self,
        transport: TransportType,
        allocated: SocketAddr,
    ) -> Option<(StunAgentId, &mut TurnClient)> {
        self.turn_clients
            .iter_mut()
            .chain(self.pending_delete_turn_clients.iter_mut())
            .find_map(|(id, client)| {
                if client
                    .relayed_addresses()
                    .any(|(relayed_transport, relayed)| {
                        relayed_transport == transport && relayed == allocated
                    })
                {
                    Some((*id, client))
                } else {
                    None
                }
            })
    }

    pub(crate) fn find_turn_client_for_5tuple(
        &self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<(StunAgentId, &TurnClient)> {
        self.turn_clients
            .iter()
            .chain(self.pending_delete_turn_clients.iter())
            .find_map(|(id, client)| {
                if client.local_addr() == local
                    && client.transport() == transport
                    && client.remote_addr() == remote
                {
                    Some((*id, client))
                } else {
                    None
                }
            })
    }

    /// Add a local candidate to this checklist.
    ///
    /// Should call the `poll` loop at the next earliest opportunity.
    ///
    /// # Panics
    ///
    /// - end_of_local_candidates() has already been called
    /// - add_component() for the candidate has not been called
    #[tracing::instrument(
        level = "info"
        skip(self, gathered),
        fields(
            checklist_id = self.checklist_id,
            candidate = ?gathered.candidate,
        )
    )]
    pub fn add_local_gathered_candidate(&mut self, gathered: GatheredCandidate) -> bool {
        let candidate_type = gathered.candidate.candidate_type;
        if !self.add_local_candidate_internal(gathered.candidate) {
            return false;
        }
        if candidate_type == CandidateType::Relayed {
            let client = gathered.turn_agent.unwrap();
            let agent_id = StunAgentId::generate();
            self.turn_clients.push((agent_id, *client));
        }
        self.generate_checks();
        true
    }

    /// Add a local candidate to this checklist.
    ///
    /// Should call the `poll` loop at the next earliest opportunity.
    ///
    /// # Panics
    ///
    /// - end_of_local_candidates() has already been called
    /// - add_component() for the candidate has not been called
    #[tracing::instrument(
        level = "info"
        skip(self),
        fields(
            checklist_id = self.checklist_id,
        )
    )]
    pub fn add_local_candidate(&mut self, local: Candidate) -> bool {
        if self.add_local_candidate_internal(local) {
            self.generate_checks();
            true
        } else {
            false
        }
    }

    fn add_local_candidate_internal(&mut self, local: Candidate) -> bool {
        let (local_credentials, remote_credentials) = {
            if self.local_end_of_candidates {
                panic!("Attempt made to add a local candidate after end-of-candidate received");
            }
            let existing = self
                .component_ids
                .iter()
                .find(|(id, _state)| id == &local.component_id);
            if let Some(_existing) = existing {
                (
                    self.local_credentials.clone(),
                    self.remote_credentials.clone(),
                )
            } else {
                panic!(
                    "Attempt made to add a local candidate without a corresponding add_component()"
                );
            }
        };

        if let Some(idx) = self
            .local_candidates
            .iter()
            .position(|c| local.redundant_with(&c.candidate))
        {
            let other = &self.local_candidates[idx].candidate;
            if self.trickle_ice || other.priority >= local.priority {
                debug!("not adding redundant candidate");
                return false;
            } else if !self.trickle_ice {
                let removed = self.local_candidates.swap_remove(idx);
                debug!(
                    "removing already existing redundant candidate {:?}",
                    removed.candidate
                );
                self.pairs.retain(|pair| {
                    pair.pair.local != removed.candidate
                        || ![
                            CandidatePairState::InProgress,
                            CandidatePairState::Succeeded,
                        ]
                        .contains(&pair.state)
                });
                // TODO: signal potential socket/agent removal?
            }
        }

        info!("adding");

        match local.transport_type {
            TransportType::Udp => {
                let (agent_id, _) =
                    self.find_or_create_udp_agent(&local, &local_credentials, &remote_credentials);
                self.local_candidates.push(ConnCheckLocalCandidate {
                    candidate: local,
                    variant: LocalCandidateVariant::Agent(agent_id),
                });
            }
            TransportType::Tcp => {
                let tcp_type = local.tcp_type.unwrap();
                if matches!(tcp_type, TcpType::Passive | TcpType::So) {
                    self.local_candidates.push(ConnCheckLocalCandidate {
                        candidate: local,
                        variant: LocalCandidateVariant::TcpListener,
                    });
                } else {
                    self.local_candidates.push(ConnCheckLocalCandidate {
                        candidate: local,
                        variant: LocalCandidateVariant::TcpActive,
                    });
                }
            }
        }
        true
    }

    /// Signal to the checklist that no more local candidates will be provided.
    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id,
        )
    )]
    pub fn end_of_local_candidates(&mut self) {
        info!("end of local candidates");
        self.local_end_of_candidates = true;
        if self.remote_end_of_candidates {
            self.check_for_failure();
        }
        self.dump_check_state();
    }

    /// Signal to the checklist that no more remote candidates will be provided
    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id,
        )
    )]
    pub fn end_of_remote_candidates(&mut self) {
        info!("end of remote candidates");
        self.remote_end_of_candidates = true;
        if self.local_end_of_candidates {
            self.check_for_failure();
        }
        self.dump_check_state();
    }

    /// Add a remote candidate to the checklist
    pub fn add_remote_candidate(&mut self, remote: Candidate) {
        if remote.candidate_type != CandidateType::PeerReflexive && self.remote_end_of_candidates {
            error!("Attempt made to add a remote candidate after an end-of-candidates received");
            return;
        }
        if !self
            .component_ids
            .iter()
            .any(|(cid, _state)| cid == &remote.component_id)
        {
            self.component_ids
                .push((remote.component_id, ComponentConnectionState::New));
        }
        self.remote_candidates.push(remote);
        self.generate_checks();
        self.dump_check_state();
    }

    fn next_triggered(&mut self) -> Option<&mut ConnCheck> {
        // triggered checks referenced by these ids may be removed before the check has a chance to
        // start.  Simply remove them and continue processing.
        while let Some(check_id) = self.triggered.pop_back() {
            if let Some(check) = self.mut_check_by_id(check_id) {
                // Don't trigger this check if there is already a STUN request in progress.
                // Can happen on remote input if the same check is triggered while the check is
                // sent to the peer.
                if check.stun_request.is_some() {
                    continue;
                }
                check.set_state(CandidatePairState::InProgress);
                return self.mut_check_by_id(check_id);
            }
        }
        None
    }

    #[cfg(test)]
    fn is_triggered(&self, needle: &CandidatePair) -> bool {
        trace!("triggered {:?}", self.triggered);
        self.triggered.iter().any(|&check_id| {
            self.check_by_id(check_id)
                .map_or(false, |check| needle == &check.pair)
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn next_waiting(&mut self) -> Option<&mut ConnCheck> {
        self.pairs
            .iter_mut()
            // first look for any that are waiting
            // FIXME: should be highest priority pair: make the data structure give us that by
            // default
            .filter_map(|check| {
                if check.state == CandidatePairState::Waiting {
                    check.set_state(CandidatePairState::InProgress);
                    Some(check)
                } else {
                    None
                }
            })
            .next()
    }

    fn foundations(&self) -> BTreeSet<String> {
        let mut foundations = BTreeSet::new();
        let _: Vec<_> = self
            .pairs
            .iter()
            .inspect(|check| {
                foundations.insert(check.pair.foundation());
            })
            .collect();
        foundations
    }

    fn check_has_turn_permission(&self, check: &ConnCheck) -> bool {
        if check.pair.local.candidate_type == CandidateType::Relayed {
            let Some((_id, client)) = self.turn_client_by_allocated_address(
                check.pair.local.transport_type,
                check.pair.local.address,
            ) else {
                return false;
            };
            if client
                .permissions(check.pair.local.transport_type, check.pair.local.address)
                .all(|permission| permission != check.pair.remote.address.ip())
            {
                return false;
            }
        }
        true
    }

    fn foundation_not_waiting_in_progress(&self, foundation: &str) -> bool {
        for check in self
            .pairs
            .iter()
            .filter(|check| check.pair.foundation() == foundation)
        {
            if !self.check_has_turn_permission(check) {
                return false;
            }
            let state = check.state();
            if [CandidatePairState::InProgress, CandidatePairState::Waiting].contains(&state) {
                return false;
            }
        }
        true
    }

    /// The list of local candidates currently configured for this checklist
    pub fn local_candidates(&self) -> impl Iterator<Item = &'_ Candidate> + '_ {
        self.local_candidates.iter().map(|local| &local.candidate)
    }

    /// The list of remote candidates currently configured for this checklist
    pub fn remote_candidates(&self) -> &[Candidate] {
        &self.remote_candidates
    }

    #[tracing::instrument(
        name = "set_checklist_state",
        level = "debug",
        skip(self),
        fields(
            self.checklist_id,
        )
    )]
    fn set_state(&mut self, state: CheckListState) {
        if self.state != state {
            trace!(old_state = ?self.state, new_state = ?state, "changing state");
            self.state = state;
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            self.checklist_id
        )
    )]
    fn find_remote_candidate(
        &self,
        component_id: usize,
        ttype: TransportType,
        addr: SocketAddr,
    ) -> Option<Candidate> {
        self.remote_candidates
            .iter()
            .find(|&remote| {
                remote.component_id == component_id
                    && remote.transport_type == ttype
                    && remote.address == addr
            })
            .cloned()
    }

    fn check_by_id(&self, id: ConnCheckId) -> Option<&ConnCheck> {
        self.pairs.iter().find(|check| check.conncheck_id == id)
    }

    fn mut_check_by_id(&mut self, id: ConnCheckId) -> Option<&mut ConnCheck> {
        self.pairs.iter_mut().find(|check| check.conncheck_id == id)
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, check),
        fields(
            self.checklist_id,
            check.conncheck_id
        )
    )]
    fn add_triggered(&mut self, check: &ConnCheck) {
        if let Some(idx) = self.triggered.iter().position(|&existing| {
            self.check_by_id(existing).map_or(false, |existing| {
                candidate_pair_is_same_connection(&existing.pair, &check.pair)
            })
        }) {
            let triggered = self.check_by_id(self.triggered[idx]).unwrap();
            // a nominating check trumps not nominating.  Otherwise, if the peers are delay sync,
            // then the non-nominating trigerred check may override the nomination process for a
            // long time and delay the connection process
            if check.nominate() && !triggered.nominate()
                || triggered.state() == CandidatePairState::Failed
            {
                let existing = self.triggered.remove(idx).unwrap();
                debug!("removing existing triggered {}", existing);
            } else {
                debug!("not adding duplicate triggered check");
                return;
            }
        }
        debug!("adding triggered check {}", check.conncheck_id);
        self.triggered.push_front(check.conncheck_id)
    }

    fn foundation_has_check_state(&self, foundation: &str, state: CandidatePairState) -> bool {
        self.pairs
            .iter()
            .any(|check| check.pair.foundation() == foundation && check.state() == state)
    }

    fn thawn_foundations(&mut self) -> Vec<String> {
        // XXX: cache this?
        let mut thawn_foundations = Vec::new();
        for check in self.pairs.iter() {
            if !thawn_foundations
                .iter()
                .any(|foundation| check.pair.foundation() == *foundation)
            {
                thawn_foundations.push(check.pair.foundation().clone());
            }
        }
        thawn_foundations
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn generate_checks(&mut self) {
        let mut checks = Vec::new();
        // Trickle ICE mandates that we only check redundancy with Frozen or Waiting pairs.  This
        // is compatible with non-trickle-ICE as checks start off in the frozen state until the
        // initial thaw.
        let mut pairs: Vec<_> = self
            .pairs
            .iter()
            .filter_map(|check| {
                if matches!(
                    check.state(),
                    CandidatePairState::Waiting | CandidatePairState::Frozen
                ) {
                    Some(check.pair.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut redundant_pairs = Vec::new();
        let mut turn_checks = Vec::new();

        for local in self.local_candidates.iter() {
            let turn_client_id = if local.candidate.candidate_type == CandidateType::Relayed {
                let turn_client_id = self
                    .turn_client_by_allocated_address(
                        local.candidate.transport_type,
                        local.candidate.address,
                    )
                    .map(|(id, _client)| id);
                if turn_client_id.is_none() {
                    warn!("No configured TURN client for candidate: {local:?}, ignoring");
                    continue;
                }
                turn_client_id
            } else {
                None
            };
            for remote in self.remote_candidates.iter() {
                if candidate_can_pair_with(&local.candidate, remote) {
                    let pair = CandidatePair::new(local.candidate.clone(), remote.clone());
                    let component_id = self
                        .component_ids
                        .iter()
                        .find(|(id, _state)| id == &local.candidate.component_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "No component {} for local candidate",
                                local.candidate.component_id
                            )
                        });

                    if let Some(redundant_pair) = pair.redundant_with(pairs.iter()) {
                        if redundant_pair.remote.candidate_type == CandidateType::PeerReflexive {
                            match local.variant {
                                LocalCandidateVariant::Agent(ref agent_id) => {
                                    redundant_pairs.push((
                                        redundant_pair.clone(),
                                        pair,
                                        *agent_id,
                                        component_id,
                                    ));
                                }
                                LocalCandidateVariant::TcpActive
                                | LocalCandidateVariant::TcpListener => {}
                            }
                        } else {
                            //trace!("not adding redundant pair {:?}", pair);
                        }
                    } else {
                        if let Some(turn_client_id) = turn_client_id {
                            turn_checks.push((turn_client_id, pair.clone()));
                        }
                        pairs.push(pair.clone());
                        match local.variant {
                            LocalCandidateVariant::Agent(ref agent_id) => {
                                checks.push(ConnCheck::new(
                                    self.checklist_id,
                                    pair.clone(),
                                    *agent_id,
                                    false,
                                    self.controlling,
                                    self.remote_credentials.clone(),
                                ));
                            }
                            LocalCandidateVariant::TcpActive => {
                                checks.push(ConnCheck::new_tcp(
                                    self.checklist_id,
                                    pair.clone(),
                                    false,
                                    self.controlling,
                                    self.remote_credentials.clone(),
                                ));
                            }
                            LocalCandidateVariant::TcpListener => (), // FIXME need something here?
                        }
                        //debug!("generated pair {:?}", pair);
                    }
                }
            }
        }
        /*
        for (peer_reflexive_pair, pair, local, component) in redundant_pairs {
            // try to replace the existing check with a non-peer reflexive version
            if let Some(check) = self.take_matching_check(&peer_reflexive_pair) {
                if !matches!(check.state(), CandidatePairState::InProgress) {
                    check.cancel();
                    match local {
                        LocalCandidateVariant::StunAgent(agent) => checks.push(Arc::new(ConnCheck::new(pair, agent.stun_agent, false))),
                        LocalCandidateVariant::TcpListen(_tcp) => checks.push(Arc::new(ConnCheck::new_tcp(pair, false, weak_inner.clone(), component))),
                        LocalCandidateVariant::TcpActive => (),
                    }
                } else {
                    self.add_check_if_not_duplicate(check);
                }
            }
        }*/

        for (turn_id, pair) in turn_checks {
            debug!(
                "Adding turn permission for {} using TURN allocation {} {}",
                pair.remote.address, pair.local.transport_type, pair.local.address
            );
            self.pending_turn_permissions.push_front((
                turn_id,
                pair.local.transport_type,
                pair.remote.address.ip(),
            ));
        }

        let mut thawn_foundations = if self.trickle_ice {
            self.thawn_foundations()
        } else {
            Vec::new()
        };
        for mut check in checks {
            if self.trickle_ice {
                // for the trickle-ICE case, if the foundation does not already have a waiting check,
                // then we use this check as the first waiting check
                // RFC 8838 Section 12 Rule 1, 2, and 3
                if !thawn_foundations
                    .iter()
                    .any(|foundation| check.pair.foundation() == *foundation)
                    && self.check_has_turn_permission(&check)
                {
                    check.set_state(CandidatePairState::Waiting);
                    thawn_foundations.push(check.pair.foundation());
                } else if self.foundation_has_check_state(
                    &check.pair.foundation(),
                    CandidatePairState::Succeeded,
                ) {
                    check.set_state(CandidatePairState::Waiting);
                }
            }
            self.add_check_if_not_duplicate(check);
        }
    }

    fn check_is_equal(check: &ConnCheck, pair: &CandidatePair, nominate: Nominate) -> bool {
        candidate_is_same_connection(&check.pair.local, &pair.local)
            && candidate_is_same_connection(&check.pair.remote, &pair.remote)
            && nominate.eq(&check.nominate)
    }

    #[tracing::instrument(level = "trace", ret, skip(self, pair))]
    fn take_matching_check(
        &mut self,
        pair: &CandidatePair,
        nominate: Nominate,
    ) -> Option<ConnCheck> {
        if let Some(position) = self
            .pairs
            .iter()
            .position(|check| Self::check_is_equal(check, pair, nominate))
        {
            self.pairs.remove(position)
        } else {
            None
        }
    }

    #[tracing::instrument(
        level = "trace",
        skip(self, pair),
        fields(
            ttype = ?pair.local.transport_type,
            local.address = ?pair.local.address,
            remote.address = ?pair.remote.address,
            local.ctype = ?pair.local.candidate_type,
            remote.ctype = ?pair.remote.candidate_type,
            foundation = %pair.foundation(),
        )
    )]
    fn matching_check(&self, pair: &CandidatePair, nominate: Nominate) -> Option<&ConnCheck> {
        let ret = self
            .pairs
            .iter()
            .find(|&check| Self::check_is_equal(check, pair, nominate));
        if let Some(check) = ret {
            trace!("found check {}", check.conncheck_id);
            Some(check)
        } else {
            trace!("could not find check");
            None
        }
    }

    fn add_check_if_not_duplicate(&mut self, check: ConnCheck) -> bool {
        if let Some(idx) = self
            .pairs
            .iter()
            .position(|existing| candidate_pair_is_same_connection(&existing.pair, &check.pair))
        {
            // a nominating check trumps not nominating.  Otherwise, if the peers are delay sync,
            // then the non-nominating trigerred check may override the nomination process for a
            // long time and delay the connection process
            if check.nominate() && !self.pairs[idx].nominate()
                || self.pairs[idx].state() == CandidatePairState::Failed
            {
                let existing = self.pairs.remove(idx).unwrap();
                debug!("removing existing check {:?}", existing);
            } else {
                debug!("not adding duplicate check");
                return false;
            }
        }

        self.add_check(check);
        true
    }

    fn add_check(&mut self, check: ConnCheck) {
        trace!("adding check {}", check.conncheck_id);

        let idx = self
            .pairs
            .binary_search_by(|existing| {
                existing
                    .pair
                    .priority(self.controlling)
                    .cmp(&check.pair.priority(self.controlling))
                    .reverse()
            })
            .unwrap_or_else(|x| x);
        self.pairs.insert(idx, check);
        self.dump_check_state();
    }

    fn set_controlling(&mut self, controlling: bool) {
        self.controlling = controlling;
        // changing the controlling (and therefore priority) requires resorting
        self.sort_pairs();
    }

    fn sort_pairs(&mut self) {
        self.pairs.make_contiguous().sort_by(|a, b| {
            a.pair
                .priority(self.controlling)
                .cmp(&b.pair.priority(self.controlling))
                .reverse()
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, pair),
        fields(
            checklist_id = self.checklist_id,
        )
    )]
    fn add_valid(&mut self, conncheck_id: ConnCheckId, pair: &CandidatePair) {
        if pair.local.transport_type == TransportType::Tcp
            && pair.local.tcp_type == Some(TcpType::Passive)
            && pair.local.address.port() == 9
        {
            warn!("not adding local passive tcp candidate without a valid port");
        }
        trace!(
            ttype = ?pair.local.transport_type,
            local.address = ?pair.local.address,
            remote.address = ?pair.remote.address,
            local.ctype = ?pair.local.candidate_type,
            remote.ctype = ?pair.remote.candidate_type,
            foundation = %pair.foundation(),
            "adding valid {conncheck_id}"
        );
        self.valid.push(conncheck_id);
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn remove_valid(&mut self, pair: &CandidatePair) {
        let valid_to_remove = self
            .valid
            .iter()
            .filter(|&check_id| {
                let Some(check) = self.check_by_id(*check_id) else {
                    return true;
                };
                candidate_pair_is_same_connection(&check.pair, pair)
            })
            .cloned()
            .collect::<Vec<_>>();
        self.valid
            .retain(|check_id| !valid_to_remove.contains(check_id));
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(checklist.id = self.checklist_id)
    )]
    fn check_for_failure(&mut self) {
        if self.state == CheckListState::Completed {
            return;
        }
        if !self.trickle_ice || (self.local_end_of_candidates && self.remote_end_of_candidates) {
            debug!("all candidates have arrived");
            let mut any_not_failed = false;
            for (component_id, state) in self.component_ids.iter_mut() {
                if self.pairs.iter().any(|check| {
                    check.pair.local.component_id == *component_id
                        && check.state() != CandidatePairState::Failed
                }) {
                    any_not_failed = true;
                    trace!("component {component_id} has any non-failed check");
                } else if *state != ComponentConnectionState::Failed {
                    *state = ComponentConnectionState::Failed;
                    self.events.push_front(ConnCheckEvent::ComponentState(
                        *component_id,
                        ComponentConnectionState::Failed,
                    ));
                }
            }
            if !any_not_failed {
                self.set_state(CheckListState::Failed);
            }
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, pair),
        fields(component.id = pair.local.component_id)
    )]
    fn nominated_pair(&mut self, pair: &CandidatePair) {
        if self.state != CheckListState::Running {
            warn!(
                "cannot nominate a pair with checklist in state {:?}",
                self.state
            );
            return;
        }
        self.dump_check_state();
        if let Some(idx) = self.valid.iter().position(|&check_id| {
            self.check_by_id(check_id).map_or(false, |check| {
                check.nominate && candidate_pair_is_same_connection(&check.pair, pair)
            })
        }) {
            info!(
                ttype = ?pair.local.transport_type,
                local.address = ?pair.local.address,
                remote.address = ?pair.remote.address,
                local.ctype = ?pair.local.candidate_type,
                remote.ctype = ?pair.remote.candidate_type,
                foundation = %pair.foundation(),
                "nominated"
            );
            self.nominated.push(self.valid.remove(idx));
            let component_id = self.component_ids.iter().find_map(|(id, _state)| {
                if *id == pair.local.component_id {
                    Some(*id)
                } else {
                    None
                }
            });
            // o Once a candidate pair for a component of a data stream has been
            //   nominated, and the state of the checklist associated with the data
            //   stream is Running, the ICE agent MUST remove all candidate pairs
            //   for the same component from the checklist and from the triggered-
            //   check queue.  If the state of a pair is In-Progress, the agent
            //   cancels the In-Progress transaction.  Cancellation means that the
            //   agent will not retransmit the Binding requests associated with the
            //   connectivity-check transaction, will not treat the lack of
            //   response to be a failure, but will wait the duration of the
            //   transaction timeout for a response.
            let triggered_to_remove = self
                .triggered
                .iter()
                .filter(|&check_id| {
                    let Some(check) = self.check_by_id(*check_id) else {
                        return true;
                    };
                    check.pair.local.component_id == pair.local.component_id
                })
                .cloned()
                .collect::<Vec<_>>();
            self.triggered
                .retain(|check_id| !triggered_to_remove.contains(check_id));
            let nominated_ids = self.nominated.clone();
            self.pairs.retain(|check| {
                if nominated_ids.contains(&check.conncheck_id) {
                    true
                } else {
                    check.pair.local.component_id != pair.local.component_id
                }
            });
            // XXX: do we also need to clear self.valid?
            // o Once candidate pairs for each component of a data stream have been
            //   nominated, and the state of the checklist associated with the data
            //   stream is Running, the ICE agent sets the state of the checklist
            //   to Completed.
            let all_nominated = self.component_ids.iter().all(|(component_id, _state)| {
                self.nominated
                    .iter()
                    .filter_map(|&check_id| self.check_by_id(check_id))
                    .any(|check| check.pair.local.component_id == *component_id)
            });
            if all_nominated {
                // ... Once an ICE agent sets the
                // state of the checklist to Completed (when there is a nominated pair
                // for each component of the data stream), that pair becomes the
                // selected pair for that agent and is used for sending and receiving
                // data for that component of the data stream.
                info!(
                    "all {} component/s nominated, setting selected pair/s",
                    self.component_ids.len()
                );
                self.nominated.clone().iter().fold(
                    Vec::new(),
                    |mut component_ids_selected, &check_id| {
                        let Some(check) = self.check_by_id(check_id) else {
                            return component_ids_selected;
                        };
                        let check_component_id = check.pair.local.component_id;
                        // Only nominate one valid candidatePair
                        if component_ids_selected.contains(&check_component_id) {
                            return component_ids_selected;
                        }
                        if let Some(component_id) = component_id {
                            let agent_id = check.agent_id().unwrap();
                            let turn = if check.pair.local.candidate_type == CandidateType::Relayed
                            {
                                self.turn_client_by_allocated_address(
                                    check.pair.local.transport_type,
                                    check.pair.local.address,
                                )
                                .map(|(_turn_id, client)| {
                                    SelectedTurn {
                                        transport: client.transport(),
                                        local_addr: client.local_addr(),
                                        remote_addr: client.remote_addr(),
                                    }
                                })
                            } else {
                                None
                            };
                            self.events.push_front(ConnCheckEvent::SelectedPair(
                                component_id,
                                Box::new(SelectedPair::new(pair.clone(), agent_id, turn)),
                            ));
                            debug!("trying to signal component {:?}", component_id);
                            self.events.push_front(ConnCheckEvent::ComponentState(
                                component_id,
                                ComponentConnectionState::Connected,
                            ));
                        }
                        component_ids_selected.push(check_component_id);
                        component_ids_selected
                    },
                );
                self.set_state(CheckListState::Completed);
            }
        } else {
            warn!("unknown nomination for pair {pair:?}");
        }
    }

    fn try_nominate(&mut self) {
        let retriggered: Vec<_> = self
            .component_ids
            .iter()
            .map(|(component_id, _state)| {
                let nominated = self.pairs.iter().find(|check| check.nominate());
                nominated.or({
                    let mut valid: Vec<_> = self
                        .valid
                        .iter()
                        .filter_map(|&check_id| self.check_by_id(check_id))
                        .filter(|check| {
                            check.pair.local.component_id == *component_id
                                && (check.pair.local.transport_type != TransportType::Tcp
                                    || check.pair.local.address.port() != 9)
                        })
                        .collect();
                    valid.sort_by(|check1, check2| {
                        check1
                            .pair
                            .priority(true /* if we are nominating, we are controlling */)
                            .cmp(&check2.pair.priority(true))
                    });
                    // FIXME: Nominate when there are two valid candidates
                    // what if there is only ever one valid?
                    if !valid.is_empty() {
                        Some(valid[0])
                    } else {
                        None
                    }
                })
            })
            .collect();
        trace!("retriggered {:?}", retriggered);
        // need to wait until all component have a valid pair before we send nominations
        if retriggered.iter().all(|pair| pair.is_some()) {
            self.dump_check_state();
            info!("all components have successful connchecks");
            let new_checks = retriggered
                .iter()
                .filter_map(|check| {
                    let check = check.as_ref().unwrap(); // checked earlier
                    if check.nominate() {
                        trace!(
                            "already have nominate check for component {}",
                            check.pair.local.component_id
                        );
                        None
                    } else {
                        let agent_id = check.agent_id().unwrap();
                        let mut check = ConnCheck::new(
                            self.checklist_id,
                            check.pair.clone(),
                            agent_id,
                            true,
                            self.controlling,
                            self.remote_credentials.clone(),
                        );
                        check.set_state(CandidatePairState::Waiting);
                        debug!("attempting nomination with check {}", check.conncheck_id);
                        Some(check)
                    }
                })
                .collect::<Vec<_>>();
            for check in new_checks {
                self.add_triggered(&check);
                self.add_check(check);
            }
        }
    }

    fn dump_check_state(&self) {
        let mut s = alloc::format!("checklist {}", self.checklist_id);
        for pair in self.pairs.iter() {
            use core::fmt::Write as _;
            let _ = write!(&mut s,
                "\nID:{id} foundation:{foundation} state:{state} nom:{nominate} con:{controlling} priority:{local_pri},{remote_pri} trans:{transport} local:{local_cand_type} {local_addr} remote:{remote_cand_type} {remote_addr}",
                id = format_args!("{:<3}", pair.conncheck_id),
                foundation = format_args!("{:10}", pair.pair.foundation()),
                state = format_args!("{:10}", pair.state()),
                nominate = format_args!("{:5}", pair.nominate()),
                controlling = format_args!("{:5}", pair.controlling),
                local_pri = format_args!("{:10}", pair.pair.local.priority),
                remote_pri = format_args!("{:10}", pair.pair.remote.priority),
                transport = format_args!("{:4}", pair.pair.local.transport_type),
                local_cand_type = format_args!("{:5}", pair.pair.local.candidate_type),
                local_addr = format_args!("{:32}", pair.pair.local.address),
                remote_cand_type = format_args!("{:5}", pair.pair.remote.candidate_type),
                remote_addr = format_args!("{:32}", pair.pair.remote.address)
            );
        }
        debug!("{}", s);
    }

    fn check_response_failure(&mut self, conncheck_id: ConnCheckId) {
        let conncheck = self.mut_check_by_id(conncheck_id).unwrap();
        warn!("conncheck failure for id {conncheck_id}");
        conncheck.set_state(CandidatePairState::Failed);
        let pair = conncheck.pair.clone();
        if conncheck.nominate() {
            self.set_state(CheckListState::Failed);
        }
        self.remove_valid(&pair);
        if self.local_end_of_candidates && self.remote_end_of_candidates {
            self.check_for_failure();
        }
    }

    fn mut_check_from_stun_response(
        &mut self,
        transaction: TransactionId,
        _from: SocketAddr,
    ) -> Option<&mut ConnCheck> {
        self.pairs.iter_mut().find_map(|check| {
            check
                .stun_request
                .filter(|&request| request == transaction)
                .map(|_request| check)
        })
    }

    fn find_local_candidate(
        &self,
        transport: TransportType,
        addr: SocketAddr,
    ) -> Option<Candidate> {
        let f = |candidate: &Candidate| -> bool {
            candidate.transport_type == transport
                && candidate_agent_local_address(candidate) == addr
        };
        self.local_candidates
            .iter()
            .find(|cand| f(&cand.candidate))
            .map(|c| c.candidate.clone())
            .or_else(|| {
                if transport == TransportType::Tcp {
                    self.pairs
                        .iter()
                        .find(|&check| f(&check.pair.local))
                        .map(|c| c.pair.local.clone())
                } else {
                    None
                }
            })
    }

    fn check_cancel(&mut self, check_id: ConnCheckId) {
        let Some(check) = self.mut_check_by_id(check_id) else {
            return;
        };
        let Some(agent_id) = check.agent_id() else {
            return;
        };
        let Some(transaction_id) = check.stun_request else {
            return;
        };
        debug!(conncheck.id = *check_id, "cancelling conncheck");
        check.set_state(CandidatePairState::Failed);
        let Some(agent) = self.mut_agent_by_id(agent_id) else {
            return;
        };
        let Some(mut request) = agent.mut_request_transaction(transaction_id) else {
            return;
        };
        request.cancel();
    }

    fn check_cancel_retransmissions(&mut self, check_id: ConnCheckId) {
        let Some(check) = self.mut_check_by_id(check_id) else {
            return;
        };
        let Some(agent_id) = check.agent_id() else {
            return;
        };
        let Some(transaction_id) = check.stun_request else {
            return;
        };
        debug!(
            conncheck.id = *check_id,
            "cancelling conncheck retransmissions"
        );
        let Some(agent) = self.mut_agent_by_id(agent_id) else {
            return;
        };
        let Some(mut request) = agent.mut_request_transaction(transaction_id) else {
            return;
        };
        request.cancel_retransmissions();
    }

    fn prune_checks_with<F: FnMut(&ConnCheck) -> bool>(
        &mut self,
        mut precondition: F,
    ) -> Vec<ConnCheck> {
        let mut i = 0;
        let mut ret = Vec::new();
        while let Some(check) = self.pairs.get(i) {
            if precondition(check) {
                ret.push(self.pairs.remove(i).unwrap());
            } else {
                i += 1;
            }
        }
        ret
    }

    fn close(&mut self) {
        self.state = CheckListState::Failed;
        self.component_ids.clear();
        self.local_candidates.clear();
        self.remote_candidates.clear();
        self.triggered.clear();
        self.pairs.clear();
        self.valid.clear();
        self.nominated.clear();
        self.pending_turn_permissions.clear();
        self.agents.clear();
    }
}

/// A builder for a [`ConnCheckListSet`]
pub struct ConnCheckListSetBuilder {
    tie_breaker: u64,
    controlling: bool,
    trickle_ice: bool,
}

impl ConnCheckListSetBuilder {
    fn new(tie_breaker: u64, controlling: bool) -> Self {
        Self {
            tie_breaker,
            controlling,
            trickle_ice: false,
        }
    }

    /// Whether ICE candidate will be trickled
    pub fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
        self
    }

    /// Build the [`ConnCheckListSet`]
    pub fn build(self) -> ConnCheckListSet {
        ConnCheckListSet {
            checklists: Default::default(),
            tie_breaker: self.tie_breaker,
            controlling: self.controlling,
            trickle_ice: self.trickle_ice,
            checklist_i: 0,
            last_send_time: None,
            pending_messages: Default::default(),
            pending_transmits: Default::default(),
            pending_remove_sockets: Default::default(),
            completed: false,
            closed: false,
        }
    }
}

/// A set of [`ConnCheckList`]s within an ICE Agent.
#[derive(Debug)]
pub struct ConnCheckListSet {
    checklists: Vec<ConnCheckList>,
    tie_breaker: u64,
    controlling: bool,
    trickle_ice: bool,
    checklist_i: usize,
    last_send_time: Option<Instant>,
    pending_messages: VecDeque<CheckListSetPendingMessage>,
    pending_transmits: VecDeque<CheckListSetTransmit>,
    pending_remove_sockets: VecDeque<CheckListSetSocket>,
    completed: bool,
    closed: bool,
}

impl ConnCheckListSet {
    // TODO: add/remove a stream after start
    // TODO: cancel when agent is stopped
    /// Create a [`ConnCheckListSetBuilder`]
    pub fn builder(tie_breaker: u64, controlling: bool) -> ConnCheckListSetBuilder {
        ConnCheckListSetBuilder::new(tie_breaker, controlling)
    }

    /// Construct a new [`ConnCheckList`] and return its ID.
    pub fn new_list(&mut self) -> usize {
        let checklist_id = CONN_CHECK_LIST_COUNT.fetch_add(1, Ordering::SeqCst);
        let ret = ConnCheckList::new(checklist_id, self.controlling(), self.trickle_ice);
        self.checklists.push(ret);
        checklist_id
    }

    /// Get a mutable reference to a [`ConnCheckList`] by ID
    pub fn mut_list(&mut self, id: usize) -> Option<&mut ConnCheckList> {
        self.checklists.iter_mut().find(|cl| cl.checklist_id == id)
    }

    /// Get a reference to a [`ConnCheckList`] by ID
    pub fn list(&self, id: usize) -> Option<&ConnCheckList> {
        self.checklists.iter().find(|cl| cl.checklist_id == id)
    }

    /// Whether the set is in the controlling mode.  This may change during the ICE negotiation
    /// process.
    pub fn controlling(&self) -> bool {
        self.controlling
    }

    fn handle_stun<T: AsRef<[u8]>>(
        &mut self,
        checklist_i: usize,
        msg: Message<'_>,
        transmit: &Transmit<T>,
        agent_id: StunAgentId,
        turn_id: Option<(StunAgentId, SocketAddr)>,
    ) -> bool {
        debug!("received STUN message {msg}");
        let Some(agent) = self.checklists[checklist_i].mut_agent_by_id(agent_id) else {
            return false;
        };
        match agent.handle_stun(msg, transmit.from) {
            HandleStunReply::Drop(_) => false,
            HandleStunReply::ValidatedStunResponse(response) => {
                let Some(remote_credentials) = agent.remote_credentials() else {
                    return false;
                };
                self.handle_stun_response(checklist_i, response, transmit.from, remote_credentials);
                true
            }
            HandleStunReply::UnvalidatedStunResponse(_msg) => false,
            HandleStunReply::IncomingStun(request) => {
                if !request.has_method(BINDING) {
                    return false;
                }
                let Some(local_credentials) = agent.local_credentials() else {
                    return false;
                };
                let Some(local_cand) = self.checklists[checklist_i]
                    .find_local_candidate(transmit.transport, transmit.to)
                else {
                    warn!("Could not find local candidate for incoming data");
                    return false;
                };

                let checklist_id = self.checklists[checklist_i].checklist_id;
                let response = self.handle_binding_request(
                    checklist_i,
                    &local_cand,
                    agent_id,
                    &request,
                    transmit.from,
                    local_credentials,
                );
                self.pending_messages.push_back(CheckListSetPendingMessage {
                    checklist_id,
                    agent_id,
                    is_request: false,
                    msg: response.finish(),
                    to: transmit.from,
                    turn_id,
                });
                true
            }
        }
    }

    #[tracing::instrument(
        name = "incoming_data_or_stun",
        level = "trace",
        skip(self, checklist_i, transmit)
        fields(
            transport = %transmit.transport,
            from = %transmit.from,
            to = %transmit.to,
        )
    )]
    fn incoming_data_or_stun<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        checklist_i: usize,
        component_id: usize,
        transmit: Transmit<T>,
        turn_client_id: Option<(StunAgentId, SocketAddr)>,
    ) -> HandleRecvReply<T> {
        if !self.checklists[checklist_i].pending_recv.is_empty() {
            panic!("Previous data has not been complete handled yet");
        }
        let (agent_id, checklist_i) = self.checklists[checklist_i]
            .find_agent_for_5tuple(transmit.transport, transmit.to, transmit.from)
            .map(|agent| (agent.0, checklist_i))
            .unwrap_or_else(|| {
                // else look at all checklists
                self.checklists
                    .iter()
                    .find_map(|checklist| {
                        checklist
                            .find_agent_for_5tuple(transmit.transport, transmit.to, transmit.from)
                            .map(|agent| (agent.0, checklist.checklist_id))
                    })
                    .unwrap_or_else(|| {
                        let mut agent = StunAgent::builder(transmit.transport, transmit.to)
                            .remote_addr(transmit.from)
                            .build();
                        agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                            self.checklists[checklist_i]
                                .local_credentials
                                .clone()
                                .into(),
                        ));
                        agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                            self.checklists[checklist_i]
                                .remote_credentials
                                .clone()
                                .into(),
                        ));
                        let (agent_id, _agent_idx) = self.checklists[checklist_i].add_agent(agent);
                        (agent_id, checklist_i)
                    })
            });

        match transmit.transport {
            TransportType::Udp => match Message::from_bytes(transmit.data.as_ref()) {
                Ok(msg) => {
                    if self.handle_stun(checklist_i, msg, &transmit, agent_id, turn_client_id) {
                        return HandleRecvReply {
                            handled: true,
                            have_more_data: false,
                            data: None,
                        };
                    }
                }
                Err(_) => {
                    if let Some(agent) = self.checklists[checklist_i].agent_by_id(agent_id) {
                        if agent.is_validated_peer(transmit.from) {
                            return HandleRecvReply {
                                handled: false,
                                have_more_data: false,
                                data: Some(DataAndRange {
                                    range: 0..transmit.data.as_ref().len(),
                                    data: transmit.data,
                                }),
                            };
                        }
                    }
                }
            },
            TransportType::Tcp => {
                // TODO: can potentially return a subset of the original data if the tcp buffer
                // is empty and the incoming data contains at least one message.
                let mut tcp_buffer = self.checklists[checklist_i]
                    .tcp_buffers
                    .entry((transmit.to, transmit.from))
                    .or_default();
                tcp_buffer.push_data(transmit.data.as_ref());

                let mut handled = false;
                let mut have_more_data = false;
                loop {
                    let Some(data) = tcp_buffer.pull_data() else {
                        break;
                    };
                    match Message::from_bytes(&data) {
                        Ok(msg) => {
                            if self.handle_stun(
                                checklist_i,
                                msg,
                                &transmit,
                                agent_id,
                                turn_client_id,
                            ) {
                                handled = true;
                            }
                        }
                        Err(_) => {
                            let checklist = &mut self.checklists[checklist_i];
                            if let Some(agent) = checklist.agent_by_id(agent_id) {
                                if agent.is_validated_peer(transmit.from) {
                                    have_more_data = true;
                                    checklist
                                        .pending_recv
                                        .push_back(PendingRecv { component_id, data });
                                }
                            }
                        }
                    }
                    tcp_buffer = self.checklists[checklist_i]
                        .tcp_buffers
                        .get_mut(&(transmit.to, transmit.from))
                        .unwrap();
                }
                return HandleRecvReply {
                    handled,
                    have_more_data,
                    data: None,
                };
            }
        }
        HandleRecvReply {
            handled: false,
            have_more_data: false,
            data: None,
        }
    }

    /// Provide received data to handle.  The returned values indicate what to do with the data.
    ///
    /// If [`HandleRecvReply::Handled`] is returned, then [`ConnCheckListSet::poll`] should be
    /// called at the earliest opportunity.
    #[tracing::instrument(
        name = "conncheck_incoming_data",
        level = "trace",
        ret(Display),
        skip(self, transmit)
        fields(
            transport = %transmit.transport,
            from = %transmit.from,
            to = %transmit.to,
            len = transmit.data.as_ref().len(),
        )
    )]
    pub fn incoming_data<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        checklist_id: usize,
        component_id: usize,
        mut transmit: Transmit<T>,
        now: Instant,
    ) -> HandleRecvReply<T> {
        let Some(mut checklist_i) = self
            .checklists
            .iter()
            .position(|cl| cl.checklist_id == checklist_id)
        else {
            warn!("no such checklist with id {checklist_id}");
            return HandleRecvReply::default();
        };

        // first de-TURN any incoming data
        let mut turn_client_id = None;
        if let Some((turn_id, turn_server_addr, checklist_i2)) = self.checklists[checklist_i]
            .find_turn_client_for_5tuple(transmit.transport, transmit.to, transmit.from)
            .map(|(id, client)| (id, client.remote_addr(), checklist_i))
            .or_else(|| {
                self.checklists.iter().find_map(|checklist| {
                    checklist
                        .find_turn_client_for_5tuple(transmit.transport, transmit.to, transmit.from)
                        .map(|(id, client)| (id, client.remote_addr(), checklist_i))
                })
            })
        {
            let client = self.checklists[checklist_i]
                .mut_turn_client_by_id(turn_id)
                .unwrap();
            match client.recv(transmit, now) {
                TurnRecvRet::Handled => {
                    // TODO: maybe handle turn events here?
                    trace!("TURN client handled the incoming data");
                    return HandleRecvReply {
                        handled: true,
                        have_more_data: false,
                        data: None,
                    };
                }
                TurnRecvRet::Ignored(ignored) => {
                    transmit = ignored;
                }
                TurnRecvRet::PeerData(peer) => {
                    let turn_client_transport = client.transport();
                    turn_client_id = Some((turn_id, turn_server_addr));
                    checklist_i = checklist_i2;
                    // FIXME: dual allocation TURN
                    let transmit = Transmit::new(
                        peer.data(),
                        peer.transport,
                        peer.peer,
                        client.relayed_addresses().next().unwrap().1,
                    );
                    let ret = self.incoming_data_or_stun(
                        checklist_i,
                        component_id,
                        transmit,
                        turn_client_id,
                    );
                    if let Some(data) = ret.data.as_ref() {
                        let checklist = &mut self.checklists[checklist_i];
                        checklist.pending_recv.push_back(PendingRecv {
                            component_id,
                            data: data.as_ref().to_vec(),
                        });
                    }
                    if turn_client_transport != TransportType::Udp {
                        loop {
                            let client = self.checklists[checklist_i]
                                .mut_turn_client_by_id(turn_id)
                                .unwrap();
                            let Some(peer) = client.poll_recv(now) else {
                                break;
                            };
                            let transmit = Transmit::new(
                                peer.data(),
                                peer.transport,
                                peer.peer,
                                client.relayed_addresses().next().unwrap().1,
                            );
                            let ret = self.incoming_data_or_stun(
                                checklist_i,
                                component_id,
                                transmit,
                                turn_client_id,
                            );
                            if let Some(data) = ret.data.as_ref() {
                                let checklist = &mut self.checklists[checklist_i];
                                checklist.pending_recv.push_back(PendingRecv {
                                    component_id,
                                    data: data.as_ref().to_vec(),
                                });
                            }
                        }
                    }
                    return HandleRecvReply {
                        handled: ret.handled,
                        have_more_data: true,
                        data: None,
                    };
                }
                TurnRecvRet::PeerIcmp {
                    transport,
                    peer,
                    icmp_type,
                    icmp_code,
                    icmp_data: _,
                } => {
                    debug!("conncheck received ICMP(type:{icmp_type:x}, code:{icmp_code:x}) over TURN from {transport}:{peer}");
                    return HandleRecvReply {
                        handled: true,
                        have_more_data: false,
                        data: None,
                    };
                }
            }
        }

        self.incoming_data_or_stun(checklist_i, component_id, transmit, turn_client_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_binding_request(
        &mut self,
        checklist_i: usize,
        local: &Candidate,
        agent_id: StunAgentId,
        msg: &Message,
        from: SocketAddr,
        local_credentials: MessageIntegrityCredentials,
    ) -> MessageWriteVec {
        let checklist = &mut self.checklists[checklist_i];
        trace!("have request {}", msg);

        if let Some(error_msg) = Message::check_attribute_types(
            msg,
            &[
                Username::TYPE,
                Fingerprint::TYPE,
                MessageIntegrity::TYPE,
                IceControlled::TYPE,
                IceControlling::TYPE,
                Priority::TYPE,
                UseCandidate::TYPE,
            ],
            &[
                Username::TYPE,
                Fingerprint::TYPE,
                MessageIntegrity::TYPE,
                Priority::TYPE,
            ],
            MessageWriteVec::new(),
        ) {
            // failure -> send error response
            return error_msg;
        }
        if msg.validate_integrity(&local_credentials).is_err() {
            let code = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            response.add_attribute(&code).unwrap();
            return response;
        }
        let peer_nominating = if let Some(use_candidate_raw) = msg.raw_attribute(UseCandidate::TYPE)
        {
            if UseCandidate::from_raw(use_candidate_raw).is_ok() {
                true
            } else {
                return Message::bad_request(msg, MessageWriteVec::new());
            }
        } else {
            false
        };

        let priority = match msg.attribute::<Priority>() {
            Ok(p) => p.priority(),
            Err(_) => {
                return Message::bad_request(msg, MessageWriteVec::new());
            }
        };

        let ice_controlling = msg.attribute::<IceControlling>();
        let ice_controlled = msg.attribute::<IceControlled>();

        // validate username
        if let Ok(username) = msg.attribute::<Username>() {
            if !validate_username(username, &checklist.local_credentials) {
                warn!("binding request failed username validation -> UNAUTHORIZED");
                let mut response = Message::builder_error(msg, MessageWriteVec::new());
                let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
                response.add_attribute(&error).unwrap();
                return response;
            }
        } else {
            // existence is checked above so can only fail when the username is invalid
            return Message::bad_request(msg, MessageWriteVec::new());
        }

        // Deal with role conflicts
        // RFC 8445 7.3.1.1.  Detecting and Repairing Role Conflicts
        trace!("checking for role conflicts");
        if let Ok(ice_controlling) = ice_controlling {
            //  o  If the agent is in the controlling role, and the ICE-CONTROLLING
            //     attribute is present in the request:
            if self.controlling {
                if self.tie_breaker >= ice_controlling.tie_breaker() {
                    debug!("role conflict detected (controlling=true), returning ROLE_CONFLICT");
                    // *  If the agent's tiebreaker value is larger than or equal to the
                    //    contents of the ICE-CONTROLLING attribute, the agent generates
                    //    a Binding error response and includes an ERROR-CODE attribute
                    //    with a value of 487 (Role Conflict) but retains its role.
                    let mut response = Message::builder_error(msg, MessageWriteVec::new());
                    let error = ErrorCode::builder(ErrorCode::ROLE_CONFLICT)
                        .build()
                        .unwrap();
                    response.add_attribute(&error).unwrap();
                    return response_add_credentials(response, local_credentials).unwrap();
                } else {
                    debug!("role conflict detected, updating controlling state to false");
                    // *  If the agent's tiebreaker value is less than the contents of
                    //    the ICE-CONTROLLING attribute, the agent switches to the
                    //    controlled role.
                    self.controlling = false;
                    for l in self.checklists.iter_mut() {
                        l.set_controlling(false);
                    }
                }
            }
        }
        if let Ok(ice_controlled) = ice_controlled {
            // o  If the agent is in the controlled role, and the ICE-CONTROLLED
            //    attribute is present in the request:
            if !self.controlling {
                if self.tie_breaker >= ice_controlled.tie_breaker() {
                    debug!("role conflict detected, updating controlling state to true");
                    // *  If the agent's tiebreaker value is larger than or equal to the
                    //    contents of the ICE-CONTROLLED attribute, the agent switches to
                    //    the controlling role.
                    self.controlling = true;
                    for l in self.checklists.iter_mut() {
                        l.set_controlling(true);
                    }
                } else {
                    debug!("role conflict detected (controlling=false), returning ROLE_CONFLICT");
                    // *  If the agent's tiebreaker value is less than the contents of
                    //    the ICE-CONTROLLED attribute, the agent generates a Binding
                    //    error response and includes an ERROR-CODE attribute with a
                    //    value of 487 (Role Conflict) but retains its role.
                    let mut response = Message::builder_error(msg, MessageWriteVec::new());
                    let error = ErrorCode::builder(ErrorCode::ROLE_CONFLICT)
                        .build()
                        .unwrap();
                    response.add_attribute(&error).unwrap();
                    return response_add_credentials(response, local_credentials).unwrap();
                }
            }
        }
        trace!("checked for role conflicts");
        let checklist = &mut self.checklists[checklist_i];
        let remote = checklist
            .find_remote_candidate(local.component_id, local.transport_type, from)
            .unwrap_or_else(|| {
                debug!("no existing remote candidate for {from}");
                // If the source transport address of the request does not match any
                // existing remote candidates, it represents a new peer-reflexive remote
                // candidate.  This candidate is constructed as follows:
                //
                //   o  The priority is the value of the PRIORITY attribute in the Binding
                //      request.
                //   o  The type is peer reflexive.
                //   o  The component ID is the component ID of the local candidate to
                //      which the request was sent.
                //   o  The foundation is an arbitrary value, different from the
                //      foundations of all other remote candidates.  If any subsequent
                //      candidate exchanges contain this peer-reflexive candidate, it will
                //      signal the actual foundation for the candidate
                let mut builder = Candidate::builder(
                    local.component_id,
                    CandidateType::PeerReflexive,
                    local.transport_type,
                    /* FIXME */ "rflx",
                    from,
                )
                .priority(priority);
                if local.transport_type == TransportType::Tcp {
                    builder = builder.tcp_type(pair_tcp_type(local.tcp_type.unwrap()))
                }
                let cand = builder.build();
                debug!("new reflexive remote {:?}", cand);
                checklist.add_remote_candidate(cand.clone());
                cand
            });
        trace!("remote candidate {remote:?}");
        // RFC 8445 Section 7.3.1.4. Triggered Checks
        let pair = CandidatePair::new(local.clone(), remote);
        if let Some(mut check) = checklist.take_matching_check(&pair, Nominate::DontCare) {
            // When the pair is already on the checklist:
            trace!("found existing {:?} check {:?}", check.state(), check);
            match check.state() {
                // If the state of that pair is Succeeded, nothing further is
                // done.
                CandidatePairState::Succeeded => {
                    if peer_nominating && !check.nominate() {
                        debug!("existing pair succeeded -> nominate");
                        let pair = check.pair.clone();
                        let agent_id = check.agent_id().unwrap();
                        let mut new_check = ConnCheck::new(
                            checklist.checklist_id,
                            pair.clone(),
                            agent_id,
                            true,
                            self.controlling,
                            checklist.remote_credentials.clone(),
                        );
                        checklist.add_check(check);
                        new_check.set_state(CandidatePairState::Waiting);
                        checklist.add_valid(new_check.conncheck_id, &pair);
                        checklist.add_check(new_check);
                        checklist.nominated_pair(&pair);
                    } else {
                        checklist.add_check(check);
                    }
                }
                // If the state of that pair is In-Progress, the agent cancels the
                // In-Progress transaction.  Cancellation means that the agent
                // will not retransmit the Binding requests associated with the
                // connectivity-check transaction, will not treat the lack of
                // response to be a failure, but will wait the duration of the
                // transaction timeout for a response.  In addition, the agent
                // MUST enqueue the pair in the triggered checklist associated
                // with the checklist, and set the state of the pair to Waiting,
                // in order to trigger a new connectivity check of the pair.
                // Creating a new connectivity check enables validating
                // In-Progress pairs as soon as possible, without having to wait
                // for retransmissions of the Binding requests associated with the
                // original connectivity-check transaction.
                CandidatePairState::InProgress => {
                    let old_check_id = check.conncheck_id;
                    let pair = check.pair.clone();
                    // TODO: ignore response timeouts

                    let agent_id = check.agent_id().unwrap();
                    let mut new_check = ConnCheck::new(
                        checklist.checklist_id,
                        pair,
                        agent_id,
                        peer_nominating,
                        self.controlling,
                        checklist.remote_credentials.clone(),
                    );
                    checklist.check_cancel_retransmissions(old_check_id);
                    checklist.add_check(check);
                    new_check.set_state(CandidatePairState::Waiting);
                    checklist.add_triggered(&new_check);
                    checklist.add_check(new_check);
                }
                // If the state of that pair is Waiting, Frozen, or Failed, the
                // agent MUST enqueue the pair in the triggered checklist
                // associated with the checklist (if not already present), and set
                // the state of the pair to Waiting, in order to trigger a new
                // connectivity check of the pair.  Note that a state change of
                // the pair from Failed to Waiting might also trigger a state
                // change of the associated checklist.
                CandidatePairState::Waiting
                | CandidatePairState::Frozen
                | CandidatePairState::Failed => {
                    let mut old_check_id = None;
                    if peer_nominating && !check.nominate() {
                        old_check_id = Some(check.conncheck_id);
                        check = ConnCheck::new(
                            checklist.checklist_id,
                            check.pair.clone(),
                            agent_id,
                            peer_nominating,
                            self.controlling,
                            checklist.remote_credentials.clone(),
                        );
                    }
                    check.set_state(CandidatePairState::Waiting);
                    if let Some(old_check_id) = old_check_id {
                        checklist.check_cancel(old_check_id);
                    }
                    checklist.add_triggered(&check);
                    checklist.add_check(check);
                }
            }
        } else {
            debug!("creating new check for pair {:?}", pair);
            let mut check = ConnCheck::new(
                checklist.checklist_id,
                pair,
                agent_id,
                peer_nominating,
                self.controlling,
                checklist.remote_credentials.clone(),
            );
            check.set_state(CandidatePairState::Waiting);
            checklist.add_triggered(&check);
            checklist.add_check(check);
        }

        binding_success_response(msg, from, local_credentials)
    }

    fn check_success(
        &mut self,
        checklist_i: usize,
        conncheck_id: ConnCheckId,
        addr: SocketAddr,
        controlling: bool,
    ) {
        let checklist = &mut self.checklists[checklist_i];
        let checklist_id = checklist.checklist_id;
        checklist.check_cancel_retransmissions(conncheck_id);
        let conncheck = checklist.mut_check_by_id(conncheck_id).unwrap();
        let conncheck_id = conncheck.conncheck_id;
        let nominate = conncheck.nominate();
        info!(
            component.id = conncheck.pair.local.component_id,
            nominate = conncheck.nominate,
            ttype = ?conncheck.pair.local.transport_type,
            local.address = ?conncheck.pair.local.address,
            remote.address = ?conncheck.pair.remote.address,
            local.ctype = ?conncheck.pair.local.candidate_type,
            remote.ctype = ?conncheck.pair.remote.candidate_type,
            foundation = %conncheck.pair.foundation(),
            xor_mapped_address = ?addr,
            "succeeded in finding a connection"
        );
        conncheck.set_state(CandidatePairState::Succeeded);
        let pair = conncheck.pair.clone();
        let ok_pair = pair_construct_valid(&pair, addr);
        let agent_id = conncheck.agent_id().unwrap();
        let mut ok_check = ConnCheck::new(
            checklist_id,
            ok_pair.clone(),
            agent_id,
            false,
            self.controlling,
            checklist.remote_credentials.clone(),
        );

        if checklist.state != CheckListState::Running {
            debug!("checklist is not running, ignoring check response");
            return;
        }

        let mut pair_dealt_with = false;
        // 1.
        // If the valid pair equals the pair that generated the check, the
        // pair is added to the valid list associated with the checklist to
        // which the pair belongs; or
        if let Some(check) = checklist.matching_check(&ok_pair, Nominate::DontCare) {
            debug!(existing.id = *check.conncheck_id, "found existing check");
            let checklist = &mut self.checklists[checklist_i];
            checklist.add_valid(conncheck_id, &pair);
            if nominate {
                checklist.nominated_pair(&pair);
                return;
            }
            pair_dealt_with = true;
        } else {
            // 2.
            // If the valid pair equals another pair in a checklist, that pair
            // is added to the valid list associated with the checklist of that
            // pair.  The pair that generated the check is not added to a vali
            // list; or
            for checklist in self.checklists.iter_mut() {
                if let Some(check) = checklist.matching_check(&ok_pair, Nominate::DontCare) {
                    debug!(
                        existing.id = *check.conncheck_id,
                        "found existing check in checklist {}", checklist.checklist_id
                    );
                    checklist.add_valid(conncheck_id, &pair);
                    if nominate {
                        checklist.nominated_pair(&pair);
                        return;
                    }
                    pair_dealt_with = true;
                    break;
                }
            }
        }
        let checklist = &mut self.checklists[checklist_i];
        // 3.
        // If the valid pair is not in any checklist, the agent computes the
        // priority for the pair based on the priority of each candidate,
        // using the algorithm in Section 6.1.2.  The priority of the local
        // candidate depends on its type.  Unless the type is peer
        // reflexive, the priority is equal to the priority signaled for
        // that candidate in the candidate exchange.  If the type is peer
        // reflexive, it is equal to the PRIORITY attribute the agent placed
        // in the Binding request that just completed.  The priority of the
        // remote candidate is taken from the candidate information of the
        // peer.  If the candidate does not appear there, then the check has
        // been a triggered check to a new remote candidate.  In that case,
        // the priority is taken as the value of the PRIORITY attribute in
        // the Binding request that triggered the check that just completed.
        // The pair is then added to the valid list.
        if !pair_dealt_with {
            debug!("no existing check");
            // TODO: need to construct correct pair priorities and foundations,
            // just use whatever the conncheck produced for now
            ok_check.set_state(CandidatePairState::Succeeded);
            let ok_id = ok_check.conncheck_id;
            if checklist.add_check_if_not_duplicate(ok_check) {
                checklist.add_valid(ok_id, &ok_pair);
            }
            checklist.add_valid(conncheck_id, &pair);

            if nominate {
                checklist.nominated_pair(&pair);
                return;
            }
        }
        // Try and nominate some pair
        if controlling {
            checklist.try_nominate();
        }
    }

    #[tracing::instrument(
        skip(self, response, remote_credentials),
        fields(
            checklist_id = self.checklists[checklist_i].checklist_id,
        ),
    )]
    fn handle_stun_response(
        &mut self,
        checklist_i: usize,
        response: Message,
        from: SocketAddr,
        remote_credentials: MessageIntegrityCredentials,
    ) {
        let checklist = &mut self.checklists[checklist_i];
        let checklist_id = checklist.checklist_id;
        // find conncheck
        let conncheck = checklist.mut_check_from_stun_response(response.transaction_id(), from);
        let conncheck = match conncheck {
            Some(conncheck) => conncheck,
            None => {
                checklist.dump_check_state();
                warn!("No existing check available, ignoring");
                return;
            }
        };
        let conncheck_id = conncheck.conncheck_id;

        if response.validate_integrity(&remote_credentials).is_err() {
            debug!("Integrity check failed, ignoring");
            return;
        }

        // if response success:
        // if mismatched address -> fail
        if from != conncheck.pair.remote.address {
            warn!(
                "response came from different ip {:?} than candidate {:?}",
                from, conncheck.pair.remote.address
            );
            checklist.check_response_failure(conncheck_id);
            return;
        }

        // if response error -> fail TODO: might be a recoverable error!
        if response.has_class(MessageClass::Error) {
            if let Ok(err) = response.attribute::<ErrorCode>() {
                if err.code() == ErrorCode::ROLE_CONFLICT {
                    info!("Role conflict received {}", response);
                    let new_role = !conncheck.controlling;
                    info!(
                        old_role = self.controlling,
                        new_role, "Role Conflict changing controlling from"
                    );
                    if self.controlling != new_role {
                        let old_pair = conncheck.pair.clone();
                        let old_conncheck_id = conncheck.conncheck_id;
                        self.controlling = new_role;
                        let agent_id = conncheck.agent_id().unwrap();
                        let mut conncheck = ConnCheck::new(
                            checklist_id,
                            conncheck.pair.clone(),
                            agent_id,
                            false,
                            self.controlling,
                            checklist.remote_credentials.clone(),
                        );
                        conncheck.set_state(CandidatePairState::Waiting);
                        checklist.check_cancel(old_conncheck_id);
                        checklist.add_triggered(&conncheck);
                        checklist.add_check(conncheck);
                        self.checklists[checklist_i].remove_valid(&old_pair);
                    }
                    return;
                }
            }
            // FIXME: some failures are recoverable
            warn!("error response {}", response);
            self.checklists[checklist_i].check_response_failure(conncheck_id);
        }

        if let Ok(xor) = response.attribute::<XorMappedAddress>() {
            let xor_addr = xor.addr(response.transaction_id());
            return self.check_success(checklist_i, conncheck_id, xor_addr, self.controlling);
        }

        self.checklists[checklist_i].check_response_failure(conncheck_id);
    }

    fn perform_conncheck(
        &mut self,
        checklist_i: usize,
        conncheck_id: ConnCheckId,
    ) -> Result<Option<CheckListSetSocket>, StunError> {
        let checklist_id = self.checklists[self.checklist_i].checklist_id;
        let checklist = &mut self.checklists[checklist_i];
        let local_credentials = checklist.local_credentials.clone();
        let remote_credentials = checklist.remote_credentials.clone();

        let conncheck = checklist.mut_check_by_id(conncheck_id).unwrap();
        let turn_id = if conncheck.pair.local.candidate_type == CandidateType::Relayed {
            let transport = conncheck.pair.local.transport_type;
            let turn_addr = conncheck.pair.local.address;
            checklist
                .turn_client_by_allocated_address(transport, turn_addr)
                .map(|(id, client)| (id, client.remote_addr()))
        } else {
            None
        };
        let conncheck = checklist.mut_check_by_id(conncheck_id).unwrap();
        let component_id = conncheck.pair.local.component_id;
        for (cid, state) in checklist.component_ids.iter_mut() {
            if *cid == component_id
                && [
                    ComponentConnectionState::New,
                    ComponentConnectionState::Failed,
                ]
                .contains(state)
            {
                *state = ComponentConnectionState::Connecting;
                checklist.events.push_front(ConnCheckEvent::ComponentState(
                    component_id,
                    ComponentConnectionState::Connecting,
                ));
            }
        }
        let conncheck = checklist.mut_check_by_id(conncheck_id).unwrap();

        debug!("starting connectivity check {}", conncheck.conncheck_id);
        if conncheck.stun_request.is_some() {
            panic!("Attempt was made to start an already started check");
        }

        let agent_id = match &conncheck.variant {
            ConnCheckVariant::Tcp(_tcp) => {
                // FIXME: TURN-TCP?
                return Ok(Some(CheckListSetSocket {
                    checklist_id,
                    component_id: conncheck.pair.local.component_id,
                    transport: TransportType::Tcp,
                    local_addr: conncheck.pair.local.base_address,
                    remote_addr: conncheck.pair.remote.address,
                }));
            }
            ConnCheckVariant::Agent(agent_id) => agent_id,
        };

        let stun_request = ConnCheck::generate_stun_request(
            &conncheck.pair,
            conncheck.nominate,
            self.controlling,
            self.tie_breaker,
            local_credentials,
            remote_credentials,
        )
        .unwrap();
        conncheck.stun_request = Some(stun_request.transaction_id());
        conncheck.controlling = self.controlling;
        let remote_addr = conncheck.pair.remote.address;

        self.pending_messages
            .push_front(CheckListSetPendingMessage {
                checklist_id,
                agent_id: *agent_id,
                turn_id,
                is_request: true,
                msg: stun_request.finish(),
                to: remote_addr,
            });
        Ok(None)
    }

    #[tracing::instrument(
        level = "info",
        ret,
        skip(self),
        fields(
             checklist_id = self.checklists[self.checklist_i].checklist_id,
        ),
    )]
    // RFC8445: 6.1.4.2. Performing Connectivity Checks
    fn next_check(&mut self) -> Option<ConnCheckId> {
        let checklist = &mut self.checklists[self.checklist_i];
        {
            if checklist.state != CheckListState::Running {
                // A non-running checklist has no next check
                return None;
            }
            checklist.dump_check_state();
        }

        // 1.  If the triggered-check queue associated with the checklist
        //     contains one or more candidate pairs, the agent removes the top
        //     pair from the queue, performs a connectivity check on that pair,
        //     puts the candidate pair state to In-Progress, and aborts the
        //     subsequent steps.
        if let Some(check) = checklist.next_triggered() {
            trace!("next check was a triggered check {:?}", check);
            Some(check.conncheck_id)
        // 3.  If there are one or more candidate pairs in the Waiting state,
        //     the agent picks the highest-priority candidate pair (if there are
        //     multiple pairs with the same priority, the pair with the lowest
        //     component ID is picked) in the Waiting state, performs a
        //     connectivity check on that pair, puts the candidate pair state to
        //     In-Progress, and aborts the subsequent steps.
        } else if let Some(check) = checklist.next_waiting() {
            trace!("next check was a waiting check {:?}", check);
            Some(check.conncheck_id)
        } else {
            // TODO: cache this locally somewhere
            // TODO: iter()ize this
            // 2.  If there is no candidate pair in the Waiting state, and if there
            //     are one or more pairs in the Frozen state, the agent checks the
            //     foundation associated with each pair in the Frozen state.  For a
            //     given foundation, if there is no pair (in any checklist in the
            //     checklist set) in the Waiting or In-Progress state, the agent
            //     puts the candidate pair state to Waiting and continues with the
            //     next step.
            let mut foundations_not_waiting_in_progress = BTreeSet::new();
            for checklist in self.checklists.iter() {
                for f in checklist.foundations() {
                    if self
                        .checklists
                        .iter()
                        .all(|checklist| checklist.foundation_not_waiting_in_progress(&f))
                    {
                        foundations_not_waiting_in_progress.insert(f);
                    }
                }
            }
            trace!(
                "current foundations not waiting or in progress: {:?}",
                foundations_not_waiting_in_progress
            );

            let mut foundations_check_added = BTreeSet::new();
            for checklist in self.checklists.iter_mut() {
                for check in checklist.pairs.iter_mut() {
                    if check.state() != CandidatePairState::Frozen {
                        continue;
                    }
                    if !foundations_not_waiting_in_progress
                        .iter()
                        .any(|f| f == &check.pair.foundation())
                    {
                        continue;
                    }
                    if foundations_check_added
                        .iter()
                        .any(|f| f == &check.pair.foundation())
                    {
                        continue;
                    }
                    check.set_state(CandidatePairState::Waiting);
                    foundations_check_added.insert(check.pair.foundation());
                }
            }

            let checklist = &mut self.checklists[self.checklist_i];
            if let Some(check) = checklist.next_waiting() {
                trace!("next check was a frozen check {:?}", check);
                check.set_state(CandidatePairState::InProgress);
                Some(check.conncheck_id)
            } else {
                // XXX: may need to return a check from a different checklist
                trace!("no next check for stream");
                None
            }
        }
    }

    /// The minimum amount of time between iterations of a [`ConnCheckListSet`]
    pub const MINIMUM_SET_TICK: Duration = Duration::from_millis(50);

    fn remove_check_resources(&mut self, checklist_i: usize, check: ConnCheck, now: Instant) {
        let ConnCheckVariant::Agent(check_agent_id) = check.variant else {
            return;
        };
        let checklist = &mut self.checklists[checklist_i];
        let checklist_id = checklist.checklist_id;
        if checklist.pairs.iter().any(|pair| {
            if let ConnCheckVariant::Agent(agent_id) = pair.variant {
                agent_id == check_agent_id
            } else {
                false
            }
        }) {
            return;
        }

        let Some(agent) = checklist.agent_by_id(check_agent_id) else {
            return;
        };

        let transport = agent.transport();
        let local_addr = agent.local_addr();
        let remote_addr = agent.remote_addr();
        debug!("found agent {transport}: {local_addr} -> {remote_addr:?} to maybe remove");

        let (transport, local_addr, remote_addr) =
            if check.pair.local.candidate_type == CandidateType::Relayed {
                let Some((turn_id, _turn_client)) =
                    checklist.mut_turn_client_by_allocated_address(transport, local_addr)
                else {
                    return;
                };

                if self.checklists.iter().any(|checklist| {
                    checklist.pairs.iter().any(|pair| {
                        pair.pair.local.candidate_type == CandidateType::Relayed
                            && pair.pair.local.address == check.pair.local.address
                    })
                }) {
                    // TODO: remove permission for remote address here
                    warn!(
                        "should remove {transport} permission from {local_addr} to {}",
                        check.pair.remote.address.ip()
                    );
                    return;
                }
                let checklist = &mut self.checklists[checklist_i];
                let mut turn_client = checklist.remove_turn_client_by_id(turn_id).unwrap();
                let _ = turn_client.delete(now);
                let checklist = &mut self.checklists[checklist_i];
                checklist
                    .pending_delete_turn_clients
                    .push((turn_id, turn_client));
                // socket remove will occur when the delete reply is received, or on timeout
                return;
            } else {
                let checklist = &mut self.checklists[checklist_i];
                if checklist
                    .turn_clients
                    .iter()
                    .chain(checklist.pending_delete_turn_clients.iter())
                    .any(|(_id, turn_client)| {
                        turn_client.transport() == transport
                            && turn_client.local_addr() == local_addr
                            && if transport == TransportType::Tcp {
                                remote_addr == Some(turn_client.remote_addr())
                            } else {
                                true
                            }
                    })
                {
                    return;
                } else {
                    (transport, local_addr, remote_addr)
                }
            };
        match transport {
            TransportType::Udp => {
                self.pending_remove_sockets.push_back(CheckListSetSocket {
                    checklist_id,
                    component_id: check.pair.local.component_id,
                    transport,
                    local_addr,
                    remote_addr: "0.0.0.0:0".parse().unwrap(),
                });
            }
            TransportType::Tcp => {
                self.pending_remove_sockets.push_back(CheckListSetSocket {
                    checklist_id,
                    component_id: check.pair.local.component_id,
                    transport,
                    local_addr,
                    remote_addr: remote_addr.unwrap(),
                });
            }
        }
    }

    fn maybe_remove_sockets(&mut self, checklist_i: usize, now: Instant) {
        let checklist = &mut self.checklists[checklist_i];
        for failed in checklist.prune_checks_with(|check| check.state == CandidatePairState::Failed)
        {
            self.remove_check_resources(checklist_i, failed, now);
        }
    }

    /// Advance the set state machine.  Should be called repeatedly until
    /// [`CheckListSetPollRet::WaitUntil`] is returned.
    #[tracing::instrument(name = "check_set_poll", level = "debug", ret, skip(self))]
    pub fn poll(&mut self, now: Instant) -> CheckListSetPollRet {
        if !self.pending_transmits.is_empty() || !self.pending_messages.is_empty() {
            return CheckListSetPollRet::WaitUntil(now);
        }

        let mut any_running = false;
        let mut all_failed = true;
        let mut all_turn_closed = self.closed;
        let start_idx = self.checklist_i;
        loop {
            let mut lowest_wait = now + Duration::from_secs(99999);
            if self.checklists.is_empty() {
                if self.closed {
                    return CheckListSetPollRet::Closed;
                }
                return CheckListSetPollRet::WaitUntil(lowest_wait);
            }
            self.checklist_i += 1;
            if self.checklist_i >= self.checklists.len() {
                self.checklist_i = 0;
            }

            let checklist = &mut self.checklists[self.checklist_i];
            for (_turn_id, client) in checklist.turn_clients.iter_mut() {
                while let Some(event) = client.poll_event() {
                    match event {
                        TurnEvent::AllocationCreated(_, _) => (),
                        TurnEvent::AllocationCreateFailed(_family) => (),
                        TurnEvent::PermissionCreated(transport, peer_addr) => {
                            for idx in 0..checklist.pairs.len() {
                                let check = &mut checklist.pairs[idx];
                                if check.pair.local.candidate_type != CandidateType::Relayed
                                    || check.pair.local.address.ip() != peer_addr
                                    || check.pair.local.transport_type != transport
                                    || !matches!(
                                        check.state,
                                        CandidatePairState::Failed | CandidatePairState::Succeeded
                                    )
                                {
                                    continue;
                                }
                            }
                        }
                        TurnEvent::PermissionCreateFailed(transport, peer_addr) => {
                            for idx in 0..checklist.pairs.len() {
                                let check = &mut checklist.pairs[idx];
                                if check.pair.local.candidate_type != CandidateType::Relayed
                                    || check.pair.local.address.ip() != peer_addr
                                    || check.pair.local.transport_type != transport
                                {
                                    continue;
                                }
                                check.set_state(CandidatePairState::Failed);
                            }
                        }
                        TurnEvent::ChannelCreated(_transport, _peer_addr) => (),
                        TurnEvent::ChannelCreateFailed(_transport, _addr) => (),
                    }
                }

                match client.poll(now) {
                    TurnPollRet::Closed => (),
                    TurnPollRet::WaitUntil(wait) => {
                        all_turn_closed = false;
                        if wait == now {
                            return CheckListSetPollRet::WaitUntil(
                                wait.max(
                                    self.last_send_time
                                        .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                        .unwrap_or(now),
                                ),
                            );
                        }
                        if wait < lowest_wait {
                            lowest_wait = wait.max(
                                self.last_send_time
                                    .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                    .unwrap_or(now),
                            );
                        }
                    }
                }
            }
            let mut idx = 0;
            while let Some((_turn_id, client)) = checklist.pending_delete_turn_clients.get_mut(idx)
            {
                match client.poll(now) {
                    TurnPollRet::Closed => {
                        let client = checklist.pending_delete_turn_clients.remove(idx).1;
                        let transport = client.transport();
                        if checklist
                            .find_agent_for_5tuple(
                                transport,
                                client.local_addr(),
                                client.remote_addr(),
                            )
                            .is_none()
                        {
                            return CheckListSetPollRet::RemoveSocket {
                                checklist_id: checklist.checklist_id,
                                // FIXME; hardcoded component id
                                component_id: 1,
                                transport,
                                local_addr: client.local_addr(),
                                remote_addr: client.remote_addr(),
                            };
                        }
                        continue;
                    }
                    TurnPollRet::WaitUntil(wait) => {
                        all_turn_closed = false;
                        if wait == now {
                            return CheckListSetPollRet::WaitUntil(
                                wait.max(
                                    self.last_send_time
                                        .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                        .unwrap_or(now),
                                ),
                            );
                        }
                        if wait < lowest_wait {
                            lowest_wait = wait.max(
                                self.last_send_time
                                    .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                    .unwrap_or(now),
                            );
                        }
                    }
                }
                idx += 1;
            }

            if let Some(event) = checklist.poll_event() {
                let checklist_id = checklist.checklist_id;
                if matches!(event, ConnCheckEvent::SelectedPair(_, _)) {
                    self.maybe_remove_sockets(self.checklist_i, now);
                }
                return CheckListSetPollRet::Event {
                    checklist_id,
                    event,
                };
            }

            let checklist_state = checklist.state();
            if checklist_state == CheckListState::Running {
                any_running = true;
            }
            if checklist_state != CheckListState::Failed {
                if let Some(last_send) = self.last_send_time {
                    if last_send + Self::MINIMUM_SET_TICK > now {
                        return CheckListSetPollRet::WaitUntil(last_send + Self::MINIMUM_SET_TICK);
                    }
                }
                all_failed = false;
                for idx in 0..checklist.pairs.len() {
                    let check = &mut checklist.pairs[idx];
                    if check.state != CandidatePairState::InProgress {
                        continue;
                    }
                    let conncheck_id = check.conncheck_id;
                    if let Some(agent_id) = check.agent_id() {
                        if let Some(agent) = checklist.mut_agent_by_id(agent_id) {
                            trace!("polling existing stun request for check {conncheck_id}");
                            match agent.poll(now) {
                                StunAgentPollRet::TransactionTimedOut(_request) => {
                                    checklist.check_cancel_retransmissions(conncheck_id);
                                    let check = &mut checklist.pairs[idx];
                                    check.set_state(CandidatePairState::Failed);
                                }
                                StunAgentPollRet::TransactionCancelled(_request) => {
                                    checklist.check_cancel_retransmissions(conncheck_id);
                                    let check = &mut checklist.pairs[idx];
                                    check.set_state(CandidatePairState::Failed);
                                }
                                StunAgentPollRet::WaitUntil(wait) => {
                                    if wait < lowest_wait {
                                        lowest_wait = wait.max(
                                            self.last_send_time
                                                .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                                .unwrap_or(now),
                                        );
                                    }
                                }
                            }
                        } else if let Some(client) = checklist.mut_turn_client_by_id(agent_id) {
                            match client.poll(now) {
                                TurnPollRet::WaitUntil(wait) => {
                                    if wait < lowest_wait {
                                        lowest_wait = wait.max(
                                            self.last_send_time
                                                .map(|last_send| last_send + Self::MINIMUM_SET_TICK)
                                                .unwrap_or(now),
                                        );
                                    }
                                }
                                TurnPollRet::Closed => (),
                            }
                        } else {
                            unreachable!();
                        }
                    }
                }
            }

            let conncheck_id = match self.next_check() {
                Some(c) => c,
                None => {
                    if start_idx == self.checklist_i {
                        debug!("nothing to do yet any-running:{any_running} completed:{} all-failed:{all_failed} turn-closed:{all_turn_closed}", self.completed);
                        // we looked at them all and none of the checklist could find anything to
                        // do
                        if !any_running && !self.completed {
                            self.completed = true;
                            return CheckListSetPollRet::Completed;
                        } else if let Some(remove) = self.pending_remove_sockets.pop_front() {
                            return remove.into_remove();
                        } else if all_failed && all_turn_closed {
                            return CheckListSetPollRet::Closed;
                        } else {
                            return CheckListSetPollRet::WaitUntil(lowest_wait);
                        }
                    } else {
                        continue;
                    }
                }
            };

            trace!("starting conncheck");
            match self.perform_conncheck(self.checklist_i, conncheck_id) {
                Ok(Some(socket)) => return socket.into_allocate(),
                Ok(None) => {
                    let checklist = &mut self.checklists[self.checklist_i];
                    if let Some(event) = checklist.poll_event() {
                        let checklist_id = checklist.checklist_id;
                        if matches!(event, ConnCheckEvent::SelectedPair(_, _)) {
                            self.maybe_remove_sockets(self.checklist_i, now);
                        }
                        return CheckListSetPollRet::Event {
                            checklist_id,
                            event,
                        };
                    } else {
                        return CheckListSetPollRet::WaitUntil(now);
                    }
                }
                Err(e) => warn!("failed to perform check: {e:?}"),
            }
        }
    }

    #[tracing::instrument(name = "check_set_poll_transmit", level = "trace", skip(self))]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<CheckListSetTransmit> {
        for checklist in self.checklists.iter_mut() {
            while let Some((turn_id, transport, remote_ip)) =
                checklist.pending_turn_permissions.pop_back()
            {
                trace!(
                    "have pending turn permission for id {turn_id:?}, {transport:?}, {remote_ip}"
                );
                let Some(client) = checklist.mut_turn_client_by_id(turn_id) else {
                    continue;
                };

                if let Err(e) = client.create_permission(transport, remote_ip, now) {
                    warn!(
                        "received error trying to create a permission to {:?}: {e}",
                        remote_ip
                    );
                }
            }
        }
        if let Some(pending) = self.pending_transmits.pop_back() {
            trace!(
                "pending {} {} -> {} transmit of {} bytes",
                pending.transmit.transport,
                pending.transmit.from,
                pending.transmit.to,
                pending.transmit.data.len()
            );
            return Some(pending);
        }

        while let Some(pending) = self.pending_messages.pop_back() {
            let Some(checklist) = self.mut_list(pending.checklist_id) else {
                continue;
            };
            let Some(agent) = checklist.mut_agent_by_id(pending.agent_id) else {
                continue;
            };
            if pending.is_request {
                debug!(
                    "Sending request {:?} to {:?} using agent: {:?} and turn id {:?}",
                    MessageHeader::from_bytes(&pending.msg).unwrap(),
                    pending.to,
                    pending.agent_id,
                    pending.turn_id
                );
                match agent.send_request(pending.msg, pending.to, now) {
                    Ok(transmit) => {
                        if let Some((turn_id, _turn_to)) = pending.turn_id {
                            let transport = transmit.transport;
                            // FIXME: try to avoid this copy
                            let data = transmit.data.into_owned();
                            let Some(client) = checklist.mut_turn_client_by_id(turn_id) else {
                                continue;
                            };
                            match client.send_to(transport, pending.to, data, now) {
                                Ok(transmit) => {
                                    if let Some(transmit) = transmit {
                                        return Some(CheckListSetTransmit {
                                            checklist_id: pending.checklist_id,
                                            transmit: transmit_send_build_unframed(transmit),
                                        });
                                    }
                                }
                                Err(e) => warn!("error sending: {e}"),
                            }
                        } else {
                            let transport = transmit.transport;
                            return Some(CheckListSetTransmit {
                                checklist_id: pending.checklist_id,
                                transmit: transmit
                                    .reinterpret_data(|data| transmit_send(transport, data)),
                            });
                        }
                    }
                    Err(e) => warn!("error sending: {e}"),
                }
            } else {
                debug!("Sending response {:?} to {:?}", pending.msg, pending.to);
                match agent.send(pending.msg, pending.to, now) {
                    Ok(transmit) => {
                        if let Some((turn_id, _turn_to)) = pending.turn_id {
                            let transport = transmit.transport;
                            let Some(client) = checklist.mut_turn_client_by_id(turn_id) else {
                                continue;
                            };
                            match client.send_to(transport, pending.to, transmit.data, now) {
                                Ok(transmit) => {
                                    if let Some(transmit) = transmit {
                                        return Some(CheckListSetTransmit {
                                            checklist_id: pending.checklist_id,
                                            transmit: transmit_send_build_unframed(transmit),
                                        });
                                    }
                                }
                                Err(e) => warn!("error sending: {e}"),
                            }
                        } else {
                            let transport = transmit.transport;
                            return Some(CheckListSetTransmit {
                                checklist_id: pending.checklist_id,
                                transmit: transmit
                                    .reinterpret_data(|data| transmit_send(transport, data)),
                            });
                        }
                    }
                    Err(e) => warn!("error sending: {e}"),
                }
            }
        }

        if self
            .last_send_time
            .map_or(false, |last_send| last_send + Self::MINIMUM_SET_TICK > now)
        {
            return None;
        }

        for checklist_i in 0..self.checklists.len() {
            let checklist = &self.checklists[checklist_i];
            let checklist_id = checklist.checklist_id;
            let agents_len = self.checklists[checklist_i].agents.len();
            for check_agent_i in 0..agents_len {
                let checklist = &mut self.checklists[checklist_i];
                let (transport, local_addr) = {
                    let check_agent = &mut checklist.agents[check_agent_i];
                    (
                        check_agent.agent.transport(),
                        check_agent.agent.local_addr(),
                    )
                };
                let checklist = &mut self.checklists[checklist_i];
                if let Some((turn_id, _client)) =
                    checklist.mut_turn_client_by_allocated_address(transport, local_addr)
                {
                    let check_agent = &mut checklist.agents[check_agent_i];
                    let Some(transmit) = check_agent.agent.poll_transmit(now) else {
                        continue;
                    };
                    let transmit = transmit.reinterpret_data(|data| data.to_vec());

                    let transport = transmit.transport;
                    let client = checklist.mut_turn_client_by_id(turn_id).unwrap();
                    match client.send_to(transport, transmit.to, transmit.data, now) {
                        Ok(transmit) => {
                            if let Some(transmit) = transmit {
                                self.last_send_time = Some(now);
                                return Some(CheckListSetTransmit {
                                    checklist_id,
                                    transmit: transmit_send_build_unframed(transmit),
                                });
                            }
                        }
                        Err(e) => warn!("error sending: {e}"),
                    }
                } else {
                    let check_agent = &mut checklist.agents[check_agent_i];
                    let Some(transmit) = check_agent.agent.poll_transmit(now) else {
                        continue;
                    };

                    let transport = transmit.transport;
                    self.last_send_time = Some(now);
                    return Some(CheckListSetTransmit {
                        checklist_id,
                        transmit: transmit.reinterpret_data(|data| transmit_send(transport, data)),
                    });
                }
            }

            let checklist = &mut self.checklists[checklist_i];
            for (_id, client) in checklist.turn_clients.iter_mut() {
                let Some(transmit) = client.poll_transmit(now) else {
                    continue;
                };

                self.last_send_time = Some(now);
                return Some(CheckListSetTransmit {
                    checklist_id,
                    transmit: transmit_send_unframed(transmit),
                });
            }

            for (_id, client) in checklist.pending_delete_turn_clients.iter_mut() {
                let Some(transmit) = client.poll_transmit(now) else {
                    continue;
                };

                self.last_send_time = Some(now);
                return Some(CheckListSetTransmit {
                    checklist_id,
                    transmit: transmit_send_unframed(transmit),
                });
            }
        }
        None
    }

    /// Report a reply (success or failure) to a TCP connection attempt.
    /// [`ConnCheckListSet::poll`] should be called at the earliest opportunity.
    #[tracing::instrument(
        level = "debug",
        skip(self, checklist_id, component_id),
        fields(
            checklist.id = checklist_id,
            component.id = component_id,
            ?local_addr,
        )
    )]
    pub fn allocated_socket(
        &mut self,
        checklist_id: usize,
        component_id: usize,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        local_addr: Result<SocketAddr, StunError>,
    ) {
        let Some(checklist) = self
            .checklists
            .iter_mut()
            .find(|checklist| checklist.checklist_id == checklist_id)
        else {
            debug!("no checklist with id {checklist_id}");
            return;
        };

        // FIXME: handle TURN TCP connection construction

        if checklist.agents.iter().map(|a| &a.agent).any(|a| {
            a.transport() == TransportType::Tcp
                && a.local_addr() == from
                && a.remote_addr() == Some(to)
        }) {
            panic!("Adding an agent with the same 5-tuple multiple times is not supported");
        }

        for check in checklist.pairs.iter_mut() {
            if check.pair.local.transport_type != TransportType::Tcp {
                continue;
            }
            if check.pair.remote.address != to {
                continue;
            }
            // FIXME: handle TURN TCP connection construction
            if from != check.pair.local.base_address {
                continue;
            }
            if check.stun_request.is_some() {
                continue;
            }
            if check.pair.local.component_id != component_id {
                continue;
            }
            if check.state != CandidatePairState::InProgress {
                continue;
            }
            trace!("found check with id {} to set agent", check.conncheck_id);
            match local_addr {
                Ok(local_addr) => {
                    let mut new_pair = check.pair.clone();
                    let mut agent = StunAgent::builder(transport, local_addr)
                        .remote_addr(check.pair.remote.address)
                        .build();
                    // FIXME: handle TURN TCP connection construction
                    new_pair.local.base_address = local_addr;
                    new_pair.local.address = local_addr;

                    let Ok(stun_request) = ConnCheck::generate_stun_request(
                        &new_pair,
                        check.nominate,
                        self.controlling,
                        self.tie_breaker,
                        checklist.local_credentials.clone(),
                        checklist.remote_credentials.clone(),
                    ) else {
                        warn!("failed to generate stun request for new tcp agent");
                        return;
                    };
                    agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                        checklist.local_credentials.clone().into(),
                    ));
                    agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                        checklist.remote_credentials.clone().into(),
                    ));
                    let transaction_id = stun_request.transaction_id();

                    let checklist_id = check.checklist_id;
                    let nominate = check.nominate;
                    let conncheck_id = check.conncheck_id;

                    let (agent_id, _agent_idx) = checklist.add_agent(agent);
                    self.pending_messages
                        .push_front(CheckListSetPendingMessage {
                            checklist_id,
                            agent_id,
                            is_request: true,
                            msg: stun_request.finish(),
                            to,
                            turn_id: None,
                        });

                    let mut new_check = ConnCheck::new(
                        checklist_id,
                        new_pair.clone(),
                        agent_id,
                        nominate,
                        self.controlling,
                        checklist.remote_credentials.clone(),
                    );
                    let is_triggered = checklist
                        .triggered
                        .iter()
                        .any(|&check_id| conncheck_id == check_id);
                    new_check.set_state(CandidatePairState::InProgress);
                    new_check.stun_request = Some(transaction_id);

                    let old_conncheck_id = conncheck_id;
                    checklist
                        .pairs
                        .retain(|check| check.conncheck_id != old_conncheck_id);
                    checklist
                        .triggered
                        .retain(|&check_id| check_id != old_conncheck_id);
                    checklist
                        .valid
                        .retain(|&check_id| check_id != old_conncheck_id);
                    if is_triggered {
                        checklist.add_triggered(&new_check);
                    }
                    checklist.add_check(new_check);
                }
                Err(_e) => {
                    check.set_state(CandidatePairState::Failed);
                }
            }
            break;
        }
    }

    pub fn close(&mut self, now: Instant) {
        for checklist_i in 0..self.checklists.len() {
            let checklist = &mut self.checklists[checklist_i];
            let mut checks = VecDeque::new();
            core::mem::swap(&mut checks, &mut checklist.pairs);
            for check in checks {
                self.remove_check_resources(checklist_i, check, now);
            }
            let checklist = &mut self.checklists[checklist_i];
            let mut turn_clients = Vec::new();
            core::mem::swap(&mut turn_clients, &mut checklist.turn_clients);
            for (turn_id, mut turn_client) in turn_clients {
                let _ = turn_client.delete(now);
                checklist
                    .pending_delete_turn_clients
                    .push((turn_id, turn_client));
            }
            checklist.close();
        }
        self.closed = true;
    }
}

/// Return values for polling a set of checklists.
#[derive(Debug)]
pub enum CheckListSetPollRet {
    /// The check lists are closed for any processing.
    Closed,
    /// Allocate a socket using the specified network 5-tuple.  Report success
    /// or failure with `allocated_socket()`.
    AllocateSocket {
        checklist_id: usize,
        component_id: usize,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// Remove a socket using the specified network 5-tuple. The socket will not be referenced
    /// further.
    RemoveSocket {
        checklist_id: usize,
        component_id: usize,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// Wait until the specified time has passed.  Receiving handled data may cause a different
    /// value to be returned from `poll()`
    WaitUntil(Instant),
    /// An event has occured
    Event {
        checklist_id: usize,
        event: ConnCheckEvent,
    },
    /// The set has completed all operations and has either succeeded or failed.  Further progress
    /// will not be made.
    Completed,
}

#[derive(Debug)]
pub struct CheckListSetTransmit {
    pub checklist_id: usize,
    pub transmit: Transmit<Box<[u8]>>,
}

#[derive(Debug)]
struct CheckListSetPendingMessage {
    checklist_id: usize,
    agent_id: StunAgentId,
    is_request: bool,
    msg: Vec<u8>,
    turn_id: Option<(StunAgentId, SocketAddr)>,
    to: SocketAddr,
}

#[derive(Debug)]
struct CheckListSetSocket {
    checklist_id: usize,
    component_id: usize,
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl CheckListSetSocket {
    fn into_allocate(self) -> CheckListSetPollRet {
        CheckListSetPollRet::AllocateSocket {
            checklist_id: self.checklist_id,
            component_id: self.component_id,
            transport: self.transport,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
        }
    }

    fn into_remove(self) -> CheckListSetPollRet {
        CheckListSetPollRet::RemoveSocket {
            checklist_id: self.checklist_id,
            component_id: self.component_id,
            transport: self.transport,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
        }
    }
}

#[derive(Debug)]
pub struct PendingRecv {
    pub component_id: usize,
    pub data: Vec<u8>,
}

fn pair_tcp_type(local: TcpType) -> TcpType {
    match local {
        TcpType::Active => TcpType::Passive,
        TcpType::Passive => TcpType::Active,
        TcpType::So => TcpType::So,
    }
}

fn pair_construct_valid(pair: &CandidatePair, mapped_address: SocketAddr) -> CandidatePair {
    let mut local = pair.local.clone();
    local.address = mapped_address;
    CandidatePair {
        local,
        remote: pair.remote.clone(),
    }
}

// can the local candidate pair with 'remote' in any way
fn candidate_can_pair_with(local: &Candidate, remote: &Candidate) -> bool {
    let address = match local.candidate_type {
        CandidateType::Host => local.address,
        _ => candidate_agent_local_address(local),
    };
    if local.transport_type == TransportType::Tcp
        && remote.transport_type == TransportType::Tcp
        && (local.tcp_type.is_none()
            || remote.tcp_type.is_none()
            || pair_tcp_type(local.tcp_type.unwrap()) != remote.tcp_type.unwrap())
    {
        return false;
    }
    local.transport_type == remote.transport_type
        && local.component_id == remote.component_id
        && address.is_ipv4() == remote.address.is_ipv4()
        && address.is_ipv6() == remote.address.is_ipv6()
}

fn validate_username(username: Username, local_credentials: &Credentials) -> bool {
    let username = username.username().as_bytes();
    let local_user = local_credentials.ufrag.as_bytes();
    if local_user.len()
        == local_user
            .iter()
            .zip(username)
            .take_while(|(l, r)| l == r)
            .count()
    {
        true
    } else {
        debug!("binding request failed username validation");
        false
    }
}

pub(crate) fn transmit_send<T: AsRef<[u8]>>(transport: TransportType, data: T) -> Box<[u8]> {
    match transport {
        TransportType::Udp => data.as_ref().into(),
        TransportType::Tcp => {
            let len = data.as_ref().len();
            let mut ret = Vec::with_capacity(2 + len);
            ret.resize(2, 0);
            BigEndian::write_u16(&mut ret, len as u16);
            ret.extend_from_slice(data.as_ref());
            ret.into_boxed_slice()
        }
    }
}

fn transmit_send_build_unframed<T: DelayedTransmitBuild + core::fmt::Debug>(
    transmit: TransmitBuild<T>,
) -> Transmit<Box<[u8]>> {
    Transmit::new(
        transmit.data.build().into_boxed_slice(),
        transmit.transport,
        transmit.from,
        transmit.to,
    )
}

fn transmit_send_unframed(transmit: Transmit<Data<'_>>) -> Transmit<Box<[u8]>> {
    transmit.reinterpret_data(|data| match data {
        Data::Owned(owned) => owned.take(),
        Data::Borrowed(borrowed) => borrowed.take().into(),
    })
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::vec;

    use stun_proto::types::AddressFamily;
    use turn_client_proto::{
        tcp::TurnClientTcp,
        types::{
            message::{ALLOCATE, CREATE_PERMISSION},
            TurnCredentials,
        },
        udp::TurnClientUdp,
    };
    use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
    use turn_server_proto::server::TurnServer;

    use super::*;
    use crate::candidate::*;

    #[test]
    fn nominate_eq_bool() {
        let _log = crate::tests::test_init_log();
        assert!(Nominate::DontCare.eq(&true));
        assert!(Nominate::DontCare.eq(&false));
        assert!(Nominate::True.eq(&true));
        assert!(Nominate::False.eq(&false));
        assert!(!Nominate::False.eq(&true));
        assert!(!Nominate::True.eq(&false));
    }

    #[test]
    fn nominate_eq_nominate() {
        let _log = crate::tests::test_init_log();
        assert!(Nominate::DontCare.eq(&Nominate::DontCare));
        assert!(Nominate::DontCare.eq(&Nominate::True));
        assert!(Nominate::DontCare.eq(&Nominate::False));
        assert!(Nominate::True.eq(&Nominate::DontCare));
        assert!(Nominate::False.eq(&Nominate::DontCare));
        assert!(Nominate::True.eq(&Nominate::True));
        assert!(Nominate::False.eq(&Nominate::False));
        assert!(!Nominate::True.eq(&Nominate::False));
        assert!(!Nominate::False.eq(&Nominate::True));
    }

    struct Peer {
        candidate: Candidate,
        local_credentials: Option<Credentials>,
        remote_credentials: Option<Credentials>,
    }

    impl Peer {
        fn default() -> Self {
            Peer::builder().build()
        }

        fn builder() -> PeerBuilder {
            PeerBuilder::default()
        }

        fn stun_agent(&self) -> StunAgent {
            if self.candidate.transport_type == TransportType::Tcp {
                unreachable!();
            }
            let agent =
                StunAgent::builder(self.candidate.transport_type, self.candidate.base_address);
            let mut agent = agent.build();
            self.configure_stun_agent(&mut agent);
            agent
        }

        fn configure_stun_agent(&self, agent: &mut StunAgent) {
            let local_credentials = self
                .local_credentials
                .clone()
                .unwrap_or_else(|| Credentials::new(String::from("user"), String::from("pass")));
            agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                local_credentials.into(),
            ));
            if let Some(remote_credentials) = self.remote_credentials.as_ref() {
                agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));
            }
        }
    }

    #[derive(Debug, Default)]
    struct PeerBuilder {
        foundation: Option<String>,
        local_credentials: Option<Credentials>,
        remote_credentials: Option<Credentials>,
        component_id: Option<usize>,
        priority: Option<u32>,
        transport: Option<TransportType>,
        local_addr: Option<SocketAddr>,
        candidate: Option<Candidate>,
        tcp_type: Option<TcpType>,
    }

    impl PeerBuilder {
        fn foundation(mut self, foundation: &str) -> Self {
            self.foundation = Some(foundation.to_owned());
            self
        }

        fn local_credentials(mut self, credentials: Credentials) -> Self {
            self.local_credentials = Some(credentials);
            self
        }

        fn remote_credentials(mut self, credentials: Credentials) -> Self {
            self.remote_credentials = Some(credentials);
            self
        }

        fn component_id(mut self, component_id: usize) -> Self {
            self.component_id = Some(component_id);
            self
        }

        fn priority(mut self, priority: u32) -> Self {
            self.priority = Some(priority);
            self
        }

        fn transport(mut self, transport: TransportType) -> Self {
            self.transport = Some(transport);
            self
        }

        fn tcp_type(mut self, tcp_type: TcpType) -> Self {
            self.tcp_type = Some(tcp_type);
            self
        }

        fn local_addr(mut self, addr: SocketAddr) -> Self {
            self.local_addr = Some(addr);
            self
        }

        fn build(self) -> Peer {
            let addr = self.candidate.as_ref().map(|c| c.base_address).unwrap_or(
                self.local_addr
                    .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()),
            );
            let ttype = self
                .candidate
                .as_ref()
                .map(|c| c.transport_type)
                .unwrap_or(self.transport.unwrap_or(TransportType::Udp));

            let tcp_type = match ttype {
                TransportType::Udp => {
                    assert!(self.tcp_type.is_none());
                    None
                }
                TransportType::Tcp => Some(self.tcp_type.unwrap_or(TcpType::Passive)),
            };

            if let Some(candidate) = &self.candidate {
                if let Some(component_id) = self.component_id {
                    if component_id != candidate.component_id {
                        panic!("mismatched component ids");
                    }
                }
                if let Some(foundation) = self.foundation.clone() {
                    if foundation != candidate.foundation {
                        panic!("mismatched foundations");
                    }
                }
            }
            let candidate = self.candidate.unwrap_or_else(|| {
                let mut builder = Candidate::builder(
                    self.component_id.unwrap_or(1),
                    CandidateType::Host,
                    ttype,
                    &self.foundation.unwrap_or(String::from("0")),
                    addr,
                );
                if let Some(priority) = self.priority {
                    builder = builder.priority(priority);
                }
                if let Some(tcp_type) = tcp_type {
                    builder = builder.tcp_type(tcp_type);
                }
                builder.build()
            });

            Peer {
                candidate,
                local_credentials: self.local_credentials,
                remote_credentials: self.remote_credentials,
            }
        }
    }

    #[test]
    fn get_candidates() {
        let _log = crate::tests::test_init_log();
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list = set.new_list();
        let list = set.mut_list(list).unwrap();
        list.add_component(1);

        let local = Peer::default();
        let remote = Peer::default();

        list.add_local_candidate(local.candidate.clone());
        list.add_remote_candidate(remote.candidate.clone());

        // The candidate list is only what we put in
        let mut locals = list.local_candidates();
        assert_eq!(locals.next(), Some(&local.candidate));
        assert_eq!(locals.next(), None);
        let remotes = list.remote_candidates();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0], remote.candidate);
    }

    // simplified version of ConnCheckList handle_binding_request that doesn't
    // update any state like ConnCheckList or even do peer-reflexive candidate
    // things
    fn handle_binding_request(
        agent: &StunAgent,
        local_credentials: &Credentials,
        msg: &Message,
        from: SocketAddr,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
    ) -> Result<Vec<u8>, StunError> {
        let local_stun_credentials = agent.local_credentials().unwrap();

        if let Some(error_msg) = Message::check_attribute_types(
            msg,
            &[
                Username::TYPE,
                Fingerprint::TYPE,
                MessageIntegrity::TYPE,
                IceControlled::TYPE,
                IceControlling::TYPE,
                Priority::TYPE,
                UseCandidate::TYPE,
            ],
            &[
                Username::TYPE,
                Fingerprint::TYPE,
                MessageIntegrity::TYPE,
                Priority::TYPE,
            ],
            MessageWriteVec::new(),
        ) {
            // failure -> send error response
            return Ok(error_msg.finish());
        }

        if msg.validate_integrity(&local_stun_credentials).is_err() {
            let code = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            response.add_attribute(&code).unwrap();
            return Ok(response.finish());
        }

        let ice_controlling = msg.attribute::<IceControlling>();
        let ice_controlled = msg.attribute::<IceControlled>();
        let username = msg.attribute::<Username>();
        let valid_username = username
            .map(|username| validate_username(username, local_credentials))
            .unwrap_or(false);

        let mut response = if ice_controlling.is_err() && ice_controlled.is_err() {
            warn!("missing ice controlled/controlling attribute");
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build()?;
            response.add_attribute(&error)?;
            response
        } else if !valid_username {
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build()?;
            response.add_attribute(&error)?;
            response
        } else if let Some(error_code) = error_response {
            info!("responding with error {}", error_code);
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(error_code).build()?;
            response.add_attribute(&error)?;
            response
        } else {
            let mut response = Message::builder_success(msg, MessageWriteVec::new());
            let xor_addr =
                XorMappedAddress::new(response_address.unwrap_or(from), msg.transaction_id());
            response.add_attribute(&xor_addr).unwrap();
            response
        };
        response.add_message_integrity(&local_stun_credentials, IntegrityAlgorithm::Sha1)?;
        response.add_fingerprint()?;
        Ok(response.finish())
    }

    fn reply_to_conncheck<T: AsRef<[u8]>>(
        agent: &mut StunAgent,
        credentials: &Credentials,
        transmit: Transmit<T>,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
        now: Instant,
    ) -> Option<Transmit<Box<[u8]>>> {
        // XXX: assumes that tcp framing is not in use
        let offset = match transmit.transport {
            TransportType::Udp => 0,
            TransportType::Tcp => 2,
        };
        error!("data: {:x?}", transmit.data.as_ref());
        match Message::from_bytes(&transmit.data.as_ref()[offset..]) {
            Err(e) => error!("error parsing STUN message {e:?}"),
            Ok(msg) => {
                debug!("received {} -> {}: {}", transmit.from, transmit.to, msg);
                if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                    let transmit = agent
                        .send(
                            handle_binding_request(
                                agent,
                                credentials,
                                &msg,
                                transmit.from,
                                error_response,
                                response_address,
                            )
                            .unwrap(),
                            transmit.from,
                            now,
                        )
                        .unwrap();
                    let transport = transmit.transport;
                    return Some(transmit.reinterpret_data(|data| transmit_send(transport, data)));
                }
            }
        }
        None
    }

    #[test]
    fn conncheck_list_transmit() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::ZERO;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let CheckListSetPollRet::WaitUntil(_) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let Some(CheckListSetTransmit {
            checklist_id: _,
            transmit,
        }) = state.local.checklist_set.poll_transmit(now)
        else {
            unreachable!()
        };
        assert_eq!(
            transmit.transport,
            state.local.peer.candidate.transport_type
        );
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, state.remote.candidate.base_address);
        state.local_list().dump_check_state();
    }

    fn assert_list_contains_checks(list: &mut ConnCheckList, pairs: Vec<&CandidatePair>) {
        list.dump_check_state();
        trace!("pairs  {:?}", pairs);

        for (pair, check) in pairs.into_iter().zip(list.pairs.iter()) {
            assert_eq!(&check.pair, pair);
        }
    }

    #[test]
    fn checklist_generate_checks() {
        let _log = crate::tests::test_init_log();
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list = set.new_list();
        let list = set.mut_list(list).unwrap();
        list.add_component(1);
        list.add_component(2);
        let local1_removed = Peer::builder()
            .priority(1)
            .local_addr("127.0.0.1:1".parse().unwrap())
            .build();
        let local1 = Peer::builder()
            .priority(100)
            .local_addr("127.0.0.1:100".parse().unwrap())
            .build();
        let local1_ignored2 = Peer::builder()
            .priority(99)
            .local_addr("127.0.0.1:99".parse().unwrap())
            .build();
        let remote1 = Peer::builder()
            .priority(2)
            .local_addr("127.0.0.1:2".parse().unwrap())
            .build();
        let local2 = Peer::builder()
            .component_id(2)
            .priority(4)
            .local_addr("127.0.0.2:3".parse().unwrap())
            .build();
        let remote2 = Peer::builder()
            .component_id(2)
            .priority(6)
            .local_addr("127.0.0.2:4".parse().unwrap())
            .build();
        let local3 = Peer::builder()
            .priority(10)
            .local_addr("127.0.0.3:5".parse().unwrap())
            .build();
        let remote3 = Peer::builder()
            .priority(15)
            .local_addr("127.0.0.3:6".parse().unwrap())
            .build();

        assert!(list.add_local_candidate(local1_removed.candidate.clone()));
        assert!(list.add_local_candidate(local1.candidate.clone()));
        assert!(!list.add_local_candidate(local1_ignored2.candidate.clone()));
        list.add_remote_candidate(remote1.candidate.clone());
        assert!(list.add_local_candidate(local2.candidate.clone()));
        list.add_remote_candidate(remote2.candidate.clone());
        assert!(list.add_local_candidate(local3.candidate.clone()));
        list.add_remote_candidate(remote3.candidate.clone());

        let pair1 = CandidatePair::new(local1.candidate.clone(), remote3.candidate.clone());
        let pair2 = CandidatePair::new(local3.candidate.clone(), remote3.candidate);
        let pair3 = CandidatePair::new(local2.candidate, remote2.candidate);
        let pair4 = CandidatePair::new(local1.candidate, remote1.candidate.clone());
        let pair5 = CandidatePair::new(local3.candidate, remote1.candidate);
        assert_list_contains_checks(list, vec![&pair1, &pair2, &pair3, &pair4, &pair5]);
    }

    #[test]
    fn checklists_initial_thaw() {
        let _log = crate::tests::test_init_log();
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list1_id = set.new_list();
        let list2_id = set.new_list();
        let now = Instant::ZERO;

        let local1 = Peer::builder()
            .foundation("0")
            .priority(1)
            .local_addr("127.0.0.1:1".parse().unwrap())
            .build();
        let remote1 = Peer::builder()
            .foundation("0")
            .priority(2)
            .local_addr("127.0.0.1:2".parse().unwrap())
            .build();
        let local2 = Peer::builder()
            .foundation("0")
            .component_id(2)
            .priority(3)
            .local_addr("127.0.0.2:3".parse().unwrap())
            .build();
        let remote2 = Peer::builder()
            .foundation("0")
            .component_id(2)
            .priority(4)
            .local_addr("127.0.0.2:4".parse().unwrap())
            .build();
        let local3 = Peer::builder()
            .foundation("1")
            .component_id(2)
            .priority(7)
            .local_addr("127.0.0.3:5".parse().unwrap())
            .build();
        let remote3 = Peer::builder()
            .foundation("1")
            .component_id(2)
            .priority(10)
            .local_addr("127.0.0.3:6".parse().unwrap())
            .build();

        // generated pairs
        let pair1 = CandidatePair::new(local1.candidate.clone(), remote1.candidate.clone());
        let pair2 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
        let pair3 = CandidatePair::new(local3.candidate.clone(), remote2.candidate.clone());
        let pair4 = CandidatePair::new(local2.candidate.clone(), remote3.candidate.clone());
        let pair5 = CandidatePair::new(local2.candidate.clone(), remote2.candidate.clone());

        let list1 = set.mut_list(list1_id).unwrap();
        list1.add_component(1);
        list1.add_component(2);
        list1.add_local_candidate(local1.candidate.clone());
        list1.add_remote_candidate(remote1.candidate.clone());

        assert_list_contains_checks(list1, vec![&pair1]);

        let list2 = set.mut_list(list2_id).unwrap();
        list2.add_component(1);
        list2.add_component(2);
        list2.add_local_candidate(local2.candidate.clone());
        list2.add_remote_candidate(remote2.candidate.clone());
        list2.add_local_candidate(local3.candidate.clone());
        list2.add_remote_candidate(remote3.candidate.clone());

        assert_list_contains_checks(list2, vec![&pair2, &pair3, &pair4, &pair5]);

        // thaw the first checklist with only a single pair will unfreeze that pair
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = set.poll(now)
        else {
            unreachable!();
        };

        let Some(_) = set.poll_transmit(now) else {
            unreachable!();
        };

        let list2 = set.mut_list(list2_id).unwrap();
        list2.dump_check_state();
        let check2 = list2.matching_check(&pair2, Nominate::DontCare).unwrap();
        assert_eq!(check2.pair, pair2);
        assert_eq!(check2.state(), CandidatePairState::InProgress);
        let check3 = list2.matching_check(&pair3, Nominate::DontCare).unwrap();
        assert_eq!(check3.pair, pair3);
        assert_eq!(check3.state(), CandidatePairState::Waiting);
        let check4 = list2.matching_check(&pair4, Nominate::DontCare).unwrap();
        assert_eq!(check4.pair, pair4);
        assert_eq!(check4.state(), CandidatePairState::Waiting);
        let check5 = list2.matching_check(&pair5, Nominate::DontCare).unwrap();
        assert_eq!(check5.pair, pair5);
        assert_eq!(check5.state(), CandidatePairState::Frozen);

        let list1 = set.mut_list(list1_id).unwrap();
        list1.dump_check_state();
        let check1 = list1.matching_check(&pair1, Nominate::DontCare).unwrap();
        assert_eq!(check1.pair, pair1);
        assert_eq!(check1.state(), CandidatePairState::Waiting);

        // thaw the second checklist with 2*2 pairs will unfreeze only the foundations not
        // unfrozen by the first checklist, which means unfreezing 3 pairs
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = set.poll(now)
        else {
            unreachable!();
        };
        let Some(_) = set.poll_transmit(now) else {
            unreachable!();
        };

        let list1 = set.mut_list(list1_id).unwrap();
        list1.dump_check_state();
        let check1 = list1.matching_check(&pair1, Nominate::DontCare).unwrap();
        assert_eq!(check1.pair, pair1);
        assert_eq!(check1.state(), CandidatePairState::InProgress);

        let list2 = set.mut_list(list2_id).unwrap();
        list2.dump_check_state();
        let check2 = list2.matching_check(&pair2, Nominate::DontCare).unwrap();
        assert_eq!(check2.pair, pair2);
        assert_eq!(check2.state(), CandidatePairState::InProgress);
        let check3 = list2.matching_check(&pair3, Nominate::DontCare).unwrap();
        assert_eq!(check3.pair, pair3);
        assert_eq!(check3.state(), CandidatePairState::Waiting);
        let check4 = list2.matching_check(&pair4, Nominate::DontCare).unwrap();
        assert_eq!(check4.pair, pair4);
        assert_eq!(check4.state(), CandidatePairState::Waiting);
        let check5 = list2.matching_check(&pair5, Nominate::DontCare).unwrap();
        assert_eq!(check5.pair, pair5);
        assert_eq!(check5.state(), CandidatePairState::Frozen);
    }

    struct FineControlPeer {
        component_id: usize,
        peer: Peer,
        checklist_set: ConnCheckListSet,
        checklist_id: usize,
    }

    struct FineControl {
        local: FineControlPeer,
        remote: Peer,
    }

    struct FineControlBuilder {
        trickle_ice: bool,
        controlling: bool,
        local_peer_builder: PeerBuilder,
        remote_peer_builder: PeerBuilder,
    }

    impl Default for FineControlBuilder {
        fn default() -> Self {
            let local_credentials = Credentials::new("luser".into(), "lpass".into());
            let remote_credentials = Credentials::new("ruser".into(), "rpass".into());
            Self {
                trickle_ice: false,
                controlling: true,
                local_peer_builder: Peer::builder()
                    .foundation("0")
                    .local_credentials(local_credentials.clone())
                    .remote_credentials(remote_credentials.clone())
                    .local_addr("127.0.0.1:1".parse().unwrap()),
                remote_peer_builder: Peer::builder()
                    .foundation("0")
                    .local_credentials(remote_credentials.clone())
                    .remote_credentials(local_credentials.clone())
                    .local_addr("127.0.0.1:2".parse().unwrap()),
            }
        }
    }

    impl FineControlBuilder {
        fn controlling(mut self, controlling: bool) -> Self {
            self.controlling = controlling;
            self
        }

        fn trickle_ice(mut self, trickle_ice: bool) -> Self {
            self.trickle_ice = trickle_ice;
            self
        }

        fn local_candidate(mut self, candidate: Candidate) -> Self {
            self.local_peer_builder.candidate = Some(candidate);
            self
        }

        fn build(self) -> FineControl {
            let mut local_set = ConnCheckListSet::builder(0, self.controlling)
                .trickle_ice(self.trickle_ice)
                .build();
            let local_list = local_set.new_list();
            let local_list = local_set.mut_list(local_list).unwrap();
            local_list.add_component(1);
            let checklist_id = local_list.checklist_id;

            let local_peer = self.local_peer_builder.build();
            let remote_peer = self.remote_peer_builder.build();

            local_list.set_local_credentials(local_peer.local_credentials.clone().unwrap());
            local_list.set_remote_credentials(local_peer.remote_credentials.clone().unwrap());
            if !self.trickle_ice {
                local_list.add_local_candidate(local_peer.candidate.clone());
                local_list.add_remote_candidate(remote_peer.candidate.clone());
            }

            FineControl {
                local: FineControlPeer {
                    component_id: 1,
                    peer: local_peer,
                    checklist_set: local_set,
                    checklist_id,
                },
                remote: remote_peer,
            }
        }
    }

    impl FineControl {
        fn builder() -> FineControlBuilder {
            FineControlBuilder::default()
        }

        fn local_list(&mut self) -> &mut ConnCheckList {
            self.local
                .checklist_set
                .mut_list(self.local.checklist_id)
                .unwrap()
        }

        fn set_remote_credentials(&mut self, credentials: Credentials) {
            self.local.peer.remote_credentials = Some(credentials.clone());
            self.remote.local_credentials = Some(credentials.clone());
            self.local_list().set_remote_credentials(credentials);
        }

        fn check_nomination(&mut self, pair: &CandidatePair, now: Instant) {
            let nominate_check = self
                .local_list()
                .matching_check(pair, Nominate::True)
                .unwrap();
            assert_eq!(nominate_check.state(), CandidatePairState::Waiting);
            let pair = nominate_check.pair.clone();
            let check_id = nominate_check.conncheck_id;
            assert!(self.local_list().is_triggered(&pair));

            // perform one tick which will perform the nomination check
            send_next_check_and_response(&self.local.peer, &self.remote)
                .perform(&mut self.local.checklist_set, now);

            let nominate_check = self.local_list().check_by_id(check_id).unwrap();
            assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

            // check list is done
            assert_eq!(self.local_list().state(), CheckListState::Completed);

            let CheckListSetPollRet::Event {
                checklist_id: _,
                event: ConnCheckEvent::SelectedPair(_cid, _selected_pair),
            } = self.local.checklist_set.poll(now)
            else {
                unreachable!();
            };
            let CheckListSetPollRet::Event {
                checklist_id: _,
                event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
            } = self.local.checklist_set.poll(now)
            else {
                unreachable!();
            };

            // perform one final tick attempt which should end the processing
            assert!(matches!(
                self.local.checklist_set.poll(now),
                CheckListSetPollRet::Completed
            ));
        }
    }

    struct NextCheckAndResponse<'next> {
        #[allow(unused)]
        local_peer: &'next Peer,
        remote_peer: &'next Peer,
        turn_server: Option<&'next mut TurnServer>,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
        unhandled_reply: bool,
    }

    impl<'a> NextCheckAndResponse<'a> {
        fn error_response(mut self, error_response: u16) -> Self {
            self.error_response = Some(error_response);
            self
        }

        fn response_address(mut self, address: SocketAddr) -> Self {
            self.response_address = Some(address);
            self
        }

        fn turn_server(mut self, server: &'a mut TurnServer) -> Self {
            self.turn_server = Some(server);
            self
        }

        fn unhandled_reply(mut self) -> Self {
            self.unhandled_reply = true;
            self
        }

        fn perform(mut self, set: &mut ConnCheckListSet, now: Instant) {
            // perform one tick which will start a connectivity check with the peer
            match set.poll(now) {
                CheckListSetPollRet::WaitUntil(_) => (),
                ret => {
                    error!("{ret:?}");
                    unreachable!()
                }
            }
            let Some(transmit) = set.poll_transmit(now) else {
                unreachable!()
            };
            let mut transmit = transmit.transmit;
            debug!("tick");

            // send a response (success or some kind of error like role-conflict)
            if let Some(turn) = self.turn_server.as_mut() {
                transmit = turn
                    .recv(transmit, now)
                    .unwrap()
                    .build()
                    .reinterpret_data(|data| data.into_boxed_slice());
            }
            let mut remote_agent = self.remote_peer.stun_agent();
            let mut reply = reply_to_conncheck(
                &mut remote_agent,
                &self.remote_peer.local_credentials.clone().unwrap(),
                transmit,
                self.error_response,
                self.response_address,
                now,
            )
            .unwrap();
            info!("reply: {reply:?}");

            if let Some(turn) = self.turn_server.as_mut() {
                reply = turn
                    .recv(reply, now)
                    .unwrap()
                    .build()
                    .reinterpret_data(|data| data.into_boxed_slice());
            }

            let checklist_id = set
                .checklists
                .iter()
                .map(|checklist| checklist.checklist_id)
                .next()
                .unwrap();
            let reply = set.incoming_data(checklist_id, 1, reply, now);
            trace!("reply: {reply:?}");
            if !self.unhandled_reply {
                assert!(reply.handled);
            }
        }
    }

    fn send_next_check_and_response<'next>(
        local_peer: &'next Peer,
        remote_peer: &'next Peer,
    ) -> NextCheckAndResponse<'next> {
        NextCheckAndResponse {
            local_peer,
            remote_peer,
            turn_server: None,
            error_response: None,
            response_address: None,
            unhandled_reply: false,
        }
    }

    #[test]
    fn very_fine_control1() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::ZERO;
        assert_eq!(state.local.component_id, 1);

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Frozen);
        let check_id = check.conncheck_id;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn role_conflict_response() {
        let _log = crate::tests::test_init_log();
        // start off in the controlled mode, otherwise, the test needs to do the nomination
        // check
        let mut state = FineControl::builder().controlling(false).build();
        let now = Instant::ZERO;

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Frozen);
        let check_id = check.conncheck_id;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::ROLE_CONFLICT)
            .perform(&mut state.local.checklist_set, now);
        state.local_list().dump_check_state();
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Failed);

        // should have resulted in the check being retriggered (always a new
        // check in our implementation)
        let triggered_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        let check_id = triggered_check.conncheck_id;
        let pair = triggered_check.pair.clone();
        assert!(state.local_list().is_triggered(&pair));

        // perform the next tick which will have a different ice controlling/ed attribute
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let triggered_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn bad_username_conncheck() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::ZERO;
        let local_list = state
            .local
            .checklist_set
            .mut_list(state.local.checklist_id)
            .unwrap();

        // set the wrong credentials and observe the failure
        let wrong_credentials =
            Credentials::new(String::from("wronguser"), String::from("wrongpass"));
        local_list.set_local_credentials(wrong_credentials);

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = local_list.matching_check(&pair, Nominate::False).unwrap();
        let check_id = check.conncheck_id;
        assert_eq!(check.state(), CandidatePairState::Frozen);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::UNAUTHORIZED)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Failed);

        // TODO: properly failing the checklist on all checks failing
        // check should be failed
        //assert_eq!(state.local_list().state(), CheckListState::Failed);

        //assert!(matches!(
        //    state.local.checklist_set.poll(now),
        //    CheckListSetPollRet::Completed
        //));
    }

    #[test]
    fn conncheck_tcp_active() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder();
        state.local_peer_builder = state
            .local_peer_builder
            .transport(TransportType::Tcp)
            .tcp_type(TcpType::Active);
        state.remote_peer_builder = state
            .remote_peer_builder
            .transport(TransportType::Tcp)
            .tcp_type(TcpType::Passive);
        let mut state = state.build();
        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let mut local_agent =
            StunAgent::builder(TransportType::Tcp, state.local.peer.candidate.base_address)
                .remote_addr(state.remote.candidate.address)
                .build();
        state.local.peer.configure_stun_agent(&mut local_agent);
        let mut remote_agent =
            StunAgent::builder(TransportType::Tcp, state.remote.candidate.address)
                .remote_addr(state.local.peer.candidate.base_address)
                .build();
        state.remote.configure_stun_agent(&mut remote_agent);
        let now = Instant::ZERO;

        let CheckListSetPollRet::AllocateSocket {
            checklist_id: id,
            component_id: cid,
            transport,
            local_addr: from,
            remote_addr: to,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(from, state.local.peer.candidate.base_address);
        assert_eq!(to, state.remote.candidate.address);
        assert_eq!(transport, TransportType::Tcp);
        error!("tcp connect");

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        state.local.checklist_set.allocated_socket(
            id,
            cid,
            transport,
            from,
            to,
            Ok(local_agent.local_addr()),
        );
        error!("tcp connect replied");

        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };
        assert_eq!(transmit.checklist_id, state.local.checklist_id);
        assert_eq!(
            transmit.transmit.from,
            state.local.peer.candidate.base_address
        );
        assert_eq!(transmit.transmit.to, state.remote.candidate.address);
        error!("tcp transmit");

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.transmit,
            None,
            None,
            now,
        ) else {
            unreachable!();
        };
        error!("tcp reply");

        let check = state
            .local_list()
            .matching_check(&pair, Nominate::DontCare)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::InProgress);

        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, 1, response, now);
        error!("tcp replied");

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.transmit,
            None,
            None,
            now,
        ) else {
            unreachable!();
        };
        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, 1, response, now);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(selected_pair.candidate_pair, pair);

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Tcp,
            local_addr,
            remote_addr,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        assert_eq!(remote_addr, pair.remote.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_tcp_passive() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder();
        state.local_peer_builder = state
            .local_peer_builder
            .transport(TransportType::Tcp)
            .local_addr("127.0.0.1:1000".parse().unwrap())
            .tcp_type(TcpType::Passive);
        state.remote_peer_builder = state
            .remote_peer_builder
            .transport(TransportType::Tcp)
            .local_addr("127.0.0.1:9".parse().unwrap())
            .tcp_type(TcpType::Active)
            .priority(10);
        let mut state = state.build();
        let now = Instant::ZERO;
        let remote_addr = SocketAddr::new(state.remote.candidate.base_address.ip(), 2000);
        let mut remote_cand = state.remote.candidate.clone();
        remote_cand.address = remote_addr;
        remote_cand.base_address = remote_addr;

        let pair = CandidatePair::new(state.local.peer.candidate.clone(), remote_cand.clone());

        let mut local_agent =
            StunAgent::builder(TransportType::Tcp, state.local.peer.candidate.base_address)
                .remote_addr(remote_addr)
                .build();
        state.local.peer.configure_stun_agent(&mut local_agent);
        let mut remote_agent = StunAgent::builder(TransportType::Tcp, remote_addr)
            .remote_addr(state.local.peer.candidate.base_address)
            .build();
        state.remote.configure_stun_agent(&mut remote_agent);

        let request = ConnCheck::generate_stun_request(
            &pair,
            false,
            false,
            100,
            state.remote.local_credentials.clone().unwrap(),
            state.remote.remote_credentials.clone().unwrap(),
        )
        .unwrap();

        let transport = remote_agent.transport();
        assert!(
            state
                .local
                .checklist_set
                .incoming_data(
                    state.local.checklist_id,
                    1,
                    remote_agent
                        .send_request(
                            request.finish(),
                            state.local.peer.candidate.base_address,
                            now
                        )
                        .unwrap()
                        .reinterpret_data(|data| transmit_send(transport, data)),
                    now,
                )
                .handled
        );

        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // success response
        let now = Instant::ZERO;
        let CheckListSetPollRet::WaitUntil(_) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };
        assert_eq!(transmit.checklist_id, state.local.checklist_id);
        assert_eq!(
            transmit.transmit.from,
            state.local.peer.candidate.base_address
        );
        assert_eq!(transmit.transmit.to, remote_cand.address);

        let response = Message::from_bytes(&transmit.transmit.data[2..]).unwrap();
        assert!(response.has_class(MessageClass::Success));

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // triggered check
        let CheckListSetPollRet::WaitUntil(_) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };
        assert_eq!(transmit.checklist_id, state.local.checklist_id);
        assert_eq!(
            transmit.transmit.from,
            state.local.peer.candidate.base_address
        );
        assert_eq!(transmit.transmit.to, remote_cand.address);

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.transmit,
            None,
            None,
            now,
        ) else {
            unreachable!();
        };
        state.local_list().dump_check_state();

        let check = state
            .local_list()
            .matching_check(&pair, Nominate::DontCare)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::InProgress);

        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, 1, response, now);
        error!("tcp replied");

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        // nominate triggered check
        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.transmit,
            None,
            None,
            now,
        ) else {
            unreachable!();
        };

        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, 1, response, now);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert!(candidate_pair_is_same_connection(
            &selected_pair.candidate_pair,
            &pair
        ));

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Tcp,
            local_addr,
            remote_addr,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        assert_eq!(remote_addr, pair.remote.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    fn remote_generate_check<'a>(
        remote_peer: &Peer,
        remote_agent: &'a mut StunAgent,
        to: SocketAddr,
        now: Instant,
    ) -> Transmit<Data<'a>> {
        // send a request from some unknown to the local agent address to produce a peer
        // reflexive candidate on the local agent
        let mut request = Message::builder_request(BINDING, MessageWriteVec::new());
        let priority = Priority::new(remote_peer.candidate.priority);
        request.add_attribute(&priority).unwrap();
        let ice = IceControlled::new(200);
        request.add_attribute(&ice).unwrap();
        let username = Username::new(
            &(remote_peer.remote_credentials.clone().unwrap().ufrag
                + ":"
                + &remote_peer.local_credentials.clone().unwrap().ufrag),
        )
        .unwrap();
        request.add_attribute(&username).unwrap();
        request
            .add_message_integrity(
                &MessageIntegrityCredentials::ShortTerm(
                    remote_peer.remote_credentials.clone().unwrap().into(),
                ),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        request.add_fingerprint().unwrap();

        remote_agent
            .send_request(request.finish(), to, now)
            .unwrap()
    }

    #[test]
    fn conncheck_incoming_prflx() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::ZERO;

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let initial_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Frozen);

        let unknown_remote_peer = Peer::builder()
            .local_addr("127.0.0.1:90".parse().unwrap())
            .foundation("1")
            .local_credentials(state.remote.local_credentials.clone().unwrap())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let mut remote_agent = unknown_remote_peer.stun_agent();

        let local_addr = state.local.peer.candidate.base_address;
        let transmit =
            remote_generate_check(&unknown_remote_peer, &mut remote_agent, local_addr, now);

        info!("sending prflx request");
        let reply =
            state
                .local
                .checklist_set
                .incoming_data(state.local.checklist_id, 1, transmit, now);
        assert!(reply.handled);

        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };

        let response = Message::from_bytes(&transmit.transmit.data).unwrap();
        let HandleStunReply::ValidatedStunResponse(response) =
            remote_agent.handle_stun(response, transmit.transmit.from)
        else {
            unreachable!();
        };
        assert_eq!(transmit.transmit.from, local_addr);
        assert!(response.has_class(MessageClass::Success));
        info!("have prflx response");

        // The stun request has created a new peer reflexive triggered check
        let mut prflx_remote_candidate = unknown_remote_peer.candidate.clone();
        prflx_remote_candidate.candidate_type = CandidateType::PeerReflexive;
        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            unknown_remote_peer.candidate.clone(),
        );
        state.local_list().dump_check_state();
        let triggered_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::Waiting);
        let check_id = triggered_check.conncheck_id;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        info!("perform triggered check");
        send_next_check_and_response(&state.local.peer, &unknown_remote_peer)
            .perform(&mut state.local.checklist_set, now);

        info!("have reply to triggered check");
        let triggered_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);
        let nominated_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        let check_id = nominated_check.conncheck_id;
        info!("perform nominated check");
        send_next_check_and_response(&state.local.peer, &unknown_remote_peer)
            .perform(&mut state.local.checklist_set, now);

        info!("have reply to nominated check");
        let nominated_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed,
        ));

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_response_prflx() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::ZERO;

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let initial_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Frozen);
        let check_id = initial_check.conncheck_id;

        let unknown_remote_peer = Peer::builder()
            .foundation("1")
            .local_credentials(state.remote.local_credentials.clone().unwrap())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let remote_agent = unknown_remote_peer.stun_agent();

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // send the next connectivity check but response with a different xor-mapped-address
        // which should result in a PeerReflexive address being produced in the check list
        send_next_check_and_response(&state.local.peer, &state.remote)
            .response_address(remote_agent.local_addr())
            .perform(&mut state.local.checklist_set, now);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Succeeded);

        // construct the peer reflexive pair
        let unknown_pair = CandidatePair::new(
            Candidate::builder(
                unknown_remote_peer.candidate.component_id,
                CandidateType::PeerReflexive,
                TransportType::Udp,
                "0",
                unknown_remote_peer.candidate.address,
            )
            .base_address(state.local.peer.candidate.base_address)
            .build(),
            state.remote.candidate.clone(),
        );
        let nominated_check = state
            .local_list()
            .matching_check(&unknown_pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        let check_id = nominated_check.conncheck_id;

        state.local_list().dump_check_state();

        send_next_check_and_response(&state.local.peer, &state.remote)
            .response_address(unknown_remote_peer.candidate.address)
            .perform(&mut state.local.checklist_set, now);
        let nominated_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed,
        ));

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_trickle_ice() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let now = Instant::ZERO;
        assert_eq!(state.local.component_id, 1);

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with no candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        let local_candidate = state.local.peer.candidate.clone();
        state.local_list().add_local_candidate(local_candidate);

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with only a local candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        let remote_candidate = state.remote.candidate.clone();
        state.local_list().add_remote_candidate(remote_candidate);

        // adding one local and one remote candidate that can be paired should have generated
        // the relevant waiting check. Not frozen because there is not other check with the
        // same foundation that already exists
        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);
        let check_id = check.conncheck_id;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);

        state.local_list().dump_check_state();

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_trickle_ice_no_remote_candidates_fail() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let local_candidate = state.local.peer.candidate.clone();

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::ZERO;

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with no candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state.local_list().add_local_candidate(local_candidate);
        state.local_list().end_of_local_candidates();

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with only a local candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state.local_list().end_of_remote_candidates();

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Failed),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::Completed));
        // a checklist with only a local candidates but no more possible candidates will error
        assert_eq!(state.local_list().state(), CheckListState::Failed);

        state.local.checklist_set.close(now);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_set_trickle_no_checks() {
        let _log = crate::tests::test_init_log();
        // ensure that a set of empty lists does not busyloop
        let mut set = ConnCheckListSet::builder(0, false)
            .trickle_ice(true)
            .build();
        let _list1_id = set.new_list();
        let _list2_id = set.new_list();

        let now = Instant::ZERO;
        let CheckListSetPollRet::WaitUntil(_now) = set.poll(now) else {
            unreachable!();
        };

        set.close(now);

        let CheckListSetPollRet::Completed = set.poll(now) else {
            unreachable!();
        };

        let CheckListSetPollRet::Closed = set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_incoming_request_while_local_in_progress() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let initial_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Frozen);
        let check_id = initial_check.conncheck_id;

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::ZERO;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // send the conncheck (unanswered)
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));
        let Some(_) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!()
        };
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::InProgress);
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        let mut remote_agent = state.remote.stun_agent();
        let local_addr = state.local.peer.stun_agent().local_addr();
        let transmit = remote_generate_check(&state.remote, &mut remote_agent, local_addr, now);

        info!("sending request");
        let reply =
            state
                .local
                .checklist_set
                .incoming_data(state.local.checklist_id, 1, transmit, now);
        assert!(reply.handled);
        // eat the success response
        let Some(_) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!()
        };
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        // after the remote has sent the check, the previous check should still be in the same
        // state
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::InProgress);
        // TODO: check for retransmit cancellation

        // a new triggered check should have been created
        let triggered_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_ne!(check_id, triggered_check.conncheck_id);
        let check_id = triggered_check.conncheck_id;
        info!("perform triggered check");
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let triggered_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_check_double_triggered() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().controlling(false).build();

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let initial_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Frozen);
        let check_id = initial_check.conncheck_id;

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::ZERO;

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // send the conncheck, reply with ROLE_CONFLICT
        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::ROLE_CONFLICT)
            .perform(&mut state.local.checklist_set, now);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Failed);

        // then hold onto the triggered transmit which removes the check from the triggered queue
        let triggered_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        let check_id = triggered_check.conncheck_id;
        let pair = triggered_check.pair.clone();
        assert!(state.local_list().is_triggered(&pair));
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let Some(_) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!()
        };
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        // receive a normal request as if the remote is doing its own possibly triggered check.
        // The handling of this will add another triggered check entry.
        let mut remote_agent = state.remote.stun_agent();
        let local_addr = state.local.peer.stun_agent().local_addr();
        let transmit = remote_generate_check(&state.remote, &mut remote_agent, local_addr, now);

        info!("sending request");
        let reply =
            state
                .local
                .checklist_set
                .incoming_data(state.local.checklist_id, 1, transmit, now);
        assert!(reply.handled);
        // eat the success response
        let Some(CheckListSetTransmit {
            checklist_id: _,
            transmit: _,
        }) = state.local.checklist_set.poll_transmit(now)
        else {
            unreachable!()
        };
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        // after the remote has sent the check, the previous check should still be in the same
        // state
        let triggered_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::InProgress);

        // a new triggered check should not have been created
        let triggered_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check_id, triggered_check.conncheck_id);

        // handling of this second triggered check used to produce a large wait that was exposed to
        // outside and could cause a visible stall.  Now that path panics if a check is attempted
        // to be started twice.
        info!("perform triggered check 2");
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        // we still haven't replied to the original triggered check
        let triggered_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(triggered_check.state(), CandidatePairState::InProgress);

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_trickle_ice_prflx_check_before_remote_credentials() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder()
            .controlling(true)
            .trickle_ice(true)
            .build();

        let local_candidate = state.local.peer.candidate.clone();
        state.local_list().add_local_candidate(local_candidate);

        let remote_credentials = generate_random_credentials();
        state.local.peer.remote_credentials = Some(remote_credentials.clone());
        state.remote.local_credentials = Some(remote_credentials.clone());
        let remote_peer = Peer::builder()
            .local_addr(state.remote.candidate.base_address)
            .foundation(&state.remote.candidate.foundation)
            .local_credentials(remote_credentials.clone())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let mut remote_agent = state.remote.stun_agent();
        let mut now = Instant::ZERO;
        let to = state.local.peer.candidate.base_address;
        let transmit = remote_generate_check(&remote_peer, &mut remote_agent, to, now);

        info!("sending prflx request");
        let reply =
            state
                .local
                .checklist_set
                .incoming_data(state.local.checklist_id, 1, transmit, now);
        assert!(reply.handled);

        let mut peer_reflexive_remote = state.remote.candidate.clone();
        peer_reflexive_remote.candidate_type = CandidateType::PeerReflexive;
        // XXX: implementation detail...
        peer_reflexive_remote.foundation = String::from("rflx");
        let pair = CandidatePair::new(state.local.peer.candidate.clone(), peer_reflexive_remote);

        let prflx_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(prflx_check.state(), CandidatePairState::Waiting);
        let check_id = prflx_check.conncheck_id;
        let ret = state.local.checklist_set.poll_transmit(now);
        // response to prflx request
        let Some(CheckListSetTransmit {
            checklist_id: _,
            transmit,
        }) = ret
        else {
            error!("{ret:?}");
            unreachable!()
        };
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, state.remote.candidate.base_address);
        let response = Message::from_bytes(&transmit.data).unwrap();
        response
            .validate_integrity(&MessageIntegrityCredentials::ShortTerm(
                state.local.peer.local_credentials.clone().unwrap().into(),
            ))
            .unwrap();

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // send the triggered conncheck which will fail due to incorrect credentials and be ignored
        send_next_check_and_response(&state.local.peer, &state.remote)
            .unhandled_reply()
            .perform(&mut state.local.checklist_set, now);
        let prflx_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(prflx_check.state(), CandidatePairState::InProgress);

        // correct remote credentials arrive
        info!("Correct remote credentials set");
        state.set_remote_credentials(remote_credentials);

        // send the updated check which should succeed
        match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::WaitUntil(new_now) => {
                now = new_now;
            }
            ret => {
                error!("{ret:?}");
                unreachable!()
            }
        }
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let prflx_check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(prflx_check.state(), CandidatePairState::Succeeded);

        state.check_nomination(&pair, now);

        state.local.checklist_set.close(now);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport: TransportType::Udp,
            local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, pair.local.address);
        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    fn turn_allocate(
        client: &mut TurnClient,
        server: &mut TurnServer,
        turn_alloc_addr: SocketAddr,
        now: Instant,
    ) {
        let transmit = client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        let transmit = server.recv(transmit, now).unwrap().build();
        let ret = client.recv(transmit, now);
        assert!(matches!(ret, TurnRecvRet::Handled));
        client.poll(now);
        let transmit = client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        assert!(server.recv(transmit, now).is_none());
        let TurnServerPollRet::AllocateSocketUdp {
            transport,
            local_addr,
            remote_addr,
            family,
        } = server.poll(now)
        else {
            unreachable!();
        };
        server.allocated_udp_socket(
            transport,
            local_addr,
            remote_addr,
            family,
            Ok(turn_alloc_addr),
            now,
        );
        let transmit = server.poll_transmit(now).unwrap();
        let ret = client.recv(transmit, now);
        assert!(matches!(ret, TurnRecvRet::Handled));
        assert!(client.relayed_addresses().count() > 0);
    }

    fn set_handle_permission(
        set: &mut ConnCheckListSet,
        turn_server: &mut TurnServer,
        now: Instant,
    ) -> Instant {
        let Some(transmit) = set.poll_transmit(now) else {
            unreachable!()
        };
        let msg = Message::from_bytes(&transmit.transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);
        let checklist_id = transmit.checklist_id;
        let transmit = turn_server.recv(transmit.transmit, now).unwrap().build();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);

        let transmit = Transmit::new(
            Data::from(transmit.data.as_slice()),
            transmit.transport,
            transmit.from,
            transmit.to,
        );
        set.incoming_data(checklist_id, 1, transmit, now);
        match set.poll(now) {
            CheckListSetPollRet::WaitUntil(now) => now,
            ret => {
                error!("{ret:?}");
                unreachable!()
            }
        }
    }

    fn turn_allocate_udp(client_transport: TransportType) {
        let local_addr = "127.0.0.1:1".parse::<SocketAddr>().unwrap();
        let turn_addr = "127.0.0.1:3478".parse::<SocketAddr>().unwrap();
        let turn_alloc_addr = "127.0.0.1:3000".parse::<SocketAddr>().unwrap();
        let turn_credentials = TurnCredentials::new("tuser", "tpass");
        let mut state = FineControl::builder()
            .local_candidate(
                Candidate::builder(
                    1,
                    CandidateType::Relayed,
                    TransportType::Udp,
                    "0",
                    turn_alloc_addr,
                )
                .priority(8000)
                .base_address(local_addr)
                .related_address(turn_addr)
                .build(),
            )
            .trickle_ice(true)
            .build();

        let now = Instant::ZERO;
        let mut turn_server = TurnServer::new(client_transport, turn_addr, "realm".to_owned());
        turn_server.add_user(
            turn_credentials.username().to_owned(),
            turn_credentials.password().to_owned(),
        );
        let mut turn_client = match client_transport {
            TransportType::Udp => TurnClientUdp::allocate(
                local_addr,
                turn_addr,
                turn_credentials,
                &[AddressFamily::IPV4],
            )
            .into(),
            TransportType::Tcp => TurnClientTcp::allocate(
                local_addr,
                turn_addr,
                turn_credentials,
                &[AddressFamily::IPV4],
            )
            .into(),
        };
        turn_allocate(&mut turn_client, &mut turn_server, turn_alloc_addr, now);

        let remote_candidate = state.remote.candidate.clone();
        state.local_list().add_remote_candidate(remote_candidate);
        let local_candidate = state.local.peer.candidate.clone();
        state
            .local_list()
            .add_local_gathered_candidate(GatheredCandidate {
                candidate: local_candidate,
                turn_agent: Some(Box::new(turn_client)),
            });
        assert_eq!(state.local.component_id, 1);

        let now = set_handle_permission(&mut state.local.checklist_set, &mut turn_server, now);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::InProgress);
        let check_id = check.conncheck_id;

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .turn_server(&mut turn_server)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);

        // should have resulted in a nomination and therefore a triggered check (always a new
        // check in our implementation)
        let nominate_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        let pair = nominate_check.pair.clone();
        let check_id = nominate_check.conncheck_id;
        assert!(state.local_list().is_triggered(&pair));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .turn_server(&mut turn_server)
            .perform(&mut state.local.checklist_set, now);

        error!("nominated id {check_id:?}");
        let nominate_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one final tick attempt which should end the processing
        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));

        state.local.checklist_set.close(now);

        // no RemoveSocket until the TURN DELETE is handled
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!();
        };

        let checklist_id = transmit.checklist_id;
        let transmit = turn_server.recv(transmit.transmit, now).unwrap().build();
        let transmit = Transmit::new(
            Data::from(transmit.data.as_slice()),
            transmit.transport,
            transmit.from,
            transmit.to,
        );
        let reply = state
            .local
            .checklist_set
            .incoming_data(checklist_id, 1, transmit, now);
        assert!(reply.handled);

        let CheckListSetPollRet::RemoveSocket {
            checklist_id: _,
            component_id: 1,
            transport,
            local_addr: remove_local_addr,
            remote_addr: _,
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(transport, client_transport);
        assert_eq!(remove_local_addr, local_addr);

        let CheckListSetPollRet::Closed = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn turn_udp_allocate_udp() {
        let _log = crate::tests::test_init_log();
        turn_allocate_udp(TransportType::Udp);
    }

    #[test]
    fn turn_tcp_allocate_udp() {
        let _log = crate::tests::test_init_log();
        turn_allocate_udp(TransportType::Tcp);
    }

    #[test]
    fn turn_udp_delayed_create_permission() {
        let _log = crate::tests::test_init_log();
        let local_addr = "127.0.0.1:1".parse::<SocketAddr>().unwrap();
        let turn_addr = "127.0.0.1:3478".parse::<SocketAddr>().unwrap();
        let turn_alloc_addr = "127.0.0.1:3000".parse::<SocketAddr>().unwrap();
        let turn_credentials = TurnCredentials::new("tuser", "tpass");
        let mut state = FineControl::builder()
            .local_candidate(
                Candidate::builder(
                    1,
                    CandidateType::Relayed,
                    TransportType::Udp,
                    "0",
                    turn_alloc_addr,
                )
                .priority(8000)
                .base_address(local_addr)
                .related_address(turn_addr)
                .build(),
            )
            .trickle_ice(true)
            .build();

        let now = Instant::ZERO;
        let mut turn_server = TurnServer::new(TransportType::Udp, turn_addr, "realm".to_owned());
        turn_server.add_user(
            turn_credentials.username().to_owned(),
            turn_credentials.password().to_owned(),
        );
        let mut turn_client = TurnClientUdp::allocate(
            local_addr,
            turn_addr,
            turn_credentials,
            &[AddressFamily::IPV4],
        )
        .into();
        turn_allocate(&mut turn_client, &mut turn_server, turn_alloc_addr, now);

        let remote_candidate = state.remote.candidate.clone();
        state.local_list().add_remote_candidate(remote_candidate);
        let local_candidate = state.local.peer.candidate.clone();
        state
            .local_list()
            .add_local_gathered_candidate(GatheredCandidate {
                candidate: local_candidate,
                turn_agent: Some(Box::new(turn_client)),
            });
        assert_eq!(state.local.component_id, 1);

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Frozen);
        let check_id = check.conncheck_id;

        let Some(transmit) = state.local.checklist_set.poll_transmit(now) else {
            unreachable!()
        };
        let msg = Message::from_bytes(&transmit.transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);
        let checklist_id = transmit.checklist_id;
        let transmit = turn_server.recv(transmit.transmit, now).unwrap().build();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        let transmit = Transmit::new(
            Data::from(transmit.data.as_slice()),
            transmit.transport,
            transmit.from,
            transmit.to,
        );
        state
            .local
            .checklist_set
            .incoming_data(checklist_id, 1, transmit, now);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connecting),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .turn_server(&mut turn_server)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);

        // should have resulted in a nomination and therefore a triggered check (always a new
        // check in our implementation)
        let nominate_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        let pair = nominate_check.pair.clone();
        let check_id = nominate_check.conncheck_id;
        assert!(state.local_list().is_triggered(&pair));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .turn_server(&mut turn_server)
            .perform(&mut state.local.checklist_set, now);

        error!("nominated id {check_id:?}");
        let nominate_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event {
            checklist_id: _,
            event: ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        } = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one final tick attempt which should end the processing
        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));
    }
}
