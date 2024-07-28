// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Connectivity check module for checking a set of candidates for an appropriate candidate pair to
//! transfer data with.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::candidate::{Candidate, CandidatePair, CandidateType, TcpType, TransportType};
use crate::component::ComponentConnectionState;
use byteorder::{BigEndian, ByteOrder};
use stun_proto::agent::{
    HandleStunReply, StunAgent, StunAgentPollRet, StunError, TcpBuffer, Transmit,
};
use stun_proto::types::attribute::*;
use stun_proto::types::message::*;

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct StunAgentId(usize);

impl std::ops::Deref for StunAgentId {
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

impl std::fmt::Display for StunAgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// ICE Credentials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub ufrag: String,
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

/// A pair that has been selected for a component
#[derive(Debug, Clone)]
pub struct SelectedPair {
    candidate_pair: CandidatePair,
    local_stun_agent: StunAgentId,
}
impl SelectedPair {
    /// Create a new [`SelectedPair`].  The pair and stun agent must be compatible.
    pub(crate) fn new(candidate_pair: CandidatePair, local_stun_agent: StunAgentId) -> Self {
        Self {
            candidate_pair,
            local_stun_agent,
        }
    }

    /// The pair for this [`SelectedPair`]
    pub fn candidate_pair(&self) -> &CandidatePair {
        &self.candidate_pair
    }

    /// The local STUN agent for this [`SelectedPair`]
    pub(crate) fn stun_agent_id(&self) -> StunAgentId {
        self.local_stun_agent
    }
}

/// Return values when handling received data
#[derive(Debug)]
pub enum HandleRecvReply {
    /// The data has been handled internally
    Handled,
    /// User data has been provided and should be handled further
    Data(Vec<u8>, SocketAddr),
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

impl std::fmt::Display for CandidatePairState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&format!("{:?}", self))
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

impl std::ops::Deref for ConnCheckId {
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

impl std::fmt::Display for ConnCheckId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

struct ConnCheck {
    conncheck_id: ConnCheckId,
    checklist_id: usize,
    nominate: bool,
    pair: CandidatePair,
    variant: ConnCheckVariant,
    controlling: bool,
    state: CandidatePairState,
    stun_request: Option<TransactionId>,
}

impl std::fmt::Debug for ConnCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnCheck")
            .field("conncheck_id", &self.conncheck_id)
            .field("checklist_id", &self.checklist_id)
            .field("nominate", &self.nominate)
            .field("pair", &self.pair)
            .finish()
    }
}

impl ConnCheck {
    fn new(
        checklist_id: usize,
        pair: CandidatePair,
        agent: StunAgentId,
        nominate: bool,
        controlling: bool,
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
        }
    }

    fn new_tcp(
        checklist_id: usize,
        pair: CandidatePair,
        nominate: bool,
        controlling: bool,
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
        }
    }

    fn clone_with_pair_nominate(
        conncheck: &ConnCheck,
        checklist_id: usize,
        pair: CandidatePair,
        new_nominate: bool,
    ) -> ConnCheck {
        match &conncheck.variant {
            ConnCheckVariant::Agent(agent) => ConnCheck::new(
                checklist_id,
                pair,
                agent.clone(),
                new_nominate,
                conncheck.controlling,
            ),
            _ => unreachable!(),
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
            if state == CandidatePairState::Succeeded || state == CandidatePairState::Failed {
                trace!("aborting recv");
                if let Some(ref _stun_request) = self.stun_request {
                    // FIXME
                    // stun_request.cancel_retransmissions();
                }
            }
            self.state = state;
        }
    }

    fn nominate(&self) -> bool {
        self.nominate
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            self.state
        )
    )]
    fn cancel(&mut self) {
        self.set_state(CandidatePairState::Failed);
        if let Some(_stun_request) = self.stun_request.take() {
            debug!(conncheck.id = *self.conncheck_id, "cancelling conncheck");
            // FIXME
            // stun_request.cancel();
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            self.state
        )
    )]
    fn cancel_retransmissions(&self) {
        if let Some(_stun_request) = self.stun_request.as_ref() {
            debug!(
                conncheck.id = *self.conncheck_id,
                "cancelling conncheck retransmissions"
            );
            // FIXME
            // stun_request.cancel_retransmissions();
        }
    }

    fn generate_stun_request<'a>(
        pair: &CandidatePair,
        nominate: bool,
        controlling: bool,
        tie_breaker: u64,
        local_credentials: Credentials,
        remote_credentials: Credentials,
    ) -> Result<MessageBuilder<'a>, StunError> {
        let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;

        // XXX: this needs to be the priority as if the candidate was peer-reflexive
        let mut msg = Message::builder_request(BINDING);
        msg.add_attribute(&Priority::new(pair.local.priority))?;
        if controlling {
            msg.add_attribute(&IceControlling::new(tie_breaker))?;
        } else {
            msg.add_attribute(&IceControlled::new(tie_breaker))?;
        }
        if nominate {
            msg.add_attribute(&UseCandidate::new())?;
        }
        let username = Username::new(&username)?;
        msg.add_attribute(&username)?;
        msg.add_message_integrity(
            &MessageIntegrityCredentials::ShortTerm(remote_credentials.clone().into()),
            IntegrityAlgorithm::Sha1,
        )?;
        msg.add_fingerprint()?;
        Ok(msg.into_owned())
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
struct CheckTcpBuffer {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    tcp_buffer: TcpBuffer,
}

/// A list of connectivity checks for an ICE stream
#[derive(Debug)]
pub struct ConnCheckList {
    checklist_id: usize,
    state: CheckListState,
    component_ids: Vec<usize>,
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
    agents: Vec<(StunAgentId, StunAgent)>,
    tcp_buffers: Vec<CheckTcpBuffer>,
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

#[derive(Debug, Clone)]
struct TcpListenCandidate {}

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

fn response_add_credentials(
    response: &mut MessageBuilder<'_>,
    local_credentials: MessageIntegrityCredentials,
) -> Result<(), StunError> {
    response.add_message_integrity(&local_credentials, IntegrityAlgorithm::Sha1)?;
    response.add_fingerprint()?;
    Ok(())
}
fn binding_success_response<'a>(
    msg: &Message<'_>,
    from: SocketAddr,
    local_credentials: MessageIntegrityCredentials,
) -> Result<MessageBuilder<'a>, StunError> {
    let mut response = Message::builder_success(msg);
    response.add_attribute(&XorMappedAddress::new(from, msg.transaction_id()))?;
    response_add_credentials(&mut response, local_credentials)?;
    Ok(response)
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

fn generate_random_ice_string(alphabet: &[u8], length: usize) -> String {
    use rand::{seq::SliceRandom, thread_rng};
    let mut rng = thread_rng();
    String::from_utf8(
        (0..length)
            .map(|_| *alphabet.choose(&mut rng).unwrap())
            .collect(),
    )
    .unwrap()
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
            component_ids: vec![],
            local_credentials: generate_random_credentials(),
            remote_credentials: generate_random_credentials(),
            local_candidates: vec![],
            remote_candidates: vec![],
            triggered: VecDeque::new(),
            pairs: VecDeque::new(),
            valid: vec![],
            nominated: vec![],
            controlling,
            trickle_ice,
            local_end_of_candidates: false,
            remote_end_of_candidates: false,
            events: VecDeque::new(),
            agents: vec![],
            tcp_buffers: vec![],
        }
    }

    fn state(&self) -> CheckListState {
        self.state
    }

    /// Set the local [`Credentials`] for this checklist
    pub fn set_local_credentials(&mut self, credentials: Credentials) {
        self.local_credentials = credentials;
    }

    /// Set the remote [`Credentials`] for this checklist
    pub fn set_remote_credentials(&mut self, credentials: Credentials) {
        self.remote_credentials = credentials;
    }

    /// Add a component id to this checklist
    pub fn add_component(&mut self, component_id: usize) {
        if self.component_ids.iter().any(|&id| id == component_id) {
            panic!(
                "Component with ID {} already exists in checklist!",
                component_id
            );
        };
        self.component_ids.push(component_id);
    }

    fn poll_event(&mut self) -> Option<ConnCheckEvent> {
        self.events.pop_back()
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
        self.agents.push((agent_id, agent));
        (agent_id, self.agents.len() - 1)
    }

    pub(crate) fn find_agent_for_5tuple(
        &self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&(StunAgentId, StunAgent)> {
        self.agents.iter().find(|a| {
            let a = &a.1;
            match transport {
                TransportType::Udp => {
                    a.local_addr() == local && a.transport() == TransportType::Udp
                }
                TransportType::Tcp => {
                    a.local_addr() == local
                        && a.transport() == TransportType::Tcp
                        && a.remote_addr().unwrap() == remote
                }
            }
        })
    }

    pub(crate) fn agent_by_id(&self, id: StunAgentId) -> Option<&StunAgent> {
        self.agents
            .iter()
            .find_map(|(needle, agent)| if id == *needle { Some(agent) } else { None })
    }

    fn mut_agent_by_id(&mut self, id: StunAgentId) -> Option<&mut StunAgent> {
        self.agents
            .iter_mut()
            .find_map(|(needle, agent)| if id == *needle { Some(agent) } else { None })
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
                let a = &a.1;
                match candidate.transport_type {
                    TransportType::Udp => {
                        a.local_addr() == candidate.base_address
                            && a.transport() == TransportType::Udp
                    }
                    _ => false,
                }
            })
            .map(|a| a.0)
        {
            return (agent_id, self.agent_by_id(agent_id).unwrap());
        }
        let mut agent =
            StunAgent::builder(candidate.transport_type, candidate.base_address).build();
        agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
            local_credentials.clone().into(),
        ));
        agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
            remote_credentials.clone().into(),
        ));
        let (agent_id, agent_idx) = self.add_agent(agent);
        (agent_id, &self.agents[agent_idx].1)
    }

    /// Add a local candidate to this checklist.
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
    pub fn add_local_candidate(&mut self, local: Candidate) {
        let (local_credentials, remote_credentials) = {
            if self.local_end_of_candidates {
                panic!("Attempt made to add a local candidate after end-of-candidate received");
            }
            let existing = self
                .component_ids
                .iter()
                .find(|&id| id == &local.component_id);
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

        info!("adding {:?}", local);

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
        self.generate_checks();
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
        if !self.component_ids.iter().any(|&v| v == remote.component_id) {
            self.component_ids.push(remote.component_id);
        }
        self.remote_candidates.push(remote);
        self.generate_checks();
        self.dump_check_state();
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, thawn_foundations)
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn initial_thaw(&mut self, thawn_foundations: &mut Vec<String>) {
        debug!("list state change from {:?} to Running", self.state);
        self.state = CheckListState::Running;

        let _: Vec<_> = self
            .pairs
            .iter_mut()
            .map(|check| {
                check.set_state(CandidatePairState::Frozen);
            })
            .collect();

        // get all the candidates that don't match any of the already thawn foundations
        let mut maybe_thaw: Vec<_> = self
            .pairs
            .iter_mut()
            .filter(|check| {
                !thawn_foundations
                    .iter()
                    .any(|foundation| &check.pair.foundation() == foundation)
            })
            .collect();
        // sort by component_id
        maybe_thaw
            .sort_unstable_by(|a, b| a.pair.local.component_id.cmp(&b.pair.local.component_id));

        // only keep the first candidate for a given foundation which should correspond to the
        // lowest component_id
        let mut seen_foundations = vec![];
        maybe_thaw.retain(|check| {
            if seen_foundations
                .iter()
                .any(|foundation| &check.pair.foundation() == foundation)
            {
                false
            } else {
                seen_foundations.push(check.pair.foundation());
                true
            }
        });

        // set them to waiting
        let _: Vec<_> = maybe_thaw
            .iter_mut()
            .map(|check| {
                check.set_state(CandidatePairState::Waiting);
            })
            .collect();

        // update the foundations seen for the next check list
        thawn_foundations.extend(seen_foundations);
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

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn next_frozen(&mut self, from_foundations: &[String]) -> Option<&mut ConnCheck> {
        self.pairs
            .iter_mut()
            .filter_map(|check| {
                if check.state() == CandidatePairState::Frozen {
                    from_foundations
                        .iter()
                        .find(|&f| f == &check.pair.foundation())
                        .and(Some(check))
                } else {
                    None
                }
            })
            .map(|check| {
                check.set_state(CandidatePairState::Waiting);
                check
            })
            .next()
    }

    fn foundations(&self) -> std::collections::HashSet<String> {
        let mut foundations = std::collections::HashSet::new();
        let _: Vec<_> = self
            .pairs
            .iter()
            .inspect(|check| {
                foundations.insert(check.pair.foundation());
            })
            .collect();
        foundations
    }

    fn foundation_not_waiting_in_progress(&self, foundation: &str) -> bool {
        self.pairs.iter().fold(true, |accum, elem| {
            if accum && elem.pair.foundation() == foundation {
                let state = elem.state();
                accum
                    && state != CandidatePairState::InProgress
                    && state != CandidatePairState::Waiting
            } else {
                accum
            }
        })
    }

    /// The list of local candidates currently configured for this checklist
    pub fn local_candidates(&self) -> Vec<Candidate> {
        self.local_candidates
            .iter()
            .map(|local| local.candidate.clone())
            .collect()
    }

    /// The list of remote candidates currently configured for this checklist
    pub fn remote_candidates(&self) -> Vec<Candidate> {
        self.remote_candidates.to_vec()
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
                debug!("removing existing triggered {:?}", existing);
            } else {
                debug!("not adding duplicate triggered check");
                return;
            }
        }
        debug!("adding triggered check {:?}", check);
        self.triggered.push_front(check.conncheck_id)
    }

    fn foundation_has_check_state(&self, foundation: &str, state: CandidatePairState) -> bool {
        self.pairs
            .iter()
            .any(|check| check.pair.foundation() == foundation && check.state() == state)
    }

    fn thawn_foundations(&mut self) -> Vec<String> {
        // XXX: cache this?
        let mut thawn_foundations = vec![];
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
        let mut checks = vec![];
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
        let mut redundant_pairs = vec![];

        for local in self.local_candidates.iter() {
            for remote in self.remote_candidates.iter() {
                if local.candidate.can_pair_with(remote) {
                    let pair = CandidatePair::new(local.candidate.clone(), remote.clone());
                    let component_id = self
                        .component_ids
                        .iter()
                        .find(|&id| id == &local.candidate.component_id)
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
                                LocalCandidateVariant::TcpActive => {}
                                LocalCandidateVariant::TcpListener => {}
                            }
                        } else {
                            //trace!("not adding redundant pair {:?}", pair);
                        }
                    } else {
                        pairs.push(pair.clone());
                        match local.variant {
                            LocalCandidateVariant::Agent(ref agent_id) => {
                                checks.push(ConnCheck::new(
                                    self.checklist_id,
                                    pair.clone(),
                                    *agent_id,
                                    false,
                                    self.controlling,
                                ));
                            }
                            LocalCandidateVariant::TcpActive => {
                                checks.push(ConnCheck::new_tcp(
                                    self.checklist_id,
                                    pair.clone(),
                                    false,
                                    self.controlling,
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

        let mut thawn_foundations = if self.trickle_ice {
            self.thawn_foundations()
        } else {
            vec![]
        };
        for mut check in checks {
            if self.trickle_ice {
                // for the trickle-ICE case, if the foundation does not already have a waiting check,
                // then we use this check as the first waiting check
                // RFC 8838 Section 12 Rule 1, 2, and 3
                if !thawn_foundations
                    .iter()
                    .any(|foundation| check.pair.foundation() == *foundation)
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

    #[tracing::instrument(level = "trace", ret, skip(self, pair))]
    fn matching_check(&self, pair: &CandidatePair, nominate: Nominate) -> Option<&ConnCheck> {
        self.pairs
            .iter()
            .find(|&check| Self::check_is_equal(check, pair, nominate))
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
        trace!("adding check {:?}", check);

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
    }

    fn set_controlling(&mut self, controlling: bool) {
        self.controlling = controlling;
        // changing the controlling (and therefore priority) requires resorting
        self.pairs.make_contiguous().sort_by(|a, b| {
            a.pair
                .priority(self.controlling)
                .cmp(&b.pair.priority(self.controlling))
                .reverse()
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id,
            pair = ?pair,
        )
    )]
    fn add_valid(&mut self, conncheck_id: ConnCheckId, pair: &CandidatePair) {
        if pair.local.transport_type == TransportType::Tcp
            && pair.local.tcp_type == Some(TcpType::Passive)
            && pair.local.address.port() == 9
        {
            trace!("not adding local passive tcp candidate without a valid port");
        }
        trace!("adding {:?}", pair);
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
        if !self.trickle_ice || self.local_end_of_candidates && self.remote_end_of_candidates {
            debug!("all candidates have arrived");
            let any_not_failed = self
                .component_ids
                .iter()
                .fold(true, |accum, &component_id| {
                    if !accum {
                        !accum
                    } else {
                        let ret = self.pairs.iter().any(|check| {
                            if check.pair.local.component_id == component_id {
                                check.state() != CandidatePairState::Failed
                            } else {
                                false
                            }
                        });
                        trace!("component {component_id} has any non-failed check:{ret}");
                        ret
                    }
                });
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
                candidate_pair_is_same_connection(&check.pair, pair) && check.nominate
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
            let component_id = self
                .component_ids
                .iter()
                .find(|&id| id == &pair.local.component_id)
                .cloned();
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
                } else if check.pair.local.component_id == pair.local.component_id {
                    check.cancel_retransmissions();
                    false
                } else {
                    true
                }
            });
            // XXX: do we also need to clear self.valid?
            // o Once candidate pairs for each component of a data stream have been
            //   nominated, and the state of the checklist associated with the data
            //   stream is Running, the ICE agent sets the state of the checklist
            //   to Completed.
            let all_nominated = self.component_ids.iter().all(|&component_id| {
                self.nominated
                    .iter()
                    .filter_map(|&check_id| self.check_by_id(check_id))
                    .any(|check| check.pair.local.component_id == component_id)
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
                    vec![],
                    |mut component_ids_selected, &check_id| {
                        let Some(check) = self.check_by_id(check_id) else {
                            return component_ids_selected;
                        };
                        let check_component_id = check.pair.local.component_id;
                        // Only nominate one valid candidatePair
                        if component_ids_selected
                            .iter()
                            .any(|&comp_id| comp_id == check_component_id)
                        {
                            return component_ids_selected;
                        }
                        if let Some(component_id) = component_id {
                            let agent_id = check.agent_id().unwrap();
                            self.events.push_front(ConnCheckEvent::SelectedPair(
                                component_id,
                                Box::new(SelectedPair::new(pair.clone(), agent_id)),
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
            warn!("unknown nomination");
        }
    }

    fn try_nominate(&mut self) {
        let retriggered: Vec<_> = self
            .component_ids
            .iter()
            .map(|&component_id| {
                let nominated = self.pairs.iter().find(|check| check.nominate());
                nominated.or({
                    let mut valid: Vec<_> = self
                        .valid
                        .iter()
                        .filter_map(|&check_id| self.check_by_id(check_id))
                        .filter(|check| {
                            check.pair.local.component_id == component_id
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
                                                         // find the local stun agent for this pair
                    if check.nominate() {
                        trace!(
                            "already have nominate check for component {}",
                            check.pair.local.component_id
                        );
                        None
                    } else {
                        let mut check = ConnCheck::clone_with_pair_nominate(
                            check,
                            self.checklist_id,
                            check.pair.clone(),
                            true,
                        );
                        check.set_state(CandidatePairState::Waiting);
                        debug!("attempting nomination with check {:?}", check);
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
        let mut s = format!("checklist {}", self.checklist_id);
        for pair in self.pairs.iter() {
            use std::fmt::Write as _;
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
        warn!("conncheck failure: {:?}", conncheck);
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
            candidate.transport_type == transport && candidate.base_address == addr
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
            last_send_time: Instant::now() - ConnCheckListSet::MINIMUM_SET_TICK,
            pending_transmits: Default::default(),
            pending_messages: Default::default(),
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
    last_send_time: Instant,
    pending_transmits: VecDeque<(usize, usize, Transmit<'static>)>,
    pending_messages: VecDeque<(
        usize,
        usize,
        StunAgentId,
        MessageBuilder<'static>,
        SocketAddr,
    )>,
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

    fn handle_stun(
        &mut self,
        checklist_i: usize,
        msg: Message<'_>,
        transmit: &Transmit,
        agent_id: StunAgentId,
    ) -> Result<Option<HandleRecvReply>, StunError> {
        let Some(agent) = self.checklists[checklist_i].mut_agent_by_id(agent_id) else {
            return Ok(None);
        };
        let local_credentials = agent.local_credentials();
        match agent.handle_stun(msg, transmit.from) {
            HandleStunReply::Drop => (),
            HandleStunReply::StunResponse(response) => {
                self.handle_stun_response(checklist_i, response, transmit.from)?;
            }
            HandleStunReply::IncomingStun(request) => {
                if request.has_method(BINDING) {
                    let Some(local_cand) = self.checklists[checklist_i]
                        .find_local_candidate(transmit.transport, transmit.to)
                    else {
                        warn!("Could not find local candidate for incoming data");
                        return Err(StunError::ResourceNotFound);
                    };

                    let checklist_id = self.checklists[checklist_i].checklist_id;
                    if let Some(response) = self.handle_binding_request(
                        checklist_i,
                        &local_cand,
                        agent_id,
                        &request,
                        transmit.from,
                        local_credentials.ok_or(StunError::ResourceNotFound)?,
                    )? {
                        self.pending_messages.push_back((
                            checklist_id,
                            local_cand.component_id,
                            agent_id,
                            response.into_owned(),
                            transmit.from,
                        ));
                        return Ok(Some(HandleRecvReply::Handled));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Provide received data to handle.  The returned values indicate what to do with the data.
    ///
    /// If [`HandleRecvReply::Handled`] is returned, then [`ConnCheckListSet::poll`] should be
    /// called at the earliest opportunity.
    #[tracing::instrument(
        name = "conncheck_incoming_data",
        level = "trace",
        err,
        ret,
        skip(self, transmit)
        fields(
            transport = %transmit.transport,
            from = %transmit.from,
            to = %transmit.to,
        )
    )]
    pub fn incoming_data(
        &mut self,
        checklist_id: usize,
        transmit: &Transmit,
    ) -> Result<Vec<HandleRecvReply>, StunError> {
        let checklist_i = self
            .checklists
            .iter()
            .position(|cl| cl.checklist_id == checklist_id)
            .ok_or(StunError::ResourceNotFound)?;
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

        let mut ret = vec![];
        match transmit.transport {
            TransportType::Udp => match Message::from_bytes(&transmit.data) {
                Ok(msg) => {
                    if let Some(reply) = self.handle_stun(checklist_i, msg, transmit, agent_id)? {
                        ret.push(reply);
                    }
                }
                Err(_) => {
                    if let Some(agent) = self.checklists[checklist_i].agent_by_id(agent_id) {
                        if agent.is_validated_peer(transmit.from) {
                            ret.push(HandleRecvReply::Data(transmit.data.to_vec(), transmit.from));
                        }
                    }
                }
            },
            TransportType::Tcp => {
                let tcp_buffer_idx = if let Some(tcp_buffer_idx) = self.checklists[checklist_i]
                    .tcp_buffers
                    .iter_mut()
                    .position(|tcp| {
                        tcp.remote_addr == transmit.from && tcp.local_addr == transmit.to
                    }) {
                    tcp_buffer_idx
                } else {
                    self.checklists[checklist_i]
                        .tcp_buffers
                        .push(CheckTcpBuffer {
                            local_addr: transmit.from,
                            remote_addr: transmit.to,
                            tcp_buffer: Default::default(),
                        });
                    self.checklists[checklist_i].tcp_buffers.len() - 1
                };
                self.checklists[checklist_i].tcp_buffers[tcp_buffer_idx]
                    .tcp_buffer
                    .push_data(transmit.data());
                while let Some(data) = self.checklists[checklist_i].tcp_buffers[tcp_buffer_idx]
                    .tcp_buffer
                    .pull_data()
                {
                    match Message::from_bytes(&data) {
                        Ok(msg) => {
                            if let Some(reply) =
                                self.handle_stun(checklist_i, msg, transmit, agent_id)?
                            {
                                ret.push(reply);
                            }
                        }
                        Err(_) => {
                            if let Some(agent) = self.checklists[checklist_i].agent_by_id(agent_id)
                            {
                                if agent.is_validated_peer(transmit.from) {
                                    ret.push(HandleRecvReply::Data(data, transmit.from));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(ret)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_binding_request<'a>(
        &mut self,
        checklist_i: usize,
        local: &Candidate,
        agent_id: StunAgentId,
        msg: &Message,
        from: SocketAddr,
        local_credentials: MessageIntegrityCredentials,
    ) -> Result<Option<MessageBuilder<'a>>, StunError> {
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
        ) {
            // failure -> send error response
            return Ok(Some(error_msg));
        }
        let peer_nominating = if let Some(use_candidate_raw) = msg.raw_attribute(UseCandidate::TYPE)
        {
            if UseCandidate::from_raw(&use_candidate_raw).is_ok() {
                true
            } else {
                let response = Message::bad_request(msg);
                return Ok(Some(response));
            }
        } else {
            false
        };

        let priority = match msg.attribute::<Priority>() {
            Ok(p) => p.priority(),
            Err(_) => {
                let response = Message::bad_request(msg);
                return Ok(Some(response));
            }
        };

        let ice_controlling = msg.attribute::<IceControlling>();
        let ice_controlled = msg.attribute::<IceControlled>();

        /*
        if checklist.state == CheckListState::Completed && !peer_nominating {
            // ignore binding requests if we are completed
            trace!("ignoring binding request as we have completed");
            return Ok(None);
        }*/

        // validate username
        if let Ok(username) = msg.attribute::<Username>() {
            if !validate_username(username, &checklist.local_credentials) {
                warn!("binding request failed username validation -> UNAUTHORIZED");
                let mut response = Message::builder_error(msg);
                response.add_attribute(&ErrorCode::builder(ErrorCode::UNAUTHORIZED).build()?)?;
                return Ok(Some(response));
            }
        } else {
            // existence is checked above so can only fail when the username is invalid
            let response = Message::bad_request(msg);
            return Ok(Some(response));
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
                    let mut response = Message::builder_error(msg);
                    response
                        .add_attribute(&ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?)?;
                    response_add_credentials(&mut response, local_credentials)?;
                    return Ok(Some(response));
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
                    let mut response = Message::builder_error(msg);
                    response
                        .add_attribute(&ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?)?;
                    response_add_credentials(&mut response, local_credentials)?;
                    return Ok(Some(response));
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
                    builder = builder.tcp_type(Candidate::pair_tcp_type(local.tcp_type.unwrap()))
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
                        let mut new_check = ConnCheck::clone_with_pair_nominate(
                            &check,
                            checklist.checklist_id,
                            pair.clone(),
                            true,
                        );
                        checklist.add_check(check);
                        new_check.set_state(CandidatePairState::Waiting);
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
                    check.cancel_retransmissions();
                    let pair = check.pair.clone();
                    // TODO: ignore response timeouts

                    let mut new_check = ConnCheck::clone_with_pair_nominate(
                        &check,
                        checklist.checklist_id,
                        pair,
                        peer_nominating,
                    );
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
                    if peer_nominating && !check.nominate() {
                        check.cancel();
                        check = ConnCheck::clone_with_pair_nominate(
                            &check,
                            checklist.checklist_id,
                            check.pair.clone(),
                            peer_nominating,
                        );
                    }
                    check.set_state(CandidatePairState::Waiting);
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
            );
            check.set_state(CandidatePairState::Waiting);
            checklist.add_triggered(&check);
            checklist.add_check(check);
        }

        Ok(Some(binding_success_response(
            msg,
            from,
            local_credentials,
        )?))
    }

    fn check_success(
        &mut self,
        checklist_i: usize,
        conncheck_id: ConnCheckId,
        addr: SocketAddr,
        controlling: bool,
    ) -> Result<(), StunError> {
        let checklist = &mut self.checklists[checklist_i];
        let checklist_id = checklist.checklist_id;
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
        let ok_pair = pair.construct_valid(addr);
        let mut ok_check =
            ConnCheck::clone_with_pair_nominate(conncheck, checklist_id, ok_pair.clone(), false);

        if checklist.state != CheckListState::Running {
            debug!("checklist is not running, ignoring check response");
            return Ok(());
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
                return Ok(());
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
                        return Ok(());
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
                return Ok(());
            }
        }
        // Try and nominate some pair
        if controlling {
            checklist.try_nominate();
        }
        Ok(())
    }

    #[tracing::instrument(
        skip(self, response),
        fields(
            checklist_id = self.checklists[checklist_i].checklist_id,
            %response
        ),
    )]
    fn handle_stun_response(
        &mut self,
        checklist_i: usize,
        response: Message,
        from: SocketAddr,
    ) -> Result<(), StunError> {
        let checklist = &mut self.checklists[checklist_i];
        let checklist_id = checklist.checklist_id;
        // find conncheck
        let conncheck = checklist.mut_check_from_stun_response(response.transaction_id(), from);
        let conncheck = match conncheck {
            Some(conncheck) => conncheck,
            None => {
                checklist.dump_check_state();
                warn!("No existing check available, ignoring");
                return Ok(());
            }
        };
        let conncheck_id = conncheck.conncheck_id;

        // if response success:
        // if mismatched address -> fail
        /* FIXME
        if from != request.peer_address() {
            warn!(
                "response came from different ip {:?} than candidate {:?}",
                from,
                stun_request.peer_address()
            );
            checklist.check_response_failure(conncheck.clone());
        }*/

        // if response error -> fail TODO: might be a recoverable error!
        if response.has_class(MessageClass::Error) {
            warn!("error response {}", response);
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
                        self.controlling = new_role;
                        conncheck.cancel();
                        let mut conncheck = ConnCheck::clone_with_pair_nominate(
                            conncheck,
                            checklist_id,
                            conncheck.pair.clone(),
                            false,
                        );
                        conncheck.set_state(CandidatePairState::Waiting);
                        checklist.add_triggered(&conncheck);
                        checklist.add_check(conncheck);
                        self.checklists[checklist_i].remove_valid(&old_pair);
                    }
                    return Ok(());
                }
            }
            // FIXME: some failures are recoverable
            self.checklists[checklist_i].check_response_failure(conncheck_id);
        }

        if let Ok(xor) = response.attribute::<XorMappedAddress>() {
            let xor_addr = xor.addr(response.transaction_id());
            return self.check_success(checklist_i, conncheck_id, xor_addr, self.controlling);
        }

        self.checklists[checklist_i].check_response_failure(conncheck_id);
        Ok(())
    }

    fn perform_conncheck(
        &mut self,
        checklist_i: usize,
        conncheck_id: ConnCheckId,
        now: Instant,
    ) -> Result<CheckListSetPollRet, StunError> {
        let checklist_id = self.checklists[self.checklist_i].checklist_id;
        let checklist = &mut self.checklists[checklist_i];
        let local_credentials = checklist.local_credentials.clone();
        let remote_credentials = checklist.remote_credentials.clone();

        let conncheck = checklist.mut_check_by_id(conncheck_id).unwrap();

        trace!("performing connectivity {:?}", &conncheck);
        if conncheck.stun_request.is_some() {
            panic!("Attempt was made to start an already started check");
        }

        if let ConnCheckVariant::Tcp(_tcp) = &conncheck.variant {
            return Ok(CheckListSetPollRet::TcpConnect(
                checklist_id,
                conncheck.pair.local.component_id,
                conncheck.pair.local.base_address,
                conncheck.pair.remote.address,
            ));
        }
        let ConnCheckVariant::Agent(agent_id) = &conncheck.variant else {
            unreachable!();
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
        let remote_addr = conncheck.pair.remote.address;
        let component_id = conncheck.pair.local.component_id;

        let agent_id = *agent_id;
        let agent = checklist.mut_agent_by_id(agent_id).unwrap();

        let transmit = agent.send(stun_request, remote_addr, now).unwrap();
        Ok(CheckListSetPollRet::Transmit(
            checklist_id,
            component_id,
            transmit_send(transmit),
        ))
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
            let mut foundations = std::collections::HashSet::new();
            for checklist in self.checklists.iter() {
                for f in checklist.foundations() {
                    foundations.insert(f);
                }
            }
            let mut foundations_not_waiting_in_progress = std::collections::HashSet::new();
            let _: Vec<_> = foundations
                .into_iter()
                .map(|f| {
                    if self
                        .checklists
                        .iter()
                        .all(|checklist| checklist.foundation_not_waiting_in_progress(&f))
                    {
                        foundations_not_waiting_in_progress.insert(f);
                    }
                })
                .collect();
            let next: Vec<_> = foundations_not_waiting_in_progress.into_iter().collect();
            trace!("current foundations not waiting or in progress: {:?}", next);

            let checklist = &mut self.checklists[self.checklist_i];
            if let Some(check) = checklist.next_frozen(&next) {
                trace!("next check was a frozen check {:?}", check);
                check.set_state(CandidatePairState::InProgress);
                Some(check.conncheck_id)
            } else {
                trace!("no next check for stream");
                None
            }
        }
    }

    /// The minimum amount of time between iterations of a [`ConnCheckListSet`]
    pub const MINIMUM_SET_TICK: Duration = Duration::from_millis(50);

    /// Advance the set state machine.  Should be called repeatedly until
    /// [`CheckListSetPollRet::WaitUntil`] or [`CheckListSetPollRet::Completed`] is returned.
    #[tracing::instrument(name = "check_set_poll", level = "debug", ret, skip(self))]
    pub fn poll<'a>(&mut self, now: Instant) -> CheckListSetPollRet<'a> {
        if let Some((checklist_id, cid, transmit)) = self.pending_transmits.pop_back() {
            return CheckListSetPollRet::Transmit(checklist_id, cid, transmit);
        }
        while let Some((checklist_id, cid, agent_id, msg, to)) = self.pending_messages.pop_back() {
            let Some(checklist) = self.mut_list(checklist_id) else {
                continue;
            };
            let Some(agent) = checklist.mut_agent_by_id(agent_id) else {
                continue;
            };
            debug!("Sending response {msg:?} to {:?}", to);
            match agent.send(msg, to, now) {
                Ok(transmit) => {
                    return CheckListSetPollRet::Transmit(
                        checklist_id,
                        cid,
                        transmit_send(transmit),
                    )
                }
                Err(e) => warn!("error sending: {e}"),
            }
        }

        for checklist in self.checklists.iter_mut() {
            if let Some(event) = checklist.poll_event() {
                return CheckListSetPollRet::Event(checklist.checklist_id, event);
            }
        }

        let mut any_running = false;
        let mut all_failed = true;
        let start_idx = self.checklist_i;
        loop {
            let mut lowest_wait = Instant::now() + Duration::from_secs(99999);
            if self.checklists.is_empty() {
                // FIXME: will not be correct once we support adding streams at runtime
                warn!("No checklists");
                return CheckListSetPollRet::Completed;
            }
            self.checklist_i += 1;
            if self.checklist_i >= self.checklists.len() {
                self.checklist_i = 0;
            }
            let checklist = &mut self.checklists[self.checklist_i];
            let checklist_state = checklist.state();
            match checklist_state {
                CheckListState::Running => {
                    if self.last_send_time + Self::MINIMUM_SET_TICK > now {
                        return CheckListSetPollRet::WaitUntil(
                            self.last_send_time + Self::MINIMUM_SET_TICK,
                        );
                    }
                    any_running = true;
                    all_failed = false;
                    for idx in 0..checklist.pairs.len() {
                        let check = &mut checklist.pairs[idx];
                        if check.state != CandidatePairState::InProgress {
                            continue;
                        }
                        let Some(agent_id) = check.agent_id() else {
                            continue;
                        };
                        let component_id = check.pair.local.component_id;
                        let conncheck_id = check.conncheck_id;
                        let Some(agent) = checklist.mut_agent_by_id(agent_id) else {
                            continue;
                        };
                        trace!("polling existing stun request for check {conncheck_id}");
                        match agent.poll(now) {
                            StunAgentPollRet::TransactionTimedOut(_request) => {
                                let check = &mut checklist.pairs[idx];
                                check.set_state(CandidatePairState::Failed);
                            }
                            StunAgentPollRet::TransactionCancelled(_request) => {
                                let check = &mut checklist.pairs[idx];
                                check.set_state(CandidatePairState::Failed);
                            }
                            StunAgentPollRet::WaitUntil(wait) => {
                                if wait < lowest_wait {
                                    lowest_wait = wait.max(now + Self::MINIMUM_SET_TICK);
                                }
                            }
                            StunAgentPollRet::SendData(transmit) => {
                                self.last_send_time = now;
                                return CheckListSetPollRet::Transmit(
                                    checklist.checklist_id,
                                    component_id,
                                    transmit_send(transmit),
                                );
                            }
                        }
                    }
                }
                CheckListState::Completed => {
                    if all_failed {
                        all_failed = false;
                    }
                }
                CheckListState::Failed => (),
            }

            let conncheck_id = match self.next_check() {
                Some(c) => c,
                None => {
                    if start_idx == self.checklist_i {
                        // we looked at them all and none of the checklist could find anything to
                        // do
                        if !any_running {
                            return CheckListSetPollRet::Completed;
                        } else {
                            return CheckListSetPollRet::WaitUntil(lowest_wait);
                        }
                    } else {
                        continue;
                    }
                }
            };

            trace!("starting conncheck");
            match self.perform_conncheck(self.checklist_i, conncheck_id, now) {
                Ok(ret) => {
                    let ret = ret.into_owned();
                    self.last_send_time = now;
                    return ret;
                }
                Err(e) => warn!("failed to perform check: {e:?}"),
            }
        }
    }

    /// Report a reply (success or failure) to a TCP connection attempt.
    /// [`ConnCheckListSet::poll`] should be called at the earliest opportunity.
    #[tracing::instrument(
        level = "debug",
        skip(self, checklist_id, component_id),
        fields(
            checklist.id = checklist_id,
            component.id = component_id,
            ?agent,
        )
    )]
    pub fn tcp_connect_reply(
        &mut self,
        checklist_id: usize,
        component_id: usize,
        from: SocketAddr,
        to: SocketAddr,
        agent: Result<StunAgent, StunError>,
    ) {
        let Some(checklist) = self
            .checklists
            .iter_mut()
            .find(|checklist| checklist.checklist_id == checklist_id)
        else {
            debug!("no checklist with id {checklist_id}");
            return;
        };

        if checklist.agents.iter().map(|a| &a.1).any(|a| {
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
            if from != check.pair.local.base_address {
                continue;
            }
            if check.stun_request.is_some() {
                continue;
            }
            if check.pair.local.component_id != component_id {
                continue;
            }
            trace!("found check with id {} to set agent", check.conncheck_id);
            match agent {
                Ok(mut agent) => {
                    let mut new_pair = check.pair.clone();
                    new_pair.local.base_address = agent.local_addr();
                    new_pair.local.address = agent.local_addr();

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
                    let controlling = check.controlling;
                    let conncheck_id = check.conncheck_id;
                    let check_state = check.state;

                    let (agent_id, _agent_idx) = checklist.add_agent(agent);
                    self.pending_messages.push_front((
                        checklist_id,
                        component_id,
                        agent_id,
                        stun_request.into_owned(),
                        to,
                    ));

                    let mut new_check = ConnCheck::new(
                        checklist_id,
                        new_pair.clone(),
                        agent_id,
                        nominate,
                        controlling,
                    );
                    let is_triggered = checklist
                        .triggered
                        .iter()
                        .any(|&check_id| conncheck_id == check_id);
                    new_check.set_state(check_state);
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
}

/// Return values for polling a set of checklists.
#[derive(Debug)]
pub enum CheckListSetPollRet<'a> {
    /// Perform a TCP connection from the provided address to the provided address.  Report success
    /// or failure with `tcp_connect_reply()`.
    TcpConnect(usize, usize, SocketAddr, SocketAddr),
    /// Transmit data
    Transmit(usize, usize, Transmit<'a>),
    /// Wait until the specified time has passed.  Receiving handled data may cause a different
    /// value to be returned from `poll()`
    WaitUntil(Instant),
    /// An event has occured
    Event(usize, ConnCheckEvent),
    /// The set has completed all operations and has either succeeded or failed.  Further progress
    /// will not be made.
    Completed,
}

impl<'a> CheckListSetPollRet<'a> {
    fn into_owned<'b>(self) -> CheckListSetPollRet<'b> {
        match self {
            CheckListSetPollRet::Transmit(stream_id, component_id, transmit) => {
                CheckListSetPollRet::Transmit(stream_id, component_id, transmit.into_owned())
            }
            CheckListSetPollRet::Event(a, b) => CheckListSetPollRet::Event(a, b),
            CheckListSetPollRet::Completed => CheckListSetPollRet::Completed,
            CheckListSetPollRet::WaitUntil(a) => CheckListSetPollRet::WaitUntil(a),
            CheckListSetPollRet::TcpConnect(a, b, c, d) => {
                CheckListSetPollRet::TcpConnect(a, b, c, d)
            }
        }
    }
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

pub(crate) fn transmit_send(transmit: Transmit) -> Transmit<'static> {
    match transmit.transport {
        TransportType::Udp => transmit.into_owned(),
        TransportType::Tcp => {
            let mut data = Vec::with_capacity(transmit.data.len());
            data.resize(2, 0);
            BigEndian::write_u16(&mut data, transmit.data.len() as u16);
            data.extend_from_slice(&transmit.data);
            Transmit::new_owned(
                data.into_boxed_slice(),
                transmit.transport,
                transmit.from,
                transmit.to,
            )
        }
    }
}

#[cfg(test)]
mod tests {
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
        let locals = list.local_candidates();
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0], local.candidate);
        let remotes = list.remote_candidates();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0], remote.candidate);
    }

    // simplified version of ConnCheckList handle_binding_request that doesn't
    // update any state like ConnCheckList or even do peer-reflexive candidate
    // things
    fn handle_binding_request<'a>(
        agent: &StunAgent,
        local_credentials: &Credentials,
        msg: &Message,
        from: SocketAddr,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
    ) -> Result<MessageBuilder<'a>, StunError> {
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
        ) {
            // failure -> send error response
            return Ok(error_msg);
        }

        let ice_controlling = msg.attribute::<IceControlling>();
        let ice_controlled = msg.attribute::<IceControlled>();
        let username = msg.attribute::<Username>();
        let valid_username = username
            .map(|username| validate_username(username, local_credentials))
            .unwrap_or(false);

        let mut response = if ice_controlling.is_err() && ice_controlled.is_err() {
            warn!("missing ice controlled/controlling attribute");
            let mut response = Message::builder_error(msg);
            response.add_attribute(&ErrorCode::builder(ErrorCode::BAD_REQUEST).build()?)?;
            response
        } else if !valid_username {
            let mut response = Message::builder_error(msg);
            response.add_attribute(&ErrorCode::builder(ErrorCode::UNAUTHORIZED).build()?)?;
            response
        } else if let Some(error_code) = error_response {
            info!("responding with error {}", error_code);
            let mut response = Message::builder_error(msg);
            response.add_attribute(&ErrorCode::builder(error_code).build()?)?;
            response
        } else {
            let mut response = Message::builder_success(msg);
            response.add_attribute(&XorMappedAddress::new(
                response_address.unwrap_or(from),
                msg.transaction_id(),
            ))?;
            response
        };
        response.add_message_integrity(&local_stun_credentials, IntegrityAlgorithm::Sha1)?;
        response.add_fingerprint()?;
        Ok(response)
    }

    fn reply_to_conncheck<'b>(
        agent: &mut StunAgent,
        credentials: &Credentials,
        transmit: Transmit<'_>,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
        now: Instant,
    ) -> Option<Transmit<'b>> {
        // XXX: assumes that tcp framing is not in use
        let offset = match transmit.transport {
            TransportType::Udp => 0,
            TransportType::Tcp => 2,
        };
        match Message::from_bytes(&transmit.data[offset..]) {
            Err(e) => error!("error parsing STUN message {e:?}"),
            Ok(msg) => {
                debug!("received from {}: {}", transmit.to, msg);
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
                    return Some(transmit_send(transmit));
                }
            }
        }
        None
    }

    #[test]
    fn conncheck_list_transmit() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::now();

        let mut thawn_foundations = vec![];
        state.local_list().generate_checks();
        state.local_list().initial_thaw(&mut thawn_foundations);
        state.local_list().dump_check_state();

        let CheckListSetPollRet::Transmit(_checklist_id, _component_id, transmit) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!()
        };
        assert_eq!(
            transmit.transport,
            state.local.peer.candidate.transport_type
        );
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, state.remote.candidate.base_address);
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
        let local1 = Peer::builder()
            .priority(1)
            .local_addr("127.0.0.1:1".parse().unwrap())
            .build();
        let remote1 = Peer::builder()
            .priority(2)
            .local_addr("127.0.0.1:2".parse().unwrap())
            .build();
        let local2 = Peer::builder()
            .component_id(2)
            .priority(4)
            .local_addr("127.0.0.1:3".parse().unwrap())
            .build();
        let remote2 = Peer::builder()
            .component_id(2)
            .priority(6)
            .local_addr("127.0.0.1:4".parse().unwrap())
            .build();
        let local3 = Peer::builder()
            .priority(10)
            .local_addr("127.0.0.1:5".parse().unwrap())
            .build();
        let remote3 = Peer::builder()
            .priority(15)
            .local_addr("127.0.0.1:6".parse().unwrap())
            .build();

        list.add_local_candidate(local1.candidate.clone());
        list.add_remote_candidate(remote1.candidate.clone());
        list.add_local_candidate(local2.candidate.clone());
        list.add_remote_candidate(remote2.candidate.clone());
        list.add_local_candidate(local3.candidate.clone());
        list.add_remote_candidate(remote3.candidate.clone());

        list.generate_checks();
        let pair1 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
        let pair2 = CandidatePair::new(local2.candidate, remote2.candidate);
        let pair3 = CandidatePair::new(local3.candidate, remote1.candidate.clone());
        let pair4 = CandidatePair::new(local1.candidate.clone(), remote3.candidate);
        let pair5 = CandidatePair::new(local1.candidate, remote1.candidate);
        assert_list_contains_checks(list, vec![&pair1, &pair2, &pair3, &pair4, &pair5]);
    }

    #[test]
    fn checklists_initial_thaw() {
        let _log = crate::tests::test_init_log();
        let mut thawn = vec![];
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list1_id = set.new_list();
        let list2_id = set.new_list();

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
            .local_addr("127.0.0.1:3".parse().unwrap())
            .build();
        let remote2 = Peer::builder()
            .foundation("0")
            .component_id(2)
            .priority(4)
            .local_addr("127.0.0.1:4".parse().unwrap())
            .build();
        let local3 = Peer::builder()
            .foundation("1")
            .component_id(2)
            .priority(7)
            .local_addr("127.0.0.1:5".parse().unwrap())
            .build();
        let remote3 = Peer::builder()
            .foundation("1")
            .component_id(2)
            .priority(10)
            .local_addr("127.0.0.1:6".parse().unwrap())
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

        list1.generate_checks();
        assert_list_contains_checks(list1, vec![&pair1]);
        // thaw the first checklist with only a single pair will unfreeze that pair
        list1.initial_thaw(&mut thawn);
        assert_eq!(thawn.len(), 1);
        assert_eq!(&thawn[0], &pair1.foundation());
        let check1 = list1.matching_check(&pair1, Nominate::DontCare).unwrap();
        assert_eq!(check1.pair, pair1);
        assert_eq!(check1.state(), CandidatePairState::Waiting);

        let list2 = set.mut_list(list2_id).unwrap();
        list2.add_component(1);
        list2.add_component(2);
        list2.add_local_candidate(local2.candidate.clone());
        list2.add_remote_candidate(remote2.candidate.clone());
        list2.add_local_candidate(local3.candidate.clone());
        list2.add_remote_candidate(remote3.candidate.clone());

        list2.generate_checks();
        assert_list_contains_checks(list2, vec![&pair2, &pair3, &pair4, &pair5]);

        // thaw the second checklist with 2*2 pairs will unfreeze only the foundations not
        // unfrozen by the first checklist, which means unfreezing 3 pairs
        list2.initial_thaw(&mut thawn);
        assert_eq!(thawn.len(), 4);
        assert!(thawn.iter().any(|f| f == &pair2.foundation()));
        assert!(thawn.iter().any(|f| f == &pair3.foundation()));
        assert!(thawn.iter().any(|f| f == &pair4.foundation()));
        assert!(thawn.iter().any(|f| f == &pair5.foundation()));
        let check2 = list2.matching_check(&pair2, Nominate::DontCare).unwrap();
        assert_eq!(check2.pair, pair2);
        assert_eq!(check2.state(), CandidatePairState::Waiting);
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
    }

    struct NextCheckAndResponse<'next> {
        #[allow(unused)]
        local_peer: &'next Peer,
        remote_peer: &'next Peer,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
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

        fn perform(self, set: &mut ConnCheckListSet, now: Instant) {
            // perform one tick which will start a connectivity check with the peer
            let transmit = match set.poll(now) {
                CheckListSetPollRet::Transmit(_sid, _cid, transmit) => transmit,
                ret => {
                    error!("{ret:?}");
                    unreachable!()
                }
            };
            match set.poll(now) {
                CheckListSetPollRet::WaitUntil(_) => (),
                ret => {
                    error!("{ret:?}");
                    unreachable!()
                }
            }
            debug!("tick");

            // send a response (success or some kind of error like role-conflict)
            let reply = reply_to_conncheck(
                &mut self.remote_peer.stun_agent(),
                &self.remote_peer.local_credentials.clone().unwrap(),
                transmit,
                self.error_response,
                self.response_address,
                now,
            )
            .unwrap();
            info!("reply: {reply:?}");

            let checklist_ids: Vec<_> = set.checklists.iter().map(|cl| cl.checklist_id).collect();
            for checklist_id in checklist_ids.into_iter() {
                let reply = set.incoming_data(checklist_id, &reply).unwrap();
                trace!("reply: {reply:?}");
                if !reply.is_empty() {
                    assert!(matches!(reply[0], HandleRecvReply::Handled));
                }
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
            error_response: None,
            response_address: None,
        }
    }

    #[test]
    fn very_fine_control1() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let mut now = Instant::now();
        assert_eq!(state.local.component_id, 1);

        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);
        match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::WaitUntil(new_now) => {
                now = new_now;
            }
            ret => {
                error!("{ret:?}");
                unreachable!();
            }
        }

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
            .perform(&mut state.local.checklist_set, now);

        error!("nominated id {check_id:?}");
        let nominate_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one final tick attempt which should end the processing
        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));
    }

    #[test]
    fn role_conflict_response() {
        let _log = crate::tests::test_init_log();
        // start off in the controlled mode, otherwise, the test needs to do the nomination
        // check
        let mut state = FineControl::builder().controlling(false).build();
        let mut now = Instant::now();

        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::ROLE_CONFLICT)
            .perform(&mut state.local.checklist_set, now);
        state.local_list().dump_check_state();
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Failed);
        match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::WaitUntil(new_now) => {
                now = new_now;
            }
            ret => {
                error!("{ret:?}");
                unreachable!();
            }
        }

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
        match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::WaitUntil(new_now) => {
                now = new_now;
            }
            ret => {
                error!("{ret:?}");
                unreachable!();
            }
        }

        // should have resulted in a nomination and therefore a triggered check (always a new
        // check in our implementation)
        let nominate_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        let pair = nominate_check.pair.clone();
        assert!(state.local_list().is_triggered(&pair));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one final tick attempt which should end the processing
        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));
    }

    #[test]
    fn bad_username_conncheck() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::now();
        let local_list = state
            .local
            .checklist_set
            .mut_list(state.local.checklist_id)
            .unwrap();

        // set the wrong credentials and observe the failure
        let wrong_credentials =
            Credentials::new(String::from("wronguser"), String::from("wrongpass"));
        local_list.set_local_credentials(wrong_credentials);
        local_list.generate_checks();

        let pair = CandidatePair::new(
            state.local.peer.candidate.clone(),
            state.remote.candidate.clone(),
        );
        let check = local_list.matching_check(&pair, Nominate::False).unwrap();
        let check_id = check.conncheck_id;
        assert_eq!(check.state(), CandidatePairState::Frozen);

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        local_list.initial_thaw(&mut thawn);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);

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
        state.local_list().generate_checks();
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
        let now = Instant::now();

        let CheckListSetPollRet::TcpConnect(id, cid, from, to) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(from, state.local.peer.candidate.base_address);
        assert_eq!(to, state.remote.candidate.address);
        error!("tcp connect");

        state
            .local
            .checklist_set
            .tcp_connect_reply(id, cid, from, to, Ok(local_agent));
        error!("tcp connect replied");

        let CheckListSetPollRet::Transmit(id, cid, transmit) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, state.remote.candidate.address);
        error!("tcp transmit");

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit,
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
            .incoming_data(state.local.checklist_id, &response)
            .unwrap();
        error!("tcp replied");

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        let CheckListSetPollRet::Transmit(_id, _cid, transmit) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.into_owned(),
            None,
            None,
            now,
        ) else {
            unreachable!();
        };
        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &response)
            .unwrap();

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(selected_pair.candidate_pair, pair);
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
        state.local_list().generate_checks();
        let now = Instant::now();
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

        assert!(matches!(
            state
                .local
                .checklist_set
                .incoming_data(
                    state.local.checklist_id,
                    &transmit_send(
                        remote_agent
                            .send(request, state.local.peer.candidate.base_address, now)
                            .unwrap()
                    ),
                )
                .unwrap()[0],
            HandleRecvReply::Handled
        ));

        let check = state
            .local_list()
            .matching_check(&pair, Nominate::False)
            .unwrap();
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // success response
        let now = Instant::now();
        let CheckListSetPollRet::Transmit(id, cid, transmit) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, remote_cand.address);

        let response = Message::from_bytes(&transmit.data[2..]).unwrap();
        assert!(response.has_class(MessageClass::Success));

        // triggered check
        let CheckListSetPollRet::Transmit(id, cid, transmit) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, remote_cand.address);

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.into_owned(),
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
            .incoming_data(state.local.checklist_id, &response)
            .unwrap();
        error!("tcp replied");

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        // nominate triggered check
        let CheckListSetPollRet::Transmit(_id, _cid, transmit) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let Some(response) = reply_to_conncheck(
            &mut remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit.into_owned(),
            None,
            None,
            now,
        ) else {
            unreachable!();
        };

        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &response)
            .unwrap();

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert!(candidate_pair_is_same_connection(
            &selected_pair.candidate_pair,
            &pair
        ))
    }

    #[test]
    fn conncheck_incoming_prflx() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::now();

        // generate existing checks
        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Waiting);

        let unknown_remote_peer = Peer::builder()
            .local_addr("127.0.0.1:90".parse().unwrap())
            .foundation("1")
            .local_credentials(state.remote.local_credentials.clone().unwrap())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let mut remote_agent = unknown_remote_peer.stun_agent();

        // send a request from some unknown to the local agent address to produce a peer
        // reflexive candidate on the local agent
        let mut request = Message::builder_request(BINDING);
        request
            .add_attribute(&Priority::new(unknown_remote_peer.candidate.priority))
            .unwrap();
        request.add_attribute(&IceControlled::new(200)).unwrap();
        let username = Username::new(
            &(state.local.peer.local_credentials.clone().unwrap().ufrag
                + ":"
                + &state.remote.local_credentials.clone().unwrap().ufrag),
        )
        .unwrap();
        request.add_attribute(&username).unwrap();
        request
            .add_message_integrity(
                &remote_agent.local_credentials().unwrap(),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        request.add_fingerprint().unwrap();

        let local_addr = state.local.peer.stun_agent().local_addr();
        let transmit = remote_agent.send(request, local_addr, now).unwrap();

        info!("sending prflx request");
        let reply = state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &transmit)
            .unwrap();
        assert!(matches!(reply[0], HandleRecvReply::Handled));
        let CheckListSetPollRet::Transmit(_, _, transmit) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let response = Message::from_bytes(&transmit.data).unwrap();
        let HandleStunReply::StunResponse(response) =
            remote_agent.handle_stun(response, transmit.from)
        else {
            unreachable!();
        };
        assert_eq!(transmit.from, local_addr);
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

        // perform one tick which will start a connectivity check with the peer
        info!("perform triggered check");
        send_next_check_and_response(&state.local.peer, &unknown_remote_peer)
            .perform(&mut state.local.checklist_set, now);
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

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

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed,
        ));
    }

    #[test]
    fn conncheck_response_prflx() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();
        let now = Instant::now();

        // generate existing checks
        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Waiting);

        let unknown_remote_peer = Peer::builder()
            .foundation("1")
            .local_credentials(state.remote.local_credentials.clone().unwrap())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let remote_agent = unknown_remote_peer.stun_agent();

        // send the next connectivity check but response with a different xor-mapped-address
        // which should result in a PeerReflexive address being produced in the check list
        send_next_check_and_response(&state.local.peer, &state.remote)
            .response_address(remote_agent.local_addr())
            .perform(&mut state.local.checklist_set, now);
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Succeeded);

        // construct the peer reflexive pair
        let pair = CandidatePair::new(
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
            .matching_check(&pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        let check_id = nominated_check.conncheck_id;

        state.local_list().dump_check_state();

        send_next_check_and_response(&state.local.peer, &state.remote)
            .response_address(unknown_remote_peer.candidate.address)
            .perform(&mut state.local.checklist_set, now);
        let nominated_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed,
        ));
    }

    #[test]
    fn conncheck_trickle_ice() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let mut now = Instant::now();
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

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
        let check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(check.state(), CandidatePairState::Succeeded);

        state.local_list().dump_check_state();
        match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::WaitUntil(new_now) => {
                now = new_now;
            }
            ret => {
                error!("{ret:?}");
                unreachable!();
            }
        }

        // should have resulted in a nomination and therefore a triggered check (always a new
        // check in our implementation)
        let nominate_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        let check_id = nominate_check.conncheck_id;
        let pair = nominate_check.pair.clone();
        assert!(state.local_list().is_triggered(&pair));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        let nominate_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        // TODO: provide end-of-candidate notification and delay completed until we receive
        // end-of-candidate
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_cid, _selected_pair),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentConnectionState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        // perform one final tick attempt which should end the processing
        assert!(matches!(
            state.local.checklist_set.poll(now),
            CheckListSetPollRet::Completed
        ));
    }

    #[test]
    fn conncheck_trickle_ice_no_remote_candidates_fail() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let local_candidate = state.local.peer.candidate.clone();

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::now();
        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with no candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state.local_list().add_local_candidate(local_candidate);
        state.local_list().end_of_local_candidates();

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with only a local candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state.local_list().end_of_remote_candidates();

        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::Completed));
        // a checklist with only a local candidates but no more possible candidates will error
        assert_eq!(state.local_list().state(), CheckListState::Failed);
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

        let now = Instant::now();
        let CheckListSetPollRet::WaitUntil(_now) = set.poll(now) else {
            unreachable!();
        };
    }

    #[test]
    fn conncheck_incoming_request_while_local_in_progress() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().build();

        // generate existing checks
        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Waiting);

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::now();

        // send the conncheck (unanswered)
        let _transmit = match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::Transmit(_sid, _cid, transmit) => transmit,
            ret => {
                error!("{ret:?}");
                unreachable!()
            }
        };
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::InProgress);
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        let mut remote_agent = state.remote.stun_agent();
        let mut request = Message::builder_request(BINDING);
        request
            .add_attribute(&Priority::new(state.remote.candidate.priority))
            .unwrap();
        request.add_attribute(&IceControlled::new(200)).unwrap();
        let username = Username::new(
            &(state.local.peer.local_credentials.clone().unwrap().ufrag
                + ":"
                + &state.remote.local_credentials.clone().unwrap().ufrag),
        )
        .unwrap();
        request.add_attribute(&username).unwrap();
        request
            .add_message_integrity(
                &remote_agent.local_credentials().unwrap(),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        request.add_fingerprint().unwrap();

        let local_addr = state.local.peer.stun_agent().local_addr();
        let transmit = remote_agent.send(request, local_addr, now).unwrap();

        info!("sending request");
        let reply = state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &transmit)
            .unwrap();
        assert!(matches!(reply[0], HandleRecvReply::Handled));
        // eat the success response
        let CheckListSetPollRet::Transmit(_sid, _cid, _response) =
            state.local.checklist_set.poll(now)
        else {
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

        let nominated_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        info!("perform nominated check");
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        let set_ret = state.local.checklist_set.poll(now);
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_comp, selected_pair),
        ) = set_ret
        else {
            unreachable!();
        };
        assert_eq!(selected_pair.candidate_pair, pair);
        let set_ret = state.local.checklist_set.poll(now);
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_comp, ComponentConnectionState::Connected),
        ) = set_ret
        else {
            unreachable!();
        };
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::Completed));
        // a checklist with only a local candidates but no more possible candidates will error
        assert_eq!(state.local_list().state(), CheckListState::Completed);
    }

    #[test]
    fn conncheck_check_double_triggered() {
        let _log = crate::tests::test_init_log();
        let mut state = FineControl::builder().controlling(false).build();

        // generate existing checks
        state.local_list().generate_checks();

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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        let initial_check = state.local_list().check_by_id(check_id).unwrap();
        assert_eq!(initial_check.state(), CandidatePairState::Waiting);

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::now();

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
        let _transmit = match state.local.checklist_set.poll(now) {
            CheckListSetPollRet::Transmit(_sid, _cid, transmit) => transmit,
            ret => {
                error!("{ret:?}");
                unreachable!()
            }
        };
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        // receive a normal request as if the remote is doing its own possibly triggered check.
        // The handling of this will add another triggered check entry.
        let mut remote_agent = state.remote.stun_agent();
        let mut request = Message::builder_request(BINDING);
        request
            .add_attribute(&Priority::new(state.remote.candidate.priority))
            .unwrap();
        request.add_attribute(&IceControlled::new(200)).unwrap();
        let username = Username::new(
            &(state.local.peer.local_credentials.clone().unwrap().ufrag
                + ":"
                + &state.remote.local_credentials.clone().unwrap().ufrag),
        )
        .unwrap();
        request.add_attribute(&username).unwrap();
        request
            .add_message_integrity(
                &remote_agent.local_credentials().unwrap(),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        request.add_fingerprint().unwrap();

        let local_addr = state.local.peer.stun_agent().local_addr();
        let transmit = remote_agent.send(request, local_addr, now).unwrap();

        info!("sending request");
        let reply = state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &transmit)
            .unwrap();
        assert!(matches!(reply[0], HandleRecvReply::Handled));
        // eat the success response
        let CheckListSetPollRet::Transmit(_sid, _cid, _response) =
            state.local.checklist_set.poll(now)
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

        let nominated_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        info!("perform nominated check");
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        let set_ret = state.local.checklist_set.poll(now);
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::SelectedPair(_comp, selected_pair),
        ) = set_ret
        else {
            unreachable!();
        };
        assert_eq!(selected_pair.candidate_pair, pair);
        let set_ret = state.local.checklist_set.poll(now);
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_comp, ComponentConnectionState::Connected),
        ) = set_ret
        else {
            unreachable!();
        };
        let set_ret = state.local.checklist_set.poll(now);
        assert!(matches!(set_ret, CheckListSetPollRet::Completed));
        // a checklist with only a local candidates but no more possible candidates will error
        assert_eq!(state.local_list().state(), CheckListState::Completed);
    }
}
