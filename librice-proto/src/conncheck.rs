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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::candidate::{Candidate, CandidatePair, CandidateType, TcpType, TransportType};
use crate::stun::agent::{
    HandleStunReply, StunAgent, StunError, StunRequest, StunRequestPollRet, Transmit,
};
use crate::stun::attribute::*;
use crate::stun::message::*;

/// ICE Credentials
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub ufrag: String,
    pub passwd: String,
}

impl From<Credentials> for ShortTermCredentials {
    fn from(cred: Credentials) -> Self {
        ShortTermCredentials {
            password: cred.passwd,
        }
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

/// The state of a component
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComponentState {
    /// Component is in initial state and no connectivity checks are in progress.
    New,
    /// Connectivity checks are in progress for this candidate
    Connecting,
    /// A [`Candidatepair`](crate::candidate::CandidatePair`) has been selected for this component
    Connected,
    /// No connection could be found for this Component
    Failed,
}

/// A pair that has been selected for a component
#[derive(Debug, Clone)]
pub struct SelectedPair {
    candidate_pair: CandidatePair,
    local_stun_agent: StunAgent,
}
impl SelectedPair {
    /// Create a new [`SelectedPair`].  The pair and stun agent must be compatible.
    pub fn new(candidate_pair: CandidatePair, local_stun_agent: StunAgent) -> Self {
        Self {
            candidate_pair,
            local_stun_agent,
        }
    }

    /// The pair for this [`SelectedPair`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice_proto::candidate::*;
    /// # use librice_proto::stun::agent::StunAgent;
    /// # use librice_proto::conncheck::SelectedPair;
    /// # use std::net::SocketAddr;
    /// let local_addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
    /// let remote_addr: SocketAddr = "127.0.0.1:5432".parse().unwrap();
    /// let local = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "local",
    ///     local_addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// let remote = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "remote",
    ///     remote_addr,
    /// )
    /// .priority(4321)
    /// .build();
    /// let pair = CandidatePair::new(local, remote);
    /// let agent = StunAgent::builder(TransportType::Udp, local_addr).build();
    /// let selected = SelectedPair::new(pair.clone(), agent);
    /// assert_eq!(selected.candidate_pair(), &pair);
    /// ```
    pub fn candidate_pair(&self) -> &CandidatePair {
        &self.candidate_pair
    }

    /// The local STUN agent for this [`SelectedPair`]
    pub fn stun_agent(&self) -> &StunAgent {
        &self.local_stun_agent
    }
}

/// Return values when handling received data
#[derive(Debug)]
pub enum HandleRecvReply {
    /// The data has been and should be ignored
    Ignored,
    /// The data has been handled internally
    Handled,
    /// User data has been provided and should be handled further
    Data(Vec<u8>, SocketAddr),
}

/// Events that can be produced during the connectivity check process
#[derive(Debug)]
pub enum ConnCheckEvent {
    /// The state of a component has changed
    ComponentState(usize, ComponentState),
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
    agent: Option<StunAgent>,
}

#[derive(Debug, Clone)]
enum ConnCheckVariant {
    Agent(StunAgent),
    Tcp(TcpConnCheck),
}

struct ConnCheck {
    conncheck_id: usize,
    checklist_id: usize,
    nominate: bool,
    pair: CandidatePair,
    state: Arc<Mutex<ConnCheckState>>,
    variant: ConnCheckVariant,
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

#[derive(Debug)]
struct ConnCheckState {
    conncheck_id: usize,
    state: CandidatePairState,
    stun_request: Option<StunRequest>,
}

impl ConnCheckState {
    #[tracing::instrument(
        name = "set_check_state",
        level = "debug",
        skip(self, state),
        fields(
            ?self.conncheck_id,
        )
    )]
    fn set_state(&mut self, state: CandidatePairState) {
        if self.state != state {
            debug!(old_state = ?self.state, new_state = ?state, "updating state");
            if state == CandidatePairState::Succeeded || state == CandidatePairState::Failed {
                debug!("aborting recv task");
                if let Some(ref stun_request) = self.stun_request {
                    stun_request.cancel_retransmissions();
                }
            }
            self.state = state;
        }
    }
}

impl ConnCheck {
    fn new(checklist_id: usize, pair: CandidatePair, agent: StunAgent, nominate: bool) -> Self {
        let conncheck_id = CONN_CHECK_COUNT.fetch_add(1, Ordering::SeqCst);
        let inner = Arc::new(Mutex::new(ConnCheckState {
            conncheck_id,
            state: CandidatePairState::Frozen,
            stun_request: None,
        }));
        Self {
            conncheck_id,
            checklist_id,
            pair,
            state: inner,
            variant: ConnCheckVariant::Agent(agent),
            nominate,
        }
    }

    fn new_tcp(checklist_id: usize, pair: CandidatePair, nominate: bool) -> Self {
        let conncheck_id = CONN_CHECK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            conncheck_id,
            checklist_id,
            pair,
            state: Arc::new(Mutex::new(ConnCheckState {
                conncheck_id,
                state: CandidatePairState::Frozen,
                stun_request: None,
            })),
            variant: ConnCheckVariant::Tcp(TcpConnCheck { agent: None }),
            nominate,
        }
    }

    fn clone_with_pair_nominate(
        conncheck: &Arc<ConnCheck>,
        checklist_id: usize,
        pair: CandidatePair,
        new_nominate: bool,
    ) -> Arc<ConnCheck> {
        match &conncheck.variant {
            ConnCheckVariant::Agent(agent) => Arc::new(ConnCheck::new(
                checklist_id,
                pair,
                agent.clone(),
                new_nominate,
            )),
            _ => unreachable!(),
        }
    }

    fn agent(&self) -> Option<&StunAgent> {
        match &self.variant {
            ConnCheckVariant::Agent(agent) => Some(agent),
            ConnCheckVariant::Tcp(tcp) => tcp.agent.as_ref(),
        }
    }

    fn state(&self) -> CandidatePairState {
        self.state.lock().unwrap().state
    }

    fn set_state(&self, state: CandidatePairState) {
        let mut inner = self.state.lock().unwrap();
        // TODO: validate state change
        inner.set_state(state)
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
    fn cancel(&self) {
        let mut inner = self.state.lock().unwrap();
        inner.set_state(CandidatePairState::Failed);
        if let Some(stun_request) = inner.stun_request.take() {
            debug!(conncheck.id = self.conncheck_id, "cancelling conncheck");
            stun_request.cancel();
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
        let inner = self.state.lock().unwrap();
        if let Some(stun_request) = inner.stun_request.as_ref() {
            debug!(
                conncheck.id = self.conncheck_id,
                "cancelling conncheck retransmissions"
            );
            stun_request.cancel_retransmissions();
        }
    }

    fn generate_stun_request(
        agent: &StunAgent,
        pair: &CandidatePair,
        nominate: bool,
        controlling: bool,
        tie_breaker: u64,
        local_credentials: Credentials,
        remote_credentials: Credentials,
    ) -> Result<StunRequest, StunError> {
        let to = pair.remote.address;
        let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;

        // XXX: this needs to be the priority as if the candidate was peer-reflexive
        let mut msg = Message::new_request(BINDING);
        msg.add_attribute(Priority::new(pair.local.priority))?;
        if controlling {
            msg.add_attribute(IceControlling::new(tie_breaker))?;
        } else {
            msg.add_attribute(IceControlled::new(tie_breaker))?;
        }
        if nominate {
            msg.add_attribute(UseCandidate::new())?;
        }
        msg.add_attribute(Username::new(&username)?)?;
        msg.add_message_integrity(
            &MessageIntegrityCredentials::ShortTerm(local_credentials.clone().into()),
            IntegrityAlgorithm::Sha1,
        )?;
        msg.add_fingerprint()?;
        agent.stun_request_transaction(&msg, to).build()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CheckListState {
    Running,
    Completed,
    Failed,
}

static CONN_CHECK_LIST_COUNT: AtomicUsize = AtomicUsize::new(0);

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
    triggered: VecDeque<Arc<ConnCheck>>,
    pairs: VecDeque<Arc<ConnCheck>>,
    valid: Vec<Arc<ConnCheck>>,
    nominated: Vec<Arc<ConnCheck>>,
    controlling: bool,
    trickle_ice: bool,
    local_end_of_candidates: bool,
    remote_end_of_candidates: bool,
    events: VecDeque<ConnCheckEvent>,
    agents: Vec<StunAgent>,
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
    Agent(StunAgent),
    TcpListener,
    TcpActive,
}

#[derive(Debug)]
struct ConnCheckLocalCandidate {
    candidate: Candidate,
    variant: LocalCandidateVariant,
}

fn binding_success_response(
    msg: &Message,
    from: SocketAddr,
    local_credentials: MessageIntegrityCredentials,
) -> Result<Message, StunError> {
    let mut response = Message::new_success(msg);
    response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
    response.add_message_integrity(&local_credentials, IntegrityAlgorithm::Sha1)?;
    response.add_fingerprint()?;
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

    /// Remove a component id from this checklist
    pub fn remove_component(&mut self, component_id: usize) {
        if let Some(idx) = self.component_ids.iter().position(|&id| id == component_id) {
            self.component_ids.remove(idx);
        }
    }

    fn poll_event(&mut self) -> Option<ConnCheckEvent> {
        self.events.pop_back()
    }

    fn find_agent_for_5tuple(
        &self,
        transport: TransportType,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<&StunAgent> {
        self.agents.iter().find(|a| {
            error!(
                "checking agent {transport:?} =? {:?}, {local:?} =? {:?}",
                a.transport(),
                a.local_addr()
            );
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

    fn find_or_create_udp_agent(
        &mut self,
        candidate: &Candidate,
        local_credentials: &Credentials,
        remote_credentials: &Credentials,
    ) -> StunAgent {
        if let Some(agent) = self.agents.iter().find(|a| match candidate.transport_type {
            TransportType::Udp => {
                a.local_addr() == candidate.base_address && a.transport() == TransportType::Udp
            }
            _ => unreachable!(),
        }) {
            agent.clone()
        } else {
            let agent =
                StunAgent::builder(candidate.transport_type, candidate.base_address).build();
            agent.set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                local_credentials.clone().into(),
            ));
            agent.set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                remote_credentials.clone().into(),
            ));
            self.agents.push(agent.clone());
            agent
        }
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
    pub fn add_local_candidate(&mut self, local: Candidate, socket: bool) {
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

        debug!("adding {:?}", local);

        match local.transport_type {
            TransportType::Udp => {
                let agent =
                    self.find_or_create_udp_agent(&local, &local_credentials, &remote_credentials);
                self.local_candidates.push(ConnCheckLocalCandidate {
                    candidate: local,
                    variant: LocalCandidateVariant::Agent(agent),
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
        if self.remote_end_of_candidates {
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

    fn next_triggered(&mut self) -> Option<Arc<ConnCheck>> {
        self.triggered.pop_back()
    }

    #[cfg(test)]
    fn is_triggered(&self, needle: &Arc<ConnCheck>) -> bool {
        trace!("triggered {:?}", self.triggered);
        self.triggered.iter().any(|check| needle.pair == check.pair)
    }

    // note this will change the state of the returned check to InProgress to avoid a race
    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn next_waiting(&self) -> Option<Arc<ConnCheck>> {
        self.pairs
            .iter()
            // first look for any that are waiting
            // FIXME: should be highest priority pair: make the data structure give us that by
            // default
            .find(|check| {
                if check.state() == CandidatePairState::Waiting {
                    check.set_state(CandidatePairState::InProgress);
                    true
                } else {
                    false
                }
            })
            .cloned()
    }

    // note this will change the returned check state to waiting to avoid a race
    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn next_frozen(&self, from_foundations: &[String]) -> Option<Arc<ConnCheck>> {
        self.pairs
            .iter()
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
            .cloned()
            .inspect(|check| check.set_state(CandidatePairState::Waiting))
            .next()
    }

    fn foundations(&self) -> std::collections::HashSet<String> {
        let mut foundations = std::collections::HashSet::new();
        let _: Vec<_> = self
            .pairs
            .iter()
            .cloned()
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

    #[tracing::instrument(
        level = "debug",
        skip(self, check),
        fields(
            self.checklist_id,
            check.conncheck_id
        )
    )]
    fn add_triggered(&mut self, check: Arc<ConnCheck>) {
        if let Some(idx) = self
            .triggered
            .iter()
            .position(|existing| candidate_pair_is_same_connection(&existing.pair, &check.pair))
        {
            // a nominating check trumps not nominating.  Otherwise, if the peers are delay sync,
            // then the non-nominating trigerred check may override the nomination process for a
            // long time and delay the connection process
            if check.nominate() && !self.triggered[idx].nominate()
                || self.triggered[idx].state() == CandidatePairState::Failed
            {
                let existing = self.triggered.remove(idx).unwrap();
                debug!("removing existing triggered {:?}", existing);
            } else {
                debug!("not adding duplicate triggered check");
                return;
            }
        }
        debug!("adding triggered check {:?}", check);
        self.triggered.push_front(check)
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
                                LocalCandidateVariant::Agent(ref agent) => {
                                    redundant_pairs.push((
                                        redundant_pair.clone(),
                                        pair,
                                        agent.clone(),
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
                            LocalCandidateVariant::Agent(ref agent) => {
                                checks.push(Arc::new(ConnCheck::new(
                                    self.checklist_id,
                                    pair.clone(),
                                    agent.clone(),
                                    false,
                                )));
                            }
                            LocalCandidateVariant::TcpActive => {
                                checks.push(Arc::new(ConnCheck::new_tcp(
                                    self.checklist_id,
                                    pair.clone(),
                                    false,
                                )));
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
                        LocalCandidateVariant::StunAgent(agent) => checks.push(Arc::new(ConnCheck::new(pair, agent.stun_agent.clone(), false))),
                        LocalCandidateVariant::TcpListen(_tcp) => checks.push(Arc::new(ConnCheck::new_tcp(pair, false, weak_inner.clone(), component))),
                        LocalCandidateVariant::TcpActive => (),
                    }
                } else {
                    self.add_check(check);
                }
            }
        }*/

        let mut thawn_foundations = if self.trickle_ice {
            self.thawn_foundations()
        } else {
            vec![]
        };
        for check in checks {
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
            self.add_check(check)
        }
    }

    fn check_is_equal(check: &Arc<ConnCheck>, pair: &CandidatePair, nominate: Nominate) -> bool {
        candidate_is_same_connection(&check.pair.local, &pair.local)
            && candidate_is_same_connection(&check.pair.remote, &pair.remote)
            && nominate.eq(&check.nominate)
    }

    #[tracing::instrument(level = "trace", ret, skip(self, pair))]
    fn matching_check(&self, pair: &CandidatePair, nominate: Nominate) -> Option<Arc<ConnCheck>> {
        self.triggered
            .iter()
            .find(|&check| Self::check_is_equal(check, pair, nominate))
            .or_else(|| {
                self.pairs
                    .iter()
                    .find(|&check| Self::check_is_equal(check, pair, nominate))
            })
            .cloned()
    }

    fn add_check(&mut self, check: Arc<ConnCheck>) {
        trace!("adding check {:?}", check);
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
                return;
            }
        }

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
        skip(self, check),
        fields(
            checklist_id = self.checklist_id,
            pair = ?check.pair,
        )
    )]
    fn add_valid(&mut self, check: Arc<ConnCheck>) {
        if check.pair.local.transport_type == TransportType::Tcp
            && check.pair.local.tcp_type == Some(TcpType::Passive)
            && check.pair.local.address.port() == 9
        {
            trace!("no adding local passive tcp candidate without a valid port");
        }
        trace!("adding {:?}", check.pair);
        self.valid.push(check);
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn remove_valid(&mut self, pair: &CandidatePair) {
        self.valid.retain(|check| {
            if !candidate_pair_is_same_connection(&check.pair, pair) {
                debug!("removing");
                false
            } else {
                true
            }
        });
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
        if let Some(idx) = self
            .valid
            .iter()
            .position(|check| candidate_pair_is_same_connection(&check.pair, pair))
        {
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
            self.triggered.retain(|check| {
                if check.pair.local.component_id == pair.local.component_id {
                    check.cancel_retransmissions();
                    false
                } else {
                    true
                }
            });
            self.pairs.retain(|check| {
                if check.pair.local.component_id == pair.local.component_id {
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
                self.nominated
                    .iter()
                    .fold(vec![], |mut component_ids_selected, check| {
                        // Only nominate one valid candidatePair
                        if !component_ids_selected
                            .iter()
                            .any(|&comp_id| comp_id == check.pair.local.component_id)
                        {
                            if let Some(component_id) = component_id {
                                self.events.push_front(ConnCheckEvent::SelectedPair(
                                    component_id,
                                    Box::new(SelectedPair::new(pair.clone(), check.agent().unwrap().clone())),
                                ));
                                debug!("trying to signal component {:?}", component_id);
                                self.events.push_front(ConnCheckEvent::ComponentState(
                                    component_id,
                                    ComponentState::Connected,
                                ));
                            }
                            component_ids_selected.push(check.pair.local.component_id);
                        }
                        component_ids_selected
                    });
                self.set_state(CheckListState::Completed);
            }
        } else {
            warn!("unknown nomination");
        }
    }

    fn try_nominate(&mut self) {
        let retrigerred: Vec<_> = self
            .component_ids
            .iter()
            .map(|&component_id| {
                let nominated = self.pairs.iter().cloned().find(|check| check.nominate());
                nominated.or({
                    let mut valid: Vec<_> = self
                        .valid
                        .iter()
                        .cloned()
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
                        valid.get(0).cloned()
                    } else {
                        None
                    }
                })
            })
            .collect();
        trace!("retriggered {:?}", retrigerred);
        // need to wait until all component have a valid pair before we send nominations
        if retrigerred.iter().all(|pair| pair.is_some()) {
            self.dump_check_state();
            info!("all components have successful connchecks");
            let _: Vec<_> = retrigerred
                .iter()
                .map(|check| {
                    let check = check.as_ref().unwrap(); // checked earlier
                                                         // find the local stun agent for this pair
                    if check.nominate() {
                        trace!(
                            "already have nominate check for component {}",
                            check.pair.local.component_id
                        );
                    } else {
                        let check = ConnCheck::clone_with_pair_nominate(
                            check,
                            self.checklist_id,
                            check.pair.clone(),
                            true,
                        );
                        check.set_state(CandidatePairState::Waiting);
                        debug!("attempting nomination with check {:?}", check);
                        self.add_check(check.clone());
                        self.add_triggered(check);
                    }
                })
                .collect();
        }
    }

    fn dump_check_state(&self) {
        let mut s = format!("checklist {}", self.checklist_id);
        for pair in self.pairs.iter() {
            use std::fmt::Write as _;
            let _ = write!(&mut s,
                "\nID:{id} foundation:{foundation} state:{state} nom:{nominate} priority:{local_pri},{remote_pri} trans:{transport} local:{local_cand_type} {local_addr} remote:{remote_cand_type} {remote_addr}",
                id = format_args!("{:<3}", pair.conncheck_id),
                foundation = format_args!("{:10}", pair.pair.foundation()),
                state = format_args!("{:10}", pair.state()),
                nominate = format_args!("{:5}", pair.nominate()),
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

    fn check_response_failure(&mut self, conncheck: Arc<ConnCheck>) {
        warn!("conncheck failure: {:?}", conncheck);
        conncheck.set_state(CandidatePairState::Failed);
        self.remove_valid(&conncheck.pair);
        if conncheck.nominate() {
            self.set_state(CheckListState::Failed);
        }
        if self.local_end_of_candidates && self.remote_end_of_candidates {
            self.check_for_failure();
        }
    }

    fn find_check_from_stun_response(
        &self,
        transaction: TransactionId,
        from: SocketAddr,
    ) -> Option<Arc<ConnCheck>> {
        let f = |check: &Arc<ConnCheck>| {
            let state = check.state.lock().unwrap();
            state.stun_request.as_ref().and_then(|request| {
                if request.request().transaction_id() == transaction
                    && request.peer_address() == from
                {
                    Some(check.clone())
                } else {
                    None
                }
            })
        };
        self.triggered
            .iter()
            .find_map(f)
            .or(self.pairs.iter().find_map(f))
    }

    fn find_local_candidate(
        &self,
        transport: TransportType,
        addr: SocketAddr,
    ) -> Option<&ConnCheckLocalCandidate> {
        self.local_candidates.iter().find(|cand| {
            cand.candidate.transport_type == transport && cand.candidate.base_address == addr
        })
    }

    fn add_tcp_agent_internal(
        &mut self,
        _component_id: usize,
        from: SocketAddr,
        to: SocketAddr,
        tie_breaker: u64,
        agent: Result<StunAgent, StunError>,
    ) {
        if self.agents.iter().any(|a| {
            a.transport() == TransportType::Tcp
                && a.local_addr() == from
                && a.remote_addr() == Some(to)
        }) {
            panic!("Adding an agent with the same 5-tuple multiple times is not supported");
        }

        let mut new_connchecks = vec![];
        for (check, is_triggered) in self
            .triggered
            .iter()
            .map(|c| (c, true))
            .chain(self.pairs.iter().map(|c| (c, false)))
        {
            if check.pair.local.transport_type != TransportType::Tcp {
                continue;
            }
            if check.pair.remote.address != to {
                continue;
            }
            if from != check.pair.local.base_address {
                continue;
            }
            let state = check.state.lock().unwrap();
            if state.stun_request.is_none() {
                trace!("found check with id {} to set agent", check.conncheck_id);
                match &agent {
                    Ok(agent) => {
                        let mut new_pair = check.pair.clone();
                        new_pair.local.base_address = agent.local_addr();
                        new_pair.local.address = agent.local_addr();

                        let Ok(stun_request) = ConnCheck::generate_stun_request(
                            agent,
                            &new_pair,
                            check.nominate,
                            self.controlling,
                            tie_breaker,
                            self.local_credentials.clone(),
                            self.remote_credentials.clone(),
                        ) else {
                            warn!("failed to generate stun request for new tcp agent");
                            return;
                        };
                        self.agents.push(agent.clone());

                        let new_check = Arc::new(ConnCheck::new(
                            check.checklist_id,
                            new_pair.clone(),
                            agent.clone(),
                            check.nominate,
                        ));
                        let old_state = state.state;
                        drop(state);
                        let mut state = new_check.state.lock().unwrap();
                        state.set_state(old_state);
                        state.stun_request = Some(stun_request);
                        drop(state);
                        new_connchecks.push((check.conncheck_id, is_triggered, new_check));
                    }
                    Err(_e) => {
                        check.set_state(CandidatePairState::Failed);
                    }
                }
            }
        }

        // remove the old checks
        self.triggered.retain(|c| {
            new_connchecks
                .iter()
                .any(|(old_id, is_triggered, _new_check)| {
                    c.conncheck_id != *old_id || !*is_triggered
                })
        });
        self.pairs.retain(|c| {
            new_connchecks
                .iter()
                .any(|(old_id, is_triggered, _new_check)| {
                    c.conncheck_id != *old_id || *is_triggered
                })
        });

        // add the replacement checks
        for (_old_id, is_triggered, new_check) in new_connchecks {
            if is_triggered {
                self.add_triggered(new_check);
            } else {
                self.add_check(new_check);
            }
        }
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
            checklists: vec![],
            tie_breaker: self.tie_breaker,
            controlling: self.controlling,
            trickle_ice: self.trickle_ice,
            checklist_i: 0,
            last_send_time: Instant::now() - ConnCheckListSet::MINIMUM_SET_TICK,
            pending_transmits: vec![],
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
    pending_transmits: Vec<(usize, usize, Transmit)>,
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
    pub fn list_mut(&mut self, id: usize) -> Option<&mut ConnCheckList> {
        self.checklists.iter_mut().find(|cl| cl.checklist_id == id)
    }

    #[cfg(test)]
    pub(crate) fn set_controlling(&mut self, controlling: bool) {
        // XXX: do we need to update any other state here?
        self.controlling = controlling;
    }

    /// Whether the set is in the controlling mode.  This may change during the ICE negotiation
    /// process.
    pub fn controlling(&mut self) -> bool {
        self.controlling
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
        let mut ret = vec![];
        let checklist_i = self
            .checklists
            .iter()
            .position(|cl| cl.checklist_id == checklist_id)
            .ok_or(StunError::ResourceNotFound)?;
        let (agent, checklist_i) = self.checklists[checklist_i]
            .find_agent_for_5tuple(transmit.transport, transmit.to, transmit.from)
            .map(|agent| (agent.clone(), checklist_i))
            .unwrap_or_else(|| {
                // else look at all checklists
                self.checklists
                    .iter()
                    .find_map(|checklist| {
                        checklist
                            .find_agent_for_5tuple(transmit.transport, transmit.to, transmit.from)
                            .map(|agent| (agent.clone(), checklist.checklist_id))
                    })
                    .unwrap_or_else(|| {
                        error!("new agent");
                        let agent = StunAgent::builder(transmit.transport, transmit.to)
                            .remote_addr(transmit.from)
                            .build();
                        self.checklists[checklist_i].agents.push(agent.clone());
                        (agent, checklist_i)
                    })
            });
        for reply in agent.handle_incoming_data(&transmit.data, transmit.from)? {
            match reply {
                HandleStunReply::Ignore => ret.push(HandleRecvReply::Ignored),
                HandleStunReply::Data(data, from) => ret.push(HandleRecvReply::Data(data, from)),
                HandleStunReply::Stun(stun, from) => {
                    if stun.is_response() {
                        self.handle_stun_response(checklist_i, stun, from)?;
                    } else if stun.has_method(BINDING) {
                        let local_cand = self.checklists[checklist_i]
                            .find_local_candidate(transmit.transport, transmit.to)
                            .unwrap()
                            .candidate
                            .clone();

                        if let Some(response) = self.handle_binding_request(
                            checklist_i,
                            &local_cand,
                            agent.clone(),
                            &stun,
                            from,
                        )? {
                            self.pending_transmits.push((
                                checklist_id,
                                local_cand.component_id,
                                Transmit {
                                    transport: transmit.transport,
                                    data: response.to_bytes(),
                                    to: transmit.from,
                                    from: transmit.to,
                                },
                            ));
                        }
                    }
                    ret.push(HandleRecvReply::Handled);
                }
            }
        }
        Ok(ret)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_binding_request(
        &mut self,
        checklist_i: usize,
        local: &Candidate,
        agent: StunAgent,
        msg: &Message,
        from: SocketAddr,
    ) -> Result<Option<Message>, StunError> {
        let checklist = &mut self.checklists[checklist_i];
        trace!("have request {}", msg);

        let local_credentials = agent
            .local_credentials()
            .ok_or(StunError::ResourceNotFound)?;

        if let Some(error_msg) = Message::check_attribute_types(
            msg,
            &[
                USERNAME,
                FINGERPRINT,
                MESSAGE_INTEGRITY,
                ICE_CONTROLLED,
                ICE_CONTROLLING,
                PRIORITY,
                USE_CANDIDATE,
            ],
            &[USERNAME, FINGERPRINT, MESSAGE_INTEGRITY, PRIORITY],
        ) {
            // failure -> send error response
            return Ok(Some(error_msg));
        }
        let peer_nominating =
            if let Some(use_candidate_raw) = msg.raw_attribute(USE_CANDIDATE) {
                if UseCandidate::from_raw(&use_candidate_raw).is_ok() {
                    true
                } else {
                    let response = Message::bad_request(msg)?;
                    return Ok(Some(response));
                }
            } else {
                false
            };

        let priority = match msg.attribute::<Priority>(PRIORITY) {
            Some(p) => p.priority(),
            None => {
                let response = Message::bad_request(msg)?;
                return Ok(Some(response));
            }
        };

        let ice_controlling = msg.attribute::<IceControlling>(ICE_CONTROLLING);
        let ice_controlled = msg.attribute::<IceControlled>(ICE_CONTROLLED);

        /*
        if checklist.state == CheckListState::Completed && !peer_nominating {
            // ignore binding requests if we are completed
            trace!("ignoring binding request as we have completed");
            return Ok(None);
        }*/

        // validate username
        if let Some(username) = msg.attribute::<Username>(USERNAME) {
            if !validate_username(username, &checklist.local_credentials) {
                warn!("binding request failed username validation -> UNAUTHORIZED");
                let mut response = Message::new_error(msg);
                response.add_attribute(ErrorCode::builder(ErrorCode::UNAUTHORIZED).build()?)?;
                return Ok(Some(response));
            }
        } else {
            // existence is checked above so can only fail when the username is invalid
            let response = Message::bad_request(msg)?;
            return Ok(Some(response));
        }

        // Deal with role conflicts
        // RFC 8445 7.3.1.1.  Detecting and Repairing Role Conflicts
        trace!("checking for role conflicts");
        if let Some(ice_controlling) = ice_controlling {
            //  o  If the agent is in the controlling role, and the ICE-CONTROLLING
            //     attribute is present in the request:
            if self.controlling {
                if self.tie_breaker >= ice_controlling.tie_breaker() {
                    debug!("role conflict detected (controlling=true), returning ROLE_CONFLICT");
                    // *  If the agent's tiebreaker value is larger than or equal to the
                    //    contents of the ICE-CONTROLLING attribute, the agent generates
                    //    a Binding error response and includes an ERROR-CODE attribute
                    //    with a value of 487 (Role Conflict) but retains its role.
                    let mut response = Message::new_error(msg);
                    response
                        .add_attribute(ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?)?;
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
        if let Some(ice_controlled) = ice_controlled {
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
                    let mut response = Message::new_error(msg);
                    response
                        .add_attribute(ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?)?;
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
        if let Some(mut check) = checklist.matching_check(&pair, Nominate::DontCare) {
            // When the pair is already on the checklist:
            trace!("found existing {:?} check {:?}", check.state(), check);
            match check.state() {
                // If the state of that pair is Succeeded, nothing further is
                // done.
                CandidatePairState::Succeeded => {
                    if peer_nominating && !check.nominate() {
                        debug!("existing pair succeeded -> nominate");
                        check = ConnCheck::clone_with_pair_nominate(
                            &check,
                            checklist.checklist_id,
                            check.pair.clone(),
                            true,
                        );
                        check.set_state(CandidatePairState::Waiting);
                        checklist.add_check(check);
                        checklist.nominated_pair(&pair);
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
                    // TODO: ignore response timeouts

                    check = ConnCheck::clone_with_pair_nominate(
                        &check,
                        checklist.checklist_id,
                        check.pair.clone(),
                        peer_nominating,
                    );
                    check.set_state(CandidatePairState::Waiting);
                    checklist.add_check(check.clone());
                    checklist.add_triggered(check);
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
                        checklist.add_check(check.clone());
                    }
                    check.set_state(CandidatePairState::Waiting);
                    checklist.add_triggered(check);
                }
            }
        } else {
            debug!("creating new check for pair {:?}", pair);
            let check = Arc::new(ConnCheck::new(
                checklist.checklist_id,
                pair,
                agent,
                peer_nominating,
            ));
            check.set_state(CandidatePairState::Waiting);
            checklist.add_check(check.clone());
            checklist.add_triggered(check);
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
        conncheck: Arc<ConnCheck>,
        addr: SocketAddr,
        controlling: bool,
    ) -> Result<(), StunError> {
        let checklist = &mut self.checklists[checklist_i];
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

        if checklist.state != CheckListState::Running {
            debug!("checklist is not running, ignoring check response");
            return Ok(());
        }

        let mut pair_dealt_with = false;
        let ok_pair = conncheck.pair.construct_valid(addr);
        // 1.
        // If the valid pair equals the pair that generated the check, the
        // pair is added to the valid list associated with the checklist to
        // which the pair belongs; or
        if let Some(check) = checklist.matching_check(&ok_pair, Nominate::DontCare) {
            debug!(existing.id = check.conncheck_id, "found existing check");
            checklist.add_valid(conncheck.clone());
            if conncheck.nominate() {
                checklist.nominated_pair(&conncheck.pair);
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
                        existing.id = check.conncheck_id,
                        "found existing check in checklist {}", checklist.checklist_id
                    );
                    checklist.add_valid(check.clone());
                    if conncheck.nominate() {
                        checklist.nominated_pair(&conncheck.pair);
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
            let ok_check = ConnCheck::clone_with_pair_nominate(
                &conncheck,
                checklist.checklist_id,
                ok_pair.clone(),
                false,
            );
            ok_check.set_state(CandidatePairState::Succeeded);
            checklist.add_check(ok_check.clone());
            checklist.add_valid(ok_check);
            checklist.add_valid(conncheck.clone());

            if conncheck.nominate() {
                checklist.nominated_pair(&conncheck.pair);
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
        // find conncheck
        let conncheck = checklist.find_check_from_stun_response(response.transaction_id(), from);
        let conncheck = match conncheck {
            Some(conncheck) => conncheck,
            None => {
                checklist.dump_check_state();
                warn!("No existing check available, ignoring");
                return Ok(());
            }
        };

        let stun_request = conncheck
            .state
            .lock()
            .unwrap()
            .stun_request
            .clone()
            .unwrap();

        // if response success:
        // if mismatched address -> fail
        if from != stun_request.peer_address() {
            warn!(
                "response came from different ip {:?} than candidate {:?}",
                from,
                stun_request.peer_address()
            );
            checklist.check_response_failure(conncheck.clone());
        }

        // if response error -> fail TODO: might be a recoverable error!
        if response.has_class(MessageClass::Error) {
            warn!("error response {}", response);
            if let Some(err) = response.attribute::<ErrorCode>(ERROR_CODE) {
                if err.code() == ErrorCode::ROLE_CONFLICT {
                    info!("Role conflict received {}", response);
                    let new_role = stun_request.request().has_attribute(ICE_CONTROLLED);
                    info!(
                        old_role = self.controlling,
                        new_role, "Role Conflict changing controlling from"
                    );
                    if self.controlling != new_role {
                        self.controlling = new_role;
                        checklist.remove_valid(&conncheck.pair);
                        conncheck.cancel();
                        let conncheck = ConnCheck::clone_with_pair_nominate(
                            &conncheck,
                            checklist.checklist_id,
                            conncheck.pair.clone(),
                            false,
                        );
                        conncheck.set_state(CandidatePairState::Waiting);
                        checklist.add_check(conncheck.clone());
                        checklist.add_triggered(conncheck);
                    }
                    return Ok(());
                }
            }
            // FIXME: some failures are recoverable
            checklist.check_response_failure(conncheck.clone());
        }

        if let Some(xor) = response.attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS) {
            let xor_addr = xor.addr(response.transaction_id());
            return self.check_success(checklist_i, conncheck, xor_addr, self.controlling);
        }

        checklist.check_response_failure(conncheck);
        Ok(())
    }

    fn perform_conncheck(
        &mut self,
        conncheck: Arc<ConnCheck>,
        now: Instant,
    ) -> Result<CheckListSetPollRet, StunError> {
        trace!("performing connectivity {:?}", &conncheck);

        let stun_request = {
            let mut inner = conncheck.state.lock().unwrap();
            if let Some(request) = inner.stun_request.clone() {
                request
            } else {
                let checklist = &self.checklists[self.checklist_i];
                if let ConnCheckVariant::Tcp(_tcp) = &conncheck.variant {
                    return Ok(CheckListSetPollRet::TcpConnect(
                        checklist.checklist_id,
                        conncheck.pair.local.component_id,
                        conncheck.pair.local.base_address,
                        conncheck.pair.remote.address,
                    ));
                }
                let ConnCheckVariant::Agent(agent) = &conncheck.variant else {
                    unreachable!();
                };
                let stun_request = ConnCheck::generate_stun_request(
                    agent,
                    &conncheck.pair,
                    conncheck.nominate,
                    self.controlling,
                    self.tie_breaker,
                    checklist.local_credentials.clone(),
                    checklist.remote_credentials.clone(),
                )?;

                inner.stun_request = Some(stun_request.clone());
                stun_request
            }
        };

        match stun_request.poll(now)? {
            StunRequestPollRet::Cancelled
            | StunRequestPollRet::WaitUntil(_)
            | StunRequestPollRet::Response(_) => unreachable!(),
            StunRequestPollRet::SendData(transmit) => Ok(CheckListSetPollRet::Transmit(
                conncheck.checklist_id,
                conncheck.pair.local.component_id,
                transmit,
            )),
        }
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
    fn next_check(&mut self) -> Option<Arc<ConnCheck>> {
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
            Some(check)
        // 3.  If there are one or more candidate pairs in the Waiting state,
        //     the agent picks the highest-priority candidate pair (if there are
        //     multiple pairs with the same priority, the pair with the lowest
        //     component ID is picked) in the Waiting state, performs a
        //     connectivity check on that pair, puts the candidate pair state to
        //     In-Progress, and aborts the subsequent steps.
        } else if let Some(check) = checklist.next_waiting() {
            trace!("next check was a waiting check {:?}", check);
            Some(check)
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
                        .iter_mut()
                        .all(|checklist| checklist.foundation_not_waiting_in_progress(&f))
                    {
                        foundations_not_waiting_in_progress.insert(f);
                    }
                })
                .collect();
            let next: Vec<_> = foundations_not_waiting_in_progress.into_iter().collect();
            trace!("current foundations not waiting or in progress: {:?}", next);

            let checklist = &self.checklists[self.checklist_i];
            if let Some(check) = checklist.next_frozen(&next) {
                trace!("next check was a frozen check {:?}", check);
                check.set_state(CandidatePairState::InProgress);
                Some(check)
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
    #[tracing::instrument(
        name = "check_set_poll",
        level = "debug",
        ret,
        skip(self)
    )]
    pub fn poll(&mut self, now: Instant) -> CheckListSetPollRet {
        if let Some((checklist_id, cid, transmit)) = self.pending_transmits.pop() {
            return CheckListSetPollRet::Transmit(checklist_id, cid, transmit);
        }

        for checklist in self.checklists.iter_mut() {
            if let Some(event) = checklist.poll_event() {
                return CheckListSetPollRet::Event(checklist.checklist_id, event);
            }
        }

        let mut any_running = false;
        let mut all_failed = true;
        loop {
            let start_idx = self.checklist_i;
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
                    for check in checklist.pairs.iter() {
                        let state = check.state.lock().unwrap();
                        if state.state != CandidatePairState::InProgress {
                            continue;
                        }
                        if let Some(request) = state.stun_request.as_ref() {
                            trace!("polling existing stun request for check {}", check.conncheck_id);
                            match request.poll(now) {
                                Err(e) => warn!("request threw error {e:?}"),
                                Ok(
                                    StunRequestPollRet::Cancelled
                                    | StunRequestPollRet::Response(_),
                                ) => (),
                                Ok(StunRequestPollRet::WaitUntil(wait)) => {
                                    if wait < lowest_wait {
                                        lowest_wait = wait.max(now + Self::MINIMUM_SET_TICK);
                                    }
                                }
                                Ok(StunRequestPollRet::SendData(transmit)) => {
                                    self.last_send_time = now;
                                    return CheckListSetPollRet::Transmit(
                                        checklist.checklist_id,
                                        check.pair.local.component_id,
                                        transmit,
                                    );
                                }
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

            let conncheck = match self.next_check() {
                Some(c) => c,
                None => {
                    if start_idx == self.checklist_i {
                        // we looked at them all and none of the checklist could find anything to
                        // do
                        if !any_running {
                            return CheckListSetPollRet::Completed;
                        } else {
                            error!("no next check waiting");
                            return CheckListSetPollRet::WaitUntil(lowest_wait);
                        }
                    } else {
                        continue;
                    }
                }
            };

            trace!("starting conncheck");
            match self.perform_conncheck(conncheck, now) {
                Ok(ret) => {
                    if !matches!(ret, CheckListSetPollRet::TcpConnect(_, _, _, _)) {
                        self.last_send_time = now;
                    }
                    return ret;
                }
                Err(e) => warn!("failed to perform check: {e:?}"),
            }
        }
    }

    /// Report a reply (success or failure) to a TCP connection attempt.
    /// [`ConnCheckListSet::poll`] should be called at the earliest opportunity.
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
        checklist.add_tcp_agent_internal(component_id, from, to, self.tie_breaker, agent)
    }
}

/// Return values for polling a set of checklists.
#[derive(Debug)]
pub enum CheckListSetPollRet {
    /// Perform a TCP connection from the provided address to the provided address.  Report success
    /// or failure with `tcp_connect_reply()`.
    TcpConnect(usize, usize, SocketAddr, SocketAddr),
    /// Transmit data
    Transmit(usize, usize, Transmit),
    /// Wait until the specified time has passed.  Receiving handled data may cause a different
    /// value to be returned from `poll()`
    WaitUntil(Instant),
    /// An event has occured
    Event(usize, ConnCheckEvent),
    /// The set has completed all operations and has either succeeded or failed.  Further progress
    /// will not be made.
    Completed,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::*;
    use crate::stun::agent::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn nominate_eq_bool() {
        init();
        assert!(Nominate::DontCare.eq(&true));
        assert!(Nominate::DontCare.eq(&false));
        assert!(Nominate::True.eq(&true));
        assert!(Nominate::False.eq(&false));
        assert!(!Nominate::False.eq(&true));
        assert!(!Nominate::True.eq(&false));
    }

    #[test]
    fn nominate_eq_nominate() {
        init();
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
            let agent = agent.build();
            self.configure_stun_agent(&agent);
            agent
        }

        fn configure_stun_agent(&self, agent: &StunAgent) {
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
        init();
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list = set.new_list();
        let list = set.list_mut(list).unwrap();
        list.add_component(1);

        let local = Peer::default();
        let remote = Peer::default();

        list.add_local_candidate(local.candidate.clone(), false);
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
    fn handle_binding_request(
        agent: &StunAgent,
        local_credentials: &Credentials,
        msg: &Message,
        from: SocketAddr,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
    ) -> Result<Message, StunError> {
        let local_stun_credentials = agent.local_credentials().unwrap();

        if let Some(error_msg) = Message::check_attribute_types(
            msg,
            &[
                USERNAME,
                FINGERPRINT,
                MESSAGE_INTEGRITY,
                ICE_CONTROLLED,
                ICE_CONTROLLING,
                PRIORITY,
                USE_CANDIDATE,
            ],
            &[USERNAME, FINGERPRINT, MESSAGE_INTEGRITY, PRIORITY],
        ) {
            // failure -> send error response
            return Ok(error_msg);
        }

        let ice_controlling = msg.attribute::<IceControlling>(ICE_CONTROLLING);
        let ice_controlled = msg.attribute::<IceControlled>(ICE_CONTROLLED);
        let username = msg.attribute::<Username>(USERNAME);
        let valid_username = username
            .map(|username| validate_username(username, local_credentials))
            .unwrap_or(false);

        let mut response = if ice_controlling.is_none() && ice_controlled.is_none() {
            warn!("missing ice controlled/controlling attribute");
            let mut response = Message::new_error(msg);
            response.add_attribute(ErrorCode::builder(ErrorCode::BAD_REQUEST).build()?)?;
            response
        } else if !valid_username {
            let mut response = Message::new_error(msg);
            response.add_attribute(ErrorCode::builder(ErrorCode::UNAUTHORIZED).build()?)?;
            response
        } else if let Some(error_code) = error_response {
            info!("responding with error {}", error_code);
            let mut response = Message::new_error(msg);
            response.add_attribute(ErrorCode::builder(error_code).build()?)?;
            response
        } else {
            let mut response = Message::new_success(msg);
            response.add_attribute(XorMappedAddress::new(
                response_address.unwrap_or(from),
                msg.transaction_id(),
            ))?;
            response
        };
        response.add_message_integrity(&local_stun_credentials, IntegrityAlgorithm::Sha1)?;
        response.add_fingerprint()?;
        Ok(response)
    }

    fn reply_to_conncheck(
        agent: &StunAgent,
        credentials: &Credentials,
        transmit: Transmit,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
    ) -> Option<Transmit> {
        let offset = match transmit.transport {
            TransportType::Udp => 0,
            TransportType::Tcp => 2,
        };
        match Message::from_bytes(&transmit.data[offset..]) {
            Err(e) => error!("error {e:?}"),
            Ok(msg) => {
                debug!("received from {}: {:?}", transmit.to, msg);
                if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                    return Some(
                        agent
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
                            )
                            .unwrap(),
                    );
                }
            }
        }
        None
    }

    #[test]
    fn conncheck_list_transmit() {
        init();
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
        init();
        let mut set = ConnCheckListSet::builder(0, true).build();
        let list = set.new_list();
        let list = set.list_mut(list).unwrap();
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

        list.add_local_candidate(local1.candidate.clone(), false);
        list.add_remote_candidate(remote1.candidate.clone());
        list.add_local_candidate(local2.candidate.clone(), false);
        list.add_remote_candidate(remote2.candidate.clone());
        list.add_local_candidate(local3.candidate.clone(), false);
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
        init();
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

        let list1 = set.list_mut(list1_id).unwrap();
        list1.add_component(1);
        list1.add_component(2);
        list1.add_local_candidate(local1.candidate.clone(), false);
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

        let list2 = set.list_mut(list2_id).unwrap();
        list2.add_component(1);
        list2.add_component(2);
        list2.add_local_candidate(local2.candidate.clone(), false);
        list2.add_remote_candidate(remote2.candidate.clone());
        list2.add_local_candidate(local3.candidate.clone(), false);
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
        local_peer_builder: PeerBuilder,
        remote_peer_builder: PeerBuilder,
    }

    impl Default for FineControlBuilder {
        fn default() -> Self {
            let local_credentials = Credentials::new("luser".into(), "lpass".into());
            let remote_credentials = Credentials::new("ruser".into(), "rpass".into());
            Self {
                trickle_ice: false,
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
        fn trickle_ice(mut self, trickle_ice: bool) -> Self {
            self.trickle_ice = trickle_ice;
            self
        }

        fn build(self) -> FineControl {
            let mut local_set = ConnCheckListSet::builder(0, true)
                .trickle_ice(self.trickle_ice)
                .build();
            let local_list = local_set.new_list();
            let local_list = local_set.list_mut(local_list).unwrap();
            local_list.add_component(1);
            let checklist_id = local_list.checklist_id;

            let local_peer = self.local_peer_builder.build();
            let remote_peer = self.remote_peer_builder.build();

            local_list.set_local_credentials(local_peer.local_credentials.clone().unwrap());
            local_list.set_remote_credentials(local_peer.remote_credentials.clone().unwrap());
            if !self.trickle_ice {
                local_list.add_local_candidate(local_peer.candidate.clone(), false);
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
                .list_mut(self.local.checklist_id)
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
                &self.remote_peer.stun_agent(),
                &self.remote_peer.local_credentials.clone().unwrap(),
                transmit,
                self.error_response,
                self.response_address,
            )
            .unwrap();
            info!("reply: {reply:?}");

            let checklist_ids: Vec<_> = set.checklists.iter().map(|cl| cl.checklist_id).collect();
            for checklist_id in checklist_ids.into_iter() {
                let reply = set.incoming_data(checklist_id, &reply).unwrap();
                trace!("reply: {reply:?}");
                assert!(matches!(
                    reply[0],
                    HandleRecvReply::Ignored | HandleRecvReply::Handled
                ));
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
        init();
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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
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
        assert!(state.local_list().is_triggered(&nominate_check));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, _selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
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
        init();
        let mut state = FineControl::builder().build();
        let mut now = Instant::now();

        // start off in the controlled mode, otherwise, the test needs to do the nomination
        // check
        state.local.checklist_set.set_controlling(false);
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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::ROLE_CONFLICT)
            .perform(&mut state.local.checklist_set, now);
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
        assert!(state.local_list().is_triggered(&triggered_check));

        // perform the next tick which will have a different ice controlling/ed attribute
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
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
        assert!(state.local_list().is_triggered(&nominate_check));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        // check list is done
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, _selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
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
        init();
        let mut state = FineControl::builder().build();
        let now = Instant::now();
        let local_list = state
            .local
            .checklist_set
            .list_mut(state.local.checklist_id)
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
        assert_eq!(check.state(), CandidatePairState::Frozen);

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        local_list.initial_thaw(&mut thawn);
        assert_eq!(check.state(), CandidatePairState::Waiting);

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .error_response(ErrorCode::UNAUTHORIZED)
            .perform(&mut state.local.checklist_set, now);
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
        init();
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
        let local_agent =
            StunAgent::builder(TransportType::Tcp, state.local.peer.candidate.base_address)
                .remote_addr(state.remote.candidate.address)
                .build();
        state.local.peer.configure_stun_agent(&local_agent);
        let remote_agent = StunAgent::builder(TransportType::Tcp, state.remote.candidate.address)
            .remote_addr(state.local.peer.candidate.base_address)
            .build();
        state.remote.configure_stun_agent(&remote_agent);
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

        let CheckListSetPollRet::Transmit(id, cid, transmit) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, state.local.checklist_id);
        assert_eq!(cid, state.local.peer.candidate.component_id);
        assert_eq!(transmit.from, state.local.peer.candidate.base_address);
        assert_eq!(transmit.to, state.remote.candidate.address);
        error!("tcp transmit");

        let Some(response) = reply_to_conncheck(
            &remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit,
            None,
            None,
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

        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let CheckListSetPollRet::Transmit(_id, _cid, transmit) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };

        let Some(response) = reply_to_conncheck(
            &remote_agent,
            state.local.peer.remote_credentials.as_ref().unwrap(),
            transmit,
            None,
            None,
        ) else {
            unreachable!();
        };
        state
            .local
            .checklist_set
            .incoming_data(state.local.checklist_id, &response)
            .unwrap();

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
        ) = state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(selected_pair.candidate_pair, pair);
    }

    #[test]
    fn conncheck_incoming_prflx() {
        init();
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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
        assert_eq!(initial_check.state(), CandidatePairState::Waiting);

        let unknown_remote_peer = Peer::builder()
            .local_addr("127.0.0.1:90".parse().unwrap())
            .foundation("1")
            .local_credentials(state.remote.local_credentials.clone().unwrap())
            .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
            .build();
        let remote_agent = unknown_remote_peer.stun_agent();

        // send a request from some unknown to the local agent address to produce a peer
        // reflexive candidate on the local agent
        let mut request = Message::new_request(BINDING);
        request
            .add_attribute(Priority::new(unknown_remote_peer.candidate.priority))
            .unwrap();
        request.add_attribute(IceControlled::new(200)).unwrap();
        request
            .add_attribute(
                Username::new(
                    &(state.local.peer.local_credentials.clone().unwrap().ufrag
                        + ":"
                        + &state.remote.local_credentials.clone().unwrap().ufrag),
                )
                .unwrap(),
            )
            .unwrap();
        request
            .add_message_integrity(
                &remote_agent.local_credentials().unwrap(),
                IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        request.add_fingerprint().unwrap();

        let local_addr = state
            .local
            .peer
            .stun_agent()
            .local_addr();
        let stun_request = remote_agent
            .stun_request_transaction(&request, local_addr)
            .build()
            .unwrap();

        info!("sending prflx request");
        let StunRequestPollRet::SendData(transmit) = stun_request.poll(now).unwrap() else {
            unreachable!();
        };
        let reply = state.local.checklist_set.incoming_data(state.local.checklist_id, &transmit).unwrap();
        assert!(matches!(reply[0], HandleRecvReply::Handled));
        let CheckListSetPollRet::Transmit(_, _, transmit) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };
        let mut reply = stun_request.agent().handle_incoming_data(&transmit.data, transmit.from).unwrap();
        let HandleStunReply::Stun(response, from) = reply.remove(0) else {
            unreachable!();
        };
        assert_eq!(from, local_addr);
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

        // perform one tick which will start a connectivity check with the peer
        info!("perform triggered check");
        send_next_check_and_response(&state.local.peer, &unknown_remote_peer).perform(&mut state.local.checklist_set, now);
        let CheckListSetPollRet::WaitUntil(now) = state.local.checklist_set.poll(now) else {
            unreachable!();
        };

        info!("have reply to triggered check");
        assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);
        let nominated_check = state
            .local_list()
            .matching_check(&pair, Nominate::True)
            .unwrap();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
        info!("perform nominated check");
        send_next_check_and_response(&state.local.peer, &unknown_remote_peer).perform(&mut state.local.checklist_set, now);

        info!("have reply to nominated check");
        assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, _selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
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
        init();
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

        let mut thawn = vec![];
        // thaw the first checklist with only a single pair will unfreeze that pair
        state.local_list().initial_thaw(&mut thawn);
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

        state.local_list().dump_check_state();
        assert_eq!(nominated_check.state(), CandidatePairState::Waiting);

        send_next_check_and_response(&state.local.peer, &state.remote)
            .response_address(unknown_remote_peer.candidate.address)
            .perform(&mut state.local.checklist_set, now);
        assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, _selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
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
        init();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let mut now = Instant::now();
        assert_eq!(state.local.component_id, 1);

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with no candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        let local_candidate = state.local.peer.candidate.clone();
        state
            .local_list()
            .add_local_candidate(local_candidate, false);

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

        // perform one tick which will start a connectivity check with the peer
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);
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
        assert!(state.local_list().is_triggered(&nominate_check));

        // perform one tick which will perform the nomination check
        send_next_check_and_response(&state.local.peer, &state.remote)
            .perform(&mut state.local.checklist_set, now);

        assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

        // check list is done
        // TODO: provide end-of-candidate notification and delay completed until we receive
        // end-of-candidate
        assert_eq!(state.local_list().state(), CheckListState::Completed);

        let CheckListSetPollRet::Event(_checklist_id, ConnCheckEvent::SelectedPair(_cid, _selected_pair)) =
            state.local.checklist_set.poll(now)
        else {
            unreachable!();
        };
        let CheckListSetPollRet::Event(
            _checklist_id,
            ConnCheckEvent::ComponentState(_cid, ComponentState::Connected),
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
        init();
        let mut state = FineControl::builder().trickle_ice(true).build();
        let local_candidate = state.local.peer.candidate.clone();

        // Don't generate any initial checks as they should be done as candidates are added to
        // the checklist
        let now = Instant::now();
        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with no candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state
            .local_list()
            .add_local_candidate(local_candidate, false);
        state.local_list().end_of_local_candidates();

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with only a local candidates has nothing to do
        assert!(matches!(set_ret, CheckListSetPollRet::WaitUntil(_)));

        state.local_list().end_of_remote_candidates();

        let set_ret = state.local.checklist_set.poll(now);
        // a checklist with only a local candidates but no more possible candidates will error
        assert_eq!(state.local_list().state(), CheckListState::Failed);
        assert!(matches!(set_ret, CheckListSetPollRet::Completed));
    }
}
