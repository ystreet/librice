// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures::channel::oneshot;
use futures::future::{AbortHandle, Abortable};
use futures::prelude::*;
use tracing_futures::Instrument;

use crate::candidate::{Candidate, CandidatePair, CandidateType, TransportType};

use crate::agent::AgentError;
use crate::stream::Credentials;

use crate::clock::{get_clock, Clock, ClockType};
use crate::component::{Component, ComponentState, SelectedPair};
use crate::stun::agent::StunAgent;
use crate::stun::attribute::*;
use crate::stun::message::*;
use crate::utils::DropLogger;

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
        write!(f, "{:?}", self)
    }
}

static CONN_CHECK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Derivative)]
#[derivative(Debug)]
struct ConnCheck {
    conncheck_id: usize,
    nominate: bool,
    pair: CandidatePair,
    #[derivative(Debug = "ignore")]
    state: Mutex<ConnCheckState>,
    #[derivative(Debug = "ignore")]
    agent: StunAgent,
}

#[derive(Debug)]
struct ConnCheckState {
    conncheck_id: usize,
    state: CandidatePairState,
    abort_handle: Option<AbortHandle>,
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
                let _ = self.abort_handle.take();
            }
            self.state = state;
        }
    }
}

impl ConnCheck {
    fn new(pair: CandidatePair, agent: StunAgent, nominate: bool) -> Self {
        let conncheck_id = CONN_CHECK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            conncheck_id,
            pair,
            state: Mutex::new(ConnCheckState {
                conncheck_id,
                state: CandidatePairState::Frozen,
                abort_handle: None,
            }),
            agent,
            nominate,
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
        let abort_handle = inner.abort_handle.take();
        if let Some(handle) = abort_handle {
            debug!(conncheck.id = self.conncheck_id, "cancelling conncheck");
            handle.abort();
            inner.set_state(CandidatePairState::Failed);
        }
    }

    async fn connectivity_check(
        conncheck: Arc<ConnCheck>,
        username: String,
        controlling: bool,
        tie_breaker: u64,
    ) -> Result<ConnCheckResponse, AgentError> {
        // generate binding request
        let msg = {
            let mut msg = Message::new_request(BINDING);

            // XXX: this needs to be the priority as if the candidate was peer-reflexive
            msg.add_attribute(Priority::new(conncheck.pair.local.priority))?;
            if controlling {
                msg.add_attribute(IceControlling::new(tie_breaker))?;
            } else {
                msg.add_attribute(IceControlled::new(tie_breaker))?;
            }
            if conncheck.nominate {
                msg.add_attribute(UseCandidate::new())?;
            }
            msg.add_attribute(Username::new(&username)?)?;
            msg.add_message_integrity(&conncheck.agent.local_credentials().unwrap())?;
            msg.add_fingerprint()?;
            msg
        };

        let to = conncheck.pair.remote.address;
        // send binding request
        // wait for response
        // if timeout -> resend?
        // if longer timeout -> fail
        // TODO: optional: if icmp error -> fail
        let (response, from) = match conncheck.agent.stun_request_transaction(&msg, to).await {
            Err(e) => {
                warn!("connectivity check produced error: {:?}", e);
                return Ok(ConnCheckResponse::Failure(conncheck));
            }
            Ok(v) => v,
        };
        trace!("have response: {}", response);

        if !response.is_response() {
            // response is not a response!
            return Ok(ConnCheckResponse::Failure(conncheck));
        }

        // if response error -> fail TODO: might be a recoverable error!
        if response.has_class(MessageClass::Error) {
            warn!("error response {}", response);
            if let Some(err) = response.attribute::<ErrorCode>(ERROR_CODE) {
                if err.code() == ErrorCode::ROLE_CONFLICT {
                    info!("Role conflict received {}", response);
                    return Ok(ConnCheckResponse::RoleConflict(conncheck, !controlling));
                }
            }
            // FIXME: some failures are recoverable
            return Ok(ConnCheckResponse::Failure(conncheck));
        }

        // if response success:
        // if mismatched address -> fail
        if from != to {
            warn!(
                "response came from different ip {:?} than candidate {:?}",
                from, to
            );
            return Ok(ConnCheckResponse::Failure(conncheck));
        }

        if let Some(xor) = response.attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS) {
            let xor_addr = xor.addr(response.transaction_id());
            // TODO: if response mapped address not in remote candidate list -> new peer-reflexive candidate
            // TODO glare
            return Ok(ConnCheckResponse::Success(conncheck, xor_addr));
        }

        Ok(ConnCheckResponse::Failure(conncheck))
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
pub struct ConnCheckList {
    checklist_id: usize,
    inner: Arc<Mutex<ConnCheckListInner>>,
}

#[derive(Debug)]
struct ConnCheckLocalCandidate {
    candidate: Candidate,
    stun_agent: StunAgent,
    stun_recv_abort: AbortHandle,
    data_recv_abort: AbortHandle,
}

#[derive(Debug)]
struct ConnCheckListInner {
    checklist_id: usize,
    set_inner: Weak<Mutex<CheckListSetInner>>,
    state: CheckListState,
    component_ids: Vec<usize>,
    components: Vec<Weak<Component>>,
    local_credentials: Credentials,
    remote_credentials: Credentials,
    local_candidates: Vec<ConnCheckLocalCandidate>,
    remote_candidates: Vec<Candidate>,
    // TODO: move to BinaryHeap or similar
    triggered: VecDeque<Arc<ConnCheck>>,
    pairs: VecDeque<Arc<ConnCheck>>,
    valid: Vec<CandidatePair>,
}

impl ConnCheckListInner {
    fn new(checklist_id: usize, set_inner: Weak<Mutex<CheckListSetInner>>) -> Self {
        Self {
            checklist_id,
            set_inner,
            state: CheckListState::Running,
            component_ids: vec![],
            components: vec![],
            local_credentials: Self::generate_random_credentials(),
            remote_credentials: Self::generate_random_credentials(),
            local_candidates: vec![],
            remote_candidates: vec![],
            triggered: VecDeque::new(),
            pairs: VecDeque::new(),
            valid: vec![],
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
        let alphabet =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/".as_bytes();
        let user = Self::generate_random_ice_string(alphabet, 4);
        let pass = Self::generate_random_ice_string(alphabet, 22);
        Credentials::new(user, pass)
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
            .position(|existing| existing.pair == check.pair)
        {
            // a nominating check trumps not nominating.  Otherwise, if the peers are delay sync,
            // then the non-nominating trigerred check may override the nomination process for a
            // long time and delay the connection process
            if check.nominate() && !self.triggered[idx].nominate() {
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

    #[tracing::instrument(
        level = "debug",
        skip(self)
        fields(
            self.checklist_id,
            remote.ctype = ?remote.candidate_type,
            remote.foundation = ?remote.foundation,
            remote.address = ?remote.address
        )
    )]
    fn add_remote_candidate(&mut self, remote: Candidate) {
        self.remote_candidates.push(remote);
    }

    fn check_is_equal(check: &Arc<ConnCheck>, pair: &CandidatePair, nominate: Nominate) -> bool {
        check.pair.local == pair.local
            && check.pair.remote == pair.remote
            && nominate.eq(&check.nominate)
    }

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

    fn take_matching_check(&mut self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        let pos = self
            .pairs
            .iter()
            .position(|check| check.pair.local == pair.local && check.pair.remote == pair.remote);
        if let Some(position) = pos {
            self.pairs.remove(position)
        } else {
            None
        }
    }

    fn add_check(&mut self, check: Arc<ConnCheck>) {
        self.pairs.push_front(check)
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, pair),
        fields(component.id = pair.local.component_id)
    )]
    fn nominated_pair(&mut self, pair: &CandidatePair) -> Option<Arc<Component>> {
        if let Some(idx) = self.valid.iter().position(|valid_pair| valid_pair == pair) {
            info!(
                ttype = ?pair.local.transport_type,
                local.address = ?pair.local.address,
                remote.address = ?pair.remote.address,
                local.ctype = ?pair.local.candidate_type,
                remote.ctype = ?pair.remote.candidate_type,
                foundation = %pair.foundation(),
                "nominated"
            );
            self.valid[idx].nominate();
            let component = self
                .components
                .iter()
                .filter_map(|component| component.upgrade())
                .find(|component| component.id == pair.local.component_id);
            if self.state == CheckListState::Running {
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
                self.dump_check_state();
                self.triggered.retain(|check| {
                    if check.pair.local.component_id == pair.local.component_id {
                        check.cancel();
                        false
                    } else {
                        true
                    }
                });
                self.pairs.retain(|check| {
                    if check.pair.local.component_id == pair.local.component_id {
                        check.cancel();
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
                    self.valid.iter().any(|valid_pair| {
                        valid_pair.local.component_id == component_id && valid_pair.nominated()
                    })
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
                    self.valid
                        .iter()
                        .fold(vec![], |mut component_ids_selected, valid_pair| {
                            // Only nominate one valid candidatePair
                            if !component_ids_selected
                                .iter()
                                .any(|&comp_id| comp_id == valid_pair.local.component_id)
                            {
                                if let Some(component) = &component {
                                    let local_agent = self
                                        .local_candidates
                                        .iter()
                                        .find(|cand| cand.candidate == pair.local)
                                        .map(|cand| cand.stun_agent.clone());
                                    if let Some(local_agent) = local_agent {
                                        component.set_selected_pair(SelectedPair::new(
                                            pair.clone(),
                                            local_agent,
                                        ));
                                    } else {
                                        panic!("Cannot find existing local stun agent!");
                                    }
                                }
                                component_ids_selected.push(valid_pair.local.component_id);
                            }
                            component_ids_selected
                        });
                    self.set_state(CheckListState::Completed);
                }
            }
            debug!(
                "trying to signal component {:?}",
                component.clone().map(|c| c.id)
            );
            return component;
        } else {
            warn!("unknown nomination");
        }
        None
    }

    fn dump_check_state(&self) {
        let mut s = format!("checklist {}", self.checklist_id);
        for pair in self.pairs.iter() {
            s += &format!(
                "\nID:{:<3} foundation:{:8} state:{:10} nom:{:6} priority:{:10},{:10} trans:{:4} local:{:5} {:32} remote:{:5} {:32}",
                pair.conncheck_id,
                pair.pair.foundation(),
                format!("{:?}", pair.state()),
                pair.nominate(),
                pair.pair.local.priority,
                pair.pair.remote.priority,
                format!("{:?}", pair.pair.local.transport_type),
                format!("{}", pair.pair.local.candidate_type),
                format!("{}", pair.pair.local.address),
                format!("{}", pair.pair.remote.candidate_type),
                format!("{}", pair.pair.remote.address)
            );
        }
        debug!("{}", s);
    }

    #[tracing::instrument(
        level = "debug",
        err
        skip(self, local, agent, from, priority)
        fields(
            checklist_id = self.checklist_id,
            state = ?self.state,
        )
    )]
    fn handle_binding_request(
        &mut self,
        peer_nominating: bool,
        component_id: usize,
        local: &Candidate,
        agent: StunAgent,
        from: SocketAddr,
        priority: u32,
    ) -> Result<Option<Arc<Component>>, AgentError> {
        let remote = self
            .find_remote_candidate(component_id, local.transport_type, from)
            .unwrap_or_else(|| {
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
                //      signal the actual foundation for the candidate.
                let cand = Candidate::builder(
                    component_id,
                    CandidateType::PeerReflexive,
                    local.transport_type,
                    /* FIXME */ "rflx",
                    priority,
                    from,
                )
                .build();
                debug!("new reflexive remote {:?}", cand);
                self.add_remote_candidate(cand.clone());
                cand
            });
        // RFC 8445 Section 7.3.1.4. Triggered Checks
        let pair = CandidatePair::new(local.clone(), remote);
        if let Some(mut check) = self.take_matching_check(&pair) {
            // When the pair is already on the checklist:
            trace!("found existing check {:?}", check);
            match check.state() {
                // If the state of that pair is Succeeded, nothing further is
                // done.
                CandidatePairState::Succeeded => {
                    if peer_nominating {
                        debug!("existing pair succeeded -> nominate");
                        check = Arc::new(ConnCheck::new(
                            check.pair.clone(),
                            check.agent.clone(),
                            true,
                        ));
                        if let Some(component) = self.nominated_pair(&pair) {
                            self.add_check(check);
                            return Ok(Some(component));
                        }
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
                    check.cancel();
                    if peer_nominating {
                        check = Arc::new(ConnCheck::new(
                            check.pair.clone(),
                            check.agent.clone(),
                            true,
                        ));
                    }
                    check.set_state(CandidatePairState::Waiting);
                    self.add_triggered(check.clone());
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
                    if peer_nominating {
                        check = Arc::new(ConnCheck::new(
                            check.pair.clone(),
                            check.agent.clone(),
                            true,
                        ));
                    }
                    check.set_state(CandidatePairState::Waiting);
                    self.add_triggered(check.clone());
                }
            }
            self.add_check(check);
        } else {
            debug!("creating new check for pair {:?}", pair);
            let check = Arc::new(ConnCheck::new(pair, agent.clone(), peer_nominating));
            check.set_state(CandidatePairState::Waiting);
            self.pairs.push_back(check.clone());
            self.add_triggered(check);
        }

        Ok(None)
    }
}

fn binding_success_response(
    msg: &Message,
    from: SocketAddr,
    local_credentials: MessageIntegrityCredentials,
) -> Result<Message, AgentError> {
    let mut response = Message::new_success(msg);
    response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
    response.add_message_integrity(&local_credentials)?;
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
        self == &Nominate::DontCare
            || (*other && self == &Nominate::True)
            || (!*other && self == &Nominate::False)
    }
}

impl ConnCheckList {
    fn state(&self) -> CheckListState {
        self.inner.lock().unwrap().state
    }

    fn set_state(&self, state: CheckListState) {
        let mut inner = self.inner.lock().unwrap();
        inner.set_state(state);
    }

    pub(crate) fn set_local_credentials(&self, credentials: Credentials) {
        let mut inner = self.inner.lock().unwrap();
        inner.local_credentials = credentials;
    }

    pub(crate) fn set_remote_credentials(&self, credentials: Credentials) {
        let mut inner = self.inner.lock().unwrap();
        inner.remote_credentials = credentials;
    }

    async fn handle_binding_request(
        weak_inner: Weak<Mutex<ConnCheckListInner>>,
        component_id: usize,
        local: &Candidate,
        agent: StunAgent,
        msg: &Message,
        from: SocketAddr,
    ) -> Result<Option<Message>, AgentError> {
        trace!("have request {}", msg);

        let local_credentials = agent
            .local_credentials()
            .ok_or(AgentError::ResourceNotFound)?;

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
            if let Some(use_candidate_raw) = msg.attribute::<RawAttribute>(USE_CANDIDATE) {
                if UseCandidate::from_raw(&use_candidate_raw).is_ok() {
                    true
                } else {
                    return Ok(Some(Message::bad_request(msg)?));
                }
            } else {
                false
            };

        let priority = match msg.attribute::<Priority>(PRIORITY) {
            Some(p) => p.priority(),
            None => {
                return Ok(Some(Message::bad_request(msg)?));
            }
        };

        let ice_controlling = msg.attribute::<IceControlling>(ICE_CONTROLLING);
        let ice_controlled = msg.attribute::<IceControlled>(ICE_CONTROLLED);

        let response = {
            let checklist = weak_inner.upgrade().ok_or(AgentError::ConnectionClosed)?;
            let mut checklist = checklist.lock().unwrap();

            if checklist.state == CheckListState::Completed && !peer_nominating {
                // ignore binding requests if we are completed
                trace!("ignoring binding request as we have completed");
                return Ok(None);
            }

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
                return Ok(Some(Message::bad_request(msg)?));
            }

            {
                // Deal with role conflicts
                // RFC 8445 7.3.1.1.  Detecting and Repairing Role Conflicts
                let set = checklist
                    .set_inner
                    .upgrade()
                    .ok_or(AgentError::ConnectionClosed)?;
                let mut set = set.lock().unwrap();
                if let Some(ice_controlling) = ice_controlling {
                    //  o  If the agent is in the controlling role, and the ICE-CONTROLLING
                    //     attribute is present in the request:
                    if set.controlling {
                        if set.tie_breaker >= ice_controlling.tie_breaker() {
                            // *  If the agent's tiebreaker value is larger than or equal to the
                            //    contents of the ICE-CONTROLLING attribute, the agent generates
                            //    a Binding error response and includes an ERROR-CODE attribute
                            //    with a value of 487 (Role Conflict) but retains its role.
                            let mut response = Message::new_error(msg);
                            response.add_attribute(
                                ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?,
                            )?;
                            return Ok(Some(response));
                        } else {
                            // *  If the agent's tiebreaker value is less than the contents of
                            //    the ICE-CONTROLLING attribute, the agent switches to the
                            //    controlled role.
                            set.controlling = false;
                            // TODO: update priorities and other things
                        }
                    }
                }
                if let Some(ice_controlled) = ice_controlled {
                    // o  If the agent is in the controlled role, and the ICE-CONTROLLED
                    //    attribute is present in the request:
                    if !set.controlling {
                        if set.tie_breaker >= ice_controlled.tie_breaker() {
                            // *  If the agent's tiebreaker value is larger than or equal to the
                            //    contents of the ICE-CONTROLLED attribute, the agent switches to
                            //    the controlling role.
                            set.controlling = true;
                            // TODO: update priorities and other things
                        } else {
                            // *  If the agent's tiebreaker value is less than the contents of
                            //    the ICE-CONTROLLED attribute, the agent generates a Binding
                            //    error response and includes an ERROR-CODE attribute with a
                            //    value of 487 (Role Conflict) but retains its role.
                            let mut response = Message::new_error(msg);
                            response.add_attribute(
                                ErrorCode::builder(ErrorCode::ROLE_CONFLICT).build()?,
                            )?;
                            return Ok(Some(response));
                        }
                    }
                }
            }

            checklist.handle_binding_request(
                peer_nominating,
                component_id,
                local,
                agent,
                from,
                priority,
            )?
        };
        if let Some(component) = response {
            component.set_state(ComponentState::Connected).await;
        }
        Ok(Some(binding_success_response(
            msg,
            from,
            local_credentials,
        )?))
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, component, local, agent),
        fields(
            checklist_id = self.checklist_id,
            component_id = component.id,
            ttype = ?local.transport_type,
            ctype = ?local.candidate_type,
            foundation = %local.foundation,
            address = ?local.address
        )
    )]
    pub(crate) async fn add_local_candidate(
        &self,
        component: &Arc<Component>,
        local: Candidate,
        agent: StunAgent,
    ) {
        if component.id != local.component_id {
            panic!(
                "attempt to add local candidate with component id {} to component with id {}",
                local.component_id, component.id
            );
        }

        debug!("adding {:?}", local);
        let checklist_id = self.checklist_id;
        let component_id = component.id;
        let weak_inner = Arc::downgrade(&self.inner);
        let (stun_send, stun_recv) = oneshot::channel();

        // We need to listen for and respond to stun binding requests for the local candidate
        let (abortable, stun_abort_handle) = futures::future::abortable({
            let agent = agent.clone();
            let local = local.clone();
            let span = debug_span!(
                parent: None,
                "conncheck_cand_recv_loop",
                checklist_id,
                component_id,
                ttype = ?local.transport_type,
                ctype = ?local.candidate_type,
                foundation = %local.foundation,
                address = ?local.address
            );
            async move {
                let _drop_log = DropLogger::new("dropping stun receive stream");
                let mut recv_stun = agent.receive_stream();
                if stun_send.send(()).is_err() {
                    panic!("stun receiver not connected anymore async task run");
                }
                while let Some(stun_or_data) = recv_stun.next().await {
                    if let Some((msg, from)) = stun_or_data.stun() {
                        // RFC8445 Section 7.3. STUN Server Procedures
                        if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                            match ConnCheckList::handle_binding_request(
                                weak_inner.clone(),
                                component_id,
                                &local,
                                agent.clone(),
                                &msg,
                                from,
                            )
                            .await
                            {
                                Ok(Some(response)) => {
                                    trace!("sending response {}", response);
                                    if let Err(e) = agent.send_to(response, from).await {
                                        warn!("error! {:?}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!("error! {:?}", e);
                                    break;
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            .instrument(span.or_current())
        });

        async_std::task::spawn(abortable);
        if stun_recv.await.is_err() {
            warn!("Failed to start listening task");
            return;
        }
        let data_abort_handle = component.add_recv_agent(agent.clone()).await;
        trace!(
            "checklist {} added recv task for candidate {:?}",
            self.checklist_id,
            local
        );

        {
            let mut inner = self.inner.lock().unwrap();
            inner.local_candidates.push(ConnCheckLocalCandidate {
                candidate: local,
                stun_agent: agent,
                // FIXME: abort when closing or not needing stun for candidate
                stun_recv_abort: stun_abort_handle,
                data_recv_abort: data_abort_handle,
            });
            let existing = inner.components.iter().find(|&v| {
                if let Some(component) = Weak::upgrade(v) {
                    component.id == component_id
                } else {
                    false
                }
            });
            if existing.is_none() {
                debug!("adding component {:?}", component);
                inner.component_ids.push(component_id);
                inner.components.push(Arc::downgrade(component));
            } else {
                trace!("not adding component {} again", component_id);
            }
        }
    }

    pub(crate) fn add_remote_candidate(&self, remote: Candidate) {
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner
                .component_ids
                .iter()
                .any(|&v| v == remote.component_id)
            {
                inner.component_ids.push(remote.component_id);
            }
            inner.add_remote_candidate(remote);
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn generate_checks(&self) {
        let mut inner = self.inner.lock().unwrap();
        let mut checks = vec![];
        let mut pairs: Vec<_> = inner.pairs.iter().map(|check| check.pair.clone()).collect();
        for local in inner.local_candidates.iter() {
            for remote in inner.remote_candidates.iter() {
                if local.candidate.transport_type == remote.transport_type
                    && local.candidate.component_id == remote.component_id
                    && local.candidate.address.is_ipv4() == remote.address.is_ipv4()
                    && local.candidate.address.is_ipv6() == remote.address.is_ipv6()
                {
                    let pair = CandidatePair::new(local.candidate.clone(), remote.clone());

                    if pair.redundant_with(pairs.iter()) {
                        trace!("not adding redundant pair");
                    } else {
                        debug!("generated pair {:?}", pair);
                        pairs.push(pair.clone());
                        checks.push(Arc::new(ConnCheck::new(
                            pair,
                            local.stun_agent.clone(),
                            false,
                        )));
                    }
                }
            }
        }
        inner.pairs.extend(checks);
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, thawn_foundations)
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn initial_thaw(&self, thawn_foundations: &mut Vec<String>) {
        let mut inner = self.inner.lock().unwrap();
        debug!("state change from {:?} to Running", inner.state);
        inner.state = CheckListState::Running;

        let _: Vec<_> = inner
            .pairs
            .iter_mut()
            .map(|check| {
                check.set_state(CandidatePairState::Frozen);
            })
            .collect();

        // get all the candidates that don't match any of the already thawn foundations
        let mut maybe_thaw: Vec<_> = inner
            .pairs
            .iter_mut()
            .filter(|check| {
                !thawn_foundations
                    .iter()
                    .any(|foundation| &check.pair.foundation() == foundation)
            })
            .collect();
        // sort by component_id
        maybe_thaw.sort_unstable_by(|a, b| {
            a.pair
                .local
                .component_id
                .partial_cmp(&b.pair.local.component_id)
                .unwrap()
        });

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

    fn next_triggered(&self) -> Option<Arc<ConnCheck>> {
        self.inner.lock().unwrap().triggered.pop_back()
    }

    #[cfg(test)]
    fn is_triggered(&self, needle: &Arc<ConnCheck>) -> bool {
        let inner = self.inner.lock().unwrap();
        trace!("triggered {:?}", inner.triggered);
        inner
            .triggered
            .iter()
            .any(|check| needle.pair == check.pair)
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
        self.inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            // first look for any that are waiting
            // FIXME: should be highest priority pair: make the data structure give us that by
            // default
            .filter(|check| {
                if check.state() == CandidatePairState::Waiting {
                    check.set_state(CandidatePairState::InProgress);
                    true
                } else {
                    false
                }
            })
            .cloned()
            .next()
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
        self.inner
            .lock()
            .unwrap()
            .pairs
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
            .inner
            .lock()
            .unwrap()
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
        self.inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            .fold(true, |accum, elem| {
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

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn add_valid(&self, pair: CandidatePair) {
        self.inner.lock().unwrap().valid.push(pair);
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            checklist_id = self.checklist_id
        )
    )]
    fn remove_valid(&self, pair: &CandidatePair) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(idx) = inner.valid.iter().position(|valid_pair| valid_pair == pair) {
            debug!("removing");
            inner.valid.remove(idx);
        }
    }

    async fn nominated_pair(&self, pair: &CandidatePair) {
        let component = self.inner.lock().unwrap().nominated_pair(pair);
        if let Some(component) = component {
            component.set_state(ComponentState::Connected).await;
        }
    }

    fn matching_check(&self, pair: &CandidatePair, nominate: Nominate) -> Option<Arc<ConnCheck>> {
        self.inner.lock().unwrap().matching_check(pair, nominate)
    }

    pub(crate) fn local_candidates(&self) -> Vec<Candidate> {
        self.inner
            .lock()
            .unwrap()
            .local_candidates
            .iter()
            .map(|local| local.candidate.clone())
            .collect()
    }

    pub(crate) fn remote_candidates(&self) -> Vec<Candidate> {
        self.inner.lock().unwrap().remote_candidates.to_vec()
    }

    fn try_nominate(&self) {
        let mut inner = self.inner.lock().unwrap();

        let retrigerred: Vec<_> = inner
            .component_ids
            .iter()
            .cloned()
            .map(|component_id| {
                let mut valid: Vec<_> = inner
                    .valid
                    .iter()
                    .cloned()
                    .filter(|pair| pair.local.component_id == component_id)
                    .collect();
                valid.sort_by(|pair1, pair2| {
                    pair1
                        .priority(true /* if we are nominating, we are controlling */)
                        .cmp(&pair2.priority(true))
                });
                // FIXME: Nominate when there are two valid candidates
                // what if there is only ever one valid?
                if !valid.is_empty() {
                    valid.iter().cloned().next()
                } else {
                    None
                }
            })
            .collect();
        if retrigerred.iter().all(|pair| pair.is_some()) {
            let _: Vec<_> = retrigerred
                .iter()
                .map(|pair| {
                    let pair = pair.clone().unwrap(); // checked earlier
                    if let Some(agent) = inner
                        .local_candidates
                        .iter()
                        .find(|&local_cand| local_cand.candidate == pair.local)
                        .map(|local| local.stun_agent.clone())
                    {
                        inner.add_triggered(Arc::new(ConnCheck::new(pair, agent, true)));
                    }
                })
                .collect();
        }
    }
}

#[derive(Debug)]
enum ConnCheckResponse {
    Success(Arc<ConnCheck>, SocketAddr),
    RoleConflict(Arc<ConnCheck>, bool),
    Failure(Arc<ConnCheck>),
}

pub(crate) struct ConnCheckListSetBuilder {
    clock: Option<Arc<dyn Clock>>,
    tie_breaker: u64,
    controlling: bool,
}

impl ConnCheckListSetBuilder {
    fn new(tie_breaker: u64, controlling: bool) -> Self {
        Self {
            clock: None,
            tie_breaker,
            controlling,
        }
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub(crate) fn build(self) -> ConnCheckListSet {
        let clock = self
            .clock
            .unwrap_or_else(|| get_clock(ClockType::default()));

        ConnCheckListSet {
            clock,
            inner: Arc::new(Mutex::new(CheckListSetInner {
                checklists: vec![],
                tie_breaker: self.tie_breaker,
                controlling: self.controlling,
            })),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnCheckListSet {
    clock: Arc<dyn Clock>,
    inner: Arc<Mutex<CheckListSetInner>>,
}

#[derive(Debug)]
pub(crate) struct CheckListSetInner {
    checklists: Vec<Arc<ConnCheckList>>,
    tie_breaker: u64,
    controlling: bool,
}

impl ConnCheckListSet {
    // TODO: add/remove a stream after start
    // TODO: cancel when agent is stopped
    pub(crate) fn builder(tie_breaker: u64, controlling: bool) -> ConnCheckListSetBuilder {
        ConnCheckListSetBuilder::new(tie_breaker, controlling)
    }

    pub(crate) fn new_list(&self) -> ConnCheckList {
        let checklist_id = CONN_CHECK_LIST_COUNT.fetch_add(1, Ordering::SeqCst);
        ConnCheckList {
            checklist_id,
            inner: Arc::new(Mutex::new(ConnCheckListInner::new(
                checklist_id,
                Arc::downgrade(&self.inner),
            ))),
        }
    }

    pub(crate) fn add_stream(&self, stream: Arc<crate::stream::Stream>) {
        let mut inner = self.inner.lock().unwrap();
        inner.checklists.push(stream.checklist.clone());
    }

    pub(crate) fn set_controlling(&self, controlling: bool) {
        let mut inner = self.inner.lock().unwrap();
        // XXX: do we need to update any other state here?
        inner.controlling = controlling;
    }

    pub(crate) fn controlling(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.controlling
    }

    #[tracing::instrument(
        level = "trace",
        ret,
        skip(conncheck),
        fields(
            conncheck.conncheck_id
        )
    )]
    async fn connectivity_check_cancellable(
        conncheck: Arc<ConnCheck>,
        username: String,
        controlling: bool,
        tie_breaker: u64,
    ) -> Result<ConnCheckResponse, AgentError> {
        let abort_registration = {
            let mut inner = conncheck.state.lock().unwrap();
            if inner.abort_handle.is_some() {
                panic!("duplicate connection checks!");
                //            return Err(AgentError::AlreadyExists);
            }

            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            inner.abort_handle = Some(abort_handle);
            abort_registration
        };

        let abortable = Abortable::new(
            ConnCheck::connectivity_check(conncheck, username, controlling, tie_breaker),
            abort_registration,
        );
        async_std::task::spawn(
            async move {
                match abortable.await {
                    Ok(v) => v,
                    Err(_) => Err(AgentError::Aborted),
                }
            }
            .in_current_span(),
        )
        .await
    }

    #[tracing::instrument(
        name = "perform_conncheck"
        level = "debug",
        err,
        skip(conncheck, checklist, set_inner),
        fields(
            checklist_id = checklist.checklist_id,
            conncheck_id = conncheck.conncheck_id
        )
    )]
    async fn perform_conncheck(
        conncheck: Arc<ConnCheck>,
        checklist: Arc<ConnCheckList>,
        set_inner: Weak<Mutex<CheckListSetInner>>,
    ) -> Result<(), AgentError> {
        trace!("performing connectivity {:?}", &conncheck);
        let (controlling, tie_breaker) = {
            if let Some(set_inner) = set_inner.upgrade() {
                let set_inner = set_inner.lock().unwrap();
                (set_inner.controlling, set_inner.tie_breaker)
            } else {
                return Err(AgentError::Aborted);
            }
        };
        let username = {
            let inner = checklist.inner.lock().unwrap();
            inner.remote_credentials.ufrag.clone() + ":" + &inner.local_credentials.ufrag
        };
        match ConnCheckListSet::connectivity_check_cancellable(
            conncheck.clone(),
            username,
            controlling,
            tie_breaker,
        )
        .await
        {
            Err(e) => {
                warn!(error = ?e, "conncheck error: {:?}", conncheck);
                conncheck.set_state(CandidatePairState::Failed);
                checklist.remove_valid(&conncheck.pair);
                match e {
                    AgentError::Aborted => (),
                    _ => checklist.set_state(CheckListState::Failed),
                }
            }
            Ok(ConnCheckResponse::Failure(conncheck)) => {
                warn!("conncheck failure: {:?}", conncheck);
                conncheck.set_state(CandidatePairState::Failed);
                checklist.remove_valid(&conncheck.pair);
                if conncheck.nominate() {
                    checklist.set_state(CheckListState::Failed);
                }
            }
            Ok(ConnCheckResponse::RoleConflict(conncheck, new_role)) => {
                if let Some(set_inner) = set_inner.upgrade() {
                    let mut set_inner = set_inner.lock().unwrap();
                    info!(
                        old_role = set_inner.controlling,
                        new_role, "Role Conflict changing controlling from"
                    );
                    if set_inner.controlling != new_role {
                        set_inner.controlling = new_role;
                        checklist.remove_valid(&conncheck.pair);
                        conncheck.cancel();
                        let conncheck = Arc::new(ConnCheck::new(
                            conncheck.pair.clone(),
                            conncheck.agent.clone(),
                            false,
                        ));
                        conncheck.set_state(CandidatePairState::Waiting);
                        let mut list_inner = checklist.inner.lock().unwrap();
                        list_inner.add_triggered(conncheck);
                    }
                } else {
                    return Err(AgentError::Aborted);
                }
            }
            Ok(ConnCheckResponse::Success(conncheck, addr)) => {
                info!(
                    component.id = conncheck.pair.local.component_id,
                    nominate = conncheck.nominate,
                    ttype = ?conncheck.pair.local.transport_type,
                    local.address = ?conncheck.pair.local.address,
                    remote.address = ?conncheck.pair.remote.address,
                    local.ctype = ?conncheck.pair.local.candidate_type,
                    remote.ctype = ?conncheck.pair.remote.candidate_type,
                    foundation = %conncheck.pair.foundation(),
                    "succeeded in finding a connection"
                );
                conncheck.set_state(CandidatePairState::Succeeded);

                let mut pair_dealt_with = false;
                let ok_pair = conncheck.pair.construct_valid(addr);
                // 1.
                // If the valid pair equals the pair that generated the check, the
                // pair is added to the valid list associated with the checklist to
                // which the pair belongs; or
                if let Some(_check) = checklist.matching_check(&ok_pair, Nominate::DontCare) {
                    checklist.add_valid(ok_pair.clone());
                    if conncheck.nominate() {
                        checklist.nominated_pair(&conncheck.pair).await;
                        return Ok(());
                    }
                    pair_dealt_with = true;
                } else {
                    // 2.
                    // If the valid pair equals another pair in a checklist, that pair
                    // is added to the valid list associated with the checklist of that
                    // pair.  The pair that generated the check is not added to a vali
                    // list; or
                    let checklists = {
                        if let Some(set_inner) = set_inner.upgrade() {
                            let set_inner = set_inner.lock().unwrap();
                            set_inner.checklists.clone()
                        } else {
                            return Err(AgentError::Aborted);
                        }
                    };
                    for checklist in checklists.iter() {
                        if let Some(check) = checklist.matching_check(&ok_pair, Nominate::DontCare)
                        {
                            checklist.add_valid(check.pair.clone());
                            if conncheck.nominate() {
                                checklist.nominated_pair(&conncheck.pair).await;
                                return Ok(());
                            }
                            pair_dealt_with = true;
                            break;
                        }
                    }
                }
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
                    // TODO: need to construct correct pair priorities, just use
                    // whatever the conncheck produced for now
                    checklist.add_valid(ok_pair);
                    checklist.add_valid(conncheck.pair.clone());

                    if conncheck.nominate() {
                        checklist.nominated_pair(&conncheck.pair).await;
                        return Ok(());
                    }
                }
                // Try and nominate some pair
                if controlling {
                    checklist.try_nominate();
                }
            } // TODO: continue binding keepalives/implement RFC7675
        }

        Ok(())
    }

    // RFC8445: 6.1.4.2. Performing Connectivity Checks
    fn next_check(&self, checklist: &ConnCheckList) -> Option<Arc<ConnCheck>> {
        {
            let checklist_inner = checklist.inner.lock().unwrap();
            checklist_inner.dump_check_state();
        }

        // 1.  If the triggered-check queue associated with the checklist
        //     contains one or more candidate pairs, the agent removes the top
        //     pair from the queue, performs a connectivity check on that pair,
        //     puts the candidate pair state to In-Progress, and aborts the
        //     subsequent steps.
        if let Some(check) = checklist.next_triggered() {
            trace!("next check was a trigerred check {:?}", check);
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
            let inner = self.inner.lock().unwrap();
            let mut foundations = std::collections::HashSet::new();
            for checklist in inner.checklists.iter() {
                for f in checklist.foundations() {
                    foundations.insert(f);
                }
            }
            let mut foundations_not_waiting_in_progress = std::collections::HashSet::new();
            let _: Vec<_> = foundations
                .into_iter()
                .map(|f| {
                    if inner
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

    #[tracing::instrument(name = "ConnCheckList Loop", level = "debug", err, skip(self))]
    pub(crate) async fn agent_conncheck_process(&self) -> Result<(), AgentError> {
        // perform initial set up
        {
            let inner = self.inner.lock().unwrap();
            for checklist in inner.checklists.iter() {
                checklist.generate_checks();
            }

            let mut thawn_foundations = vec![];
            for checklist in inner.checklists.iter() {
                checklist.initial_thaw(&mut thawn_foundations);
            }
        }

        let mut running = RunningCheckListSet::from_set(self);

        loop {
            match running.process_next().await {
                CheckListSetProcess::Completed => break,
                CheckListSetProcess::HaveCheck(check) => {
                    async_std::task::spawn(check.perform());
                }
                CheckListSetProcess::NothingToDo => (),
            }
            let delay = self
                .clock
                .delay(Duration::from_millis(100 /* FIXME */))
                .await;
            delay.wait().await;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct OutstandingConnCheck {
    conncheck: Arc<ConnCheck>,
    checklist: Arc<ConnCheckList>,
    set_inner: Weak<Mutex<CheckListSetInner>>,
}

impl OutstandingConnCheck {
    async fn perform(self) -> Result<(), AgentError> {
        ConnCheckListSet::perform_conncheck(self.conncheck, self.checklist, self.set_inner).await
    }
}

#[derive(Debug)]
enum CheckListSetProcess {
    HaveCheck(OutstandingConnCheck),
    NothingToDo,
    Completed,
}

struct RunningCheckListSet<'set> {
    set: &'set ConnCheckListSet,
    checklist_i: usize,
}

impl<'set> RunningCheckListSet<'set> {
    pub(crate) fn from_set(set: &'set ConnCheckListSet) -> Self {
        Self {
            set,
            checklist_i: 0,
        }
    }

    // perform one tick of the connection state machine
    pub(crate) async fn process_next(&mut self) -> CheckListSetProcess {
        let mut any_running = false;
        loop {
            let start_idx = self.checklist_i;
            let checklist = {
                let set_inner = self.set.inner.lock().unwrap();
                let checklist = &set_inner.checklists[self.checklist_i];
                self.checklist_i += 1;
                if self.checklist_i >= set_inner.checklists.len() {
                    self.checklist_i = 0;
                }
                if checklist.state() == CheckListState::Running {
                    any_running = true;
                }
                checklist.clone()
            };
            let conncheck = match self.set.next_check(&checklist) {
                Some(c) => c,
                None => {
                    if start_idx == self.checklist_i {
                        // we looked at them all and none of the checklist could find anything to
                        // do
                        if !any_running {
                            return CheckListSetProcess::Completed;
                        } else {
                            return CheckListSetProcess::NothingToDo;
                        }
                    } else {
                        continue;
                    }
                }
            };

            let weak_set_inner = Arc::downgrade(&self.set.inner);
            return CheckListSetProcess::HaveCheck(OutstandingConnCheck {
                conncheck,
                checklist,
                set_inner: weak_set_inner,
            });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::candidate::*;
    use crate::clock::ClockType;
    use crate::stream::*;
    use crate::stun::agent::*;
    use crate::stun::socket::tests::*;
    use crate::stun::socket::*;
    use async_std::net::{TcpListener, TcpStream, UdpSocket};
    use async_std::task;
    use std::sync::Arc;

    fn init() {
        crate::tests::test_init_log();
    }

    struct Peer {
        channel: StunChannel,
        candidate: Candidate,
        agent: StunAgent,
        credentials: Credentials,
    }

    impl Peer {
        async fn default() -> Self {
            Peer::builder().build().await
        }

        fn builder<'this>() -> PeerBuilder<'this> {
            PeerBuilder::default()
        }
    }

    struct PeerBuilder<'this> {
        channel: Option<StunChannel>,
        foundation: Option<&'this str>,
        clock: Option<Arc<dyn Clock>>,
        credentials: Credentials,
        component_id: Option<usize>,
        candidate: Option<Candidate>,
    }

    impl<'this> PeerBuilder<'this> {
        fn channel(mut self, channel: StunChannel) -> Self {
            self.channel = Some(channel);
            self
        }

        fn foundation(mut self, foundation: &'this str) -> Self {
            self.foundation = Some(foundation);
            self
        }

        fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
            self.clock = Some(clock);
            self
        }

        fn credentials(mut self, credentials: Credentials) -> Self {
            self.credentials = credentials;
            self
        }

        fn component_id(mut self, component_id: usize) -> Self {
            self.component_id = Some(component_id);
            self
        }

        fn candidate(mut self, candidate: Candidate) -> Self {
            self.candidate = Some(candidate);
            self
        }

        async fn build(self) -> Peer {
            let addr = self
                .candidate
                .as_ref()
                .map(|c| c.base_address)
                .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
            let ttype = self
                .candidate
                .as_ref()
                .map(|c| c.transport_type)
                .unwrap_or(TransportType::Udp);
            let channel = match self.channel {
                Some(c) => c,
                None => match ttype {
                    TransportType::Udp => {
                        let socket = UdpSocket::bind(addr).await.unwrap();
                        StunChannel::UdpAny(UdpSocketChannel::new(socket))
                    }
                    TransportType::Tcp => {
                        if addr.port() != 0 {
                            let stream = TcpStream::connect(addr).await.unwrap();
                            StunChannel::Tcp(TcpChannel::new(stream))
                        } else {
                            panic!("can't create tcp channel peer")
                        }
                    }
                    #[cfg(test)]
                    TransportType::AsyncChannel => panic!("can't create async channel peer"),
                },
            };
            if let Some(candidate) = &self.candidate {
                if let Some(component_id) = self.component_id {
                    if component_id != candidate.component_id {
                        panic!("mismatched component ids");
                    }
                }
                if let Some(foundation) = self.foundation {
                    if foundation != candidate.foundation {
                        panic!("mismatched foundations");
                    }
                }
            }
            let addr = channel.local_addr().unwrap();
            let candidate = self.candidate.unwrap_or_else(|| {
                Candidate::builder(
                    self.component_id.unwrap_or(1),
                    CandidateType::Host,
                    TransportType::Udp,
                    self.foundation.unwrap_or("0"),
                    0,
                    addr,
                )
                .build()
            });
            let clock = self.clock.unwrap_or_else(|| get_clock(ClockType::System));
            let agent = StunAgent::builder(channel.clone()).clock(clock).build();

            Peer {
                channel,
                candidate,
                agent,
                credentials: self.credentials,
            }
        }
    }

    impl<'this> Default for PeerBuilder<'this> {
        fn default() -> Self {
            Self {
                channel: None,
                foundation: None,
                clock: None,
                credentials: Credentials::new(String::from("user"), String::from("pass")),
                component_id: None,
                candidate: None,
            }
        }
    }

    #[test]
    fn get_candidates() {
        init();
        async_std::task::block_on(async move {
            let agent = Agent::default();
            let stream = agent.add_stream();
            let component = stream.add_component().unwrap();

            let local = Peer::default().await;
            let remote = Peer::default().await;

            let set = agent.check_list_set();
            let list = set.new_list();
            list.add_local_candidate(&component, local.candidate.clone(), local.agent.clone())
                .await;
            list.add_remote_candidate(remote.candidate.clone());

            // The candidate list is only what we put in
            let locals = list.local_candidates();
            assert_eq!(locals.len(), 1);
            assert_eq!(locals[0], local.candidate);
            let remotes = list.remote_candidates();
            assert_eq!(remotes.len(), 1);
            assert_eq!(remotes[0], remote.candidate);
        })
    }

    // simplified version of ConnCheckList handle_binding_request that doesn't
    // update any state like ConnCheckList or even do peer-reflexive candidate
    // things
    async fn handle_binding_request(
        agent: &StunAgent,
        local_credentials: &Credentials,
        msg: &Message,
        from: SocketAddr,
        error_response: Option<u16>,
    ) -> Result<Message, AgentError> {
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
            error!("missing ice controlled/controlling attribute");
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
            response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
            response
        };
        response.add_message_integrity(&local_stun_credentials)?;
        response.add_fingerprint()?;
        Ok(response)
    }

    fn reply_to_conncheck_task(agent: StunAgent, credentials: Credentials) {
        let mut remote_data_stream = agent.receive_stream();
        task::spawn({
            async move {
                while let Some(stun_or_data) = remote_data_stream.next().await {
                    match stun_or_data {
                        StunOrData::Data(data, from) => {
                            debug!("received from {} data: {:?}", from, data)
                        }
                        StunOrData::Stun(msg, from) => {
                            debug!("received from {}: {:?}", from, msg);
                            if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                                agent
                                    .send_to(
                                        handle_binding_request(
                                            &agent,
                                            &credentials,
                                            &msg,
                                            from,
                                            None,
                                        )
                                        .await
                                        .unwrap(),
                                        from,
                                    )
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn conncheck_udp_host() {
        init();
        async_std::task::block_on(async move {
            let local_credentials = Credentials::new(String::from("luser"), String::from("lpass"));
            let remote_credentials = Credentials::new(String::from("ruser"), String::from("rpass"));
            // start the remote peer
            let remote = Peer::default().await;
            remote
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));
            remote
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    local_credentials.clone().into(),
                ));
            // set up the local peer
            let local = Peer::default().await;
            local
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    local_credentials.clone().into(),
                ));
            local
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));

            reply_to_conncheck_task(remote.agent.clone(), remote_credentials.clone());
            reply_to_conncheck_task(local.agent.clone(), local_credentials.clone());

            let pair = CandidatePair::new(local.candidate, remote.candidate);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent, false));

            // this is what we're testing.  All of the above is setup for performing this check
            let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;
            let res =
                ConnCheckListSet::connectivity_check_cancellable(conncheck, username, true, 0)
                    .await
                    .unwrap();
            match res {
                ConnCheckResponse::Success(_check, addr) => {
                    assert_eq!(addr, local.channel.local_addr().unwrap());
                }
                _ => unreachable!(),
            }
        })
    }

    fn assert_list_contains_checks(list: &ConnCheckList, pairs: Vec<&CandidatePair>) {
        for pair in pairs.iter() {
            let check = list.matching_check(pair, Nominate::DontCare).unwrap();
            assert_eq!(&&check.pair, pair);
        }
    }

    #[test]
    fn checklist_generate_checks() {
        init();
        async_std::task::block_on(async move {
            let agent = Arc::new(Agent::default());
            let stream = agent.add_stream();
            let component1 = stream.add_component().unwrap();
            let component2 = stream.add_component().unwrap();
            let local1 = Peer::default().await;
            let remote1 = Peer::default().await;
            let local2 = Peer::builder().component_id(2).build().await;
            let remote2 = Peer::builder().component_id(2).build().await;
            let local3 = Peer::default().await;
            let remote3 = Peer::default().await;

            let set = agent.check_list_set();
            let list = set.new_list();
            list.add_local_candidate(&component1, local1.candidate.clone(), local1.agent)
                .await;
            list.add_remote_candidate(remote1.candidate.clone());
            list.add_local_candidate(&component2, local2.candidate.clone(), local2.agent)
                .await;
            list.add_remote_candidate(remote2.candidate.clone());
            list.add_local_candidate(&component1, local3.candidate.clone(), local3.agent)
                .await;
            list.add_remote_candidate(remote3.candidate.clone());

            list.generate_checks();
            let pair1 = CandidatePair::new(local1.candidate.clone(), remote1.candidate.clone());
            let pair2 = CandidatePair::new(local2.candidate.clone(), remote2.candidate.clone());
            let pair3 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
            let pair4 = CandidatePair::new(local1.candidate.clone(), remote3.candidate);
            let pair5 = CandidatePair::new(local3.candidate, remote1.candidate);
            assert_list_contains_checks(&list, vec![&pair1, &pair2, &pair3, &pair4, &pair5]);
        });
    }

    #[test]
    fn checklists_initial_thaw() {
        init();
        async_std::task::block_on(async move {
            let agent = Arc::new(Agent::default());
            let stream = agent.add_stream();
            let component1 = stream.add_component().unwrap();
            let component2 = stream.add_component().unwrap();
            let set = agent.check_list_set();
            let list1 = set.new_list();
            let list2 = set.new_list();

            let local1 = Peer::builder().foundation("0").build().await;
            let remote1 = Peer::builder().foundation("0").build().await;
            let local2 = Peer::builder()
                .foundation("0")
                .component_id(2)
                .build()
                .await;
            let remote2 = Peer::builder()
                .foundation("0")
                .component_id(2)
                .build()
                .await;
            let local3 = Peer::builder()
                .foundation("1")
                .component_id(2)
                .build()
                .await;
            let remote3 = Peer::builder()
                .foundation("1")
                .component_id(2)
                .build()
                .await;

            list1
                .add_local_candidate(&component1, local1.candidate.clone(), local1.agent)
                .await;
            list1.add_remote_candidate(remote1.candidate.clone());
            list2
                .add_local_candidate(&component2, local2.candidate.clone(), local2.agent)
                .await;
            list2.add_remote_candidate(remote2.candidate.clone());
            list2
                .add_local_candidate(&component2, local3.candidate.clone(), local3.agent)
                .await;
            list2.add_remote_candidate(remote3.candidate.clone());

            list1.generate_checks();
            list2.generate_checks();

            // generated pairs
            let pair1 = CandidatePair::new(local1.candidate, remote1.candidate);
            let pair2 = CandidatePair::new(local2.candidate.clone(), remote2.candidate.clone());
            let pair3 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
            let pair4 = CandidatePair::new(local2.candidate, remote3.candidate);
            let pair5 = CandidatePair::new(local3.candidate, remote2.candidate);
            assert_list_contains_checks(&list1, vec![&pair1]);
            assert_list_contains_checks(&list2, vec![&pair2, &pair3, &pair4, &pair5]);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            list1.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 1);
            assert_eq!(&thawn[0], &pair1.foundation());
            // thaw the second checklist with 2*2 pairs will unfreeze only the foundations not
            // unfrozen by the first checklist, which means unfreezing 3 pairs
            list2.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 4);
            assert!(thawn.iter().any(|f| f == &pair2.foundation()));
            assert!(thawn.iter().any(|f| f == &pair3.foundation()));
            assert!(thawn.iter().any(|f| f == &pair4.foundation()));
            assert!(thawn.iter().any(|f| f == &pair5.foundation()));
            let check1 = list1.matching_check(&pair1, Nominate::DontCare).unwrap();
            assert_eq!(check1.pair, pair1);
            assert_eq!(check1.state(), CandidatePairState::Waiting);
            let check2 = list2.matching_check(&pair2, Nominate::DontCare).unwrap();
            assert_eq!(check2.pair, pair2);
            assert_eq!(check2.state(), CandidatePairState::Frozen);
            let check3 = list2.matching_check(&pair3, Nominate::DontCare).unwrap();
            assert_eq!(check3.pair, pair3);
            assert_eq!(check3.state(), CandidatePairState::Waiting);
            let check4 = list2.matching_check(&pair4, Nominate::DontCare).unwrap();
            assert_eq!(check4.pair, pair4);
            assert_eq!(check4.state(), CandidatePairState::Waiting);
            let check5 = list2.matching_check(&pair5, Nominate::DontCare).unwrap();
            assert_eq!(check5.pair, pair5);
            assert_eq!(check5.state(), CandidatePairState::Waiting);
        });
    }

    struct FineControlPeer {
        component: Arc<Component>,
        peer: Peer,
        checklist_set: ConnCheckListSet,
        checklist: Arc<ConnCheckList>,
    }

    struct FineControl {
        local: FineControlPeer,
        remote: Peer,
    }

    struct FineControlBuilder {
        clock: Arc<dyn Clock>,
    }

    impl Default for FineControlBuilder {
        fn default() -> Self {
            Self {
                clock: Arc::new(crate::clock::tests::TestClock::default()),
            }
        }
    }

    impl FineControlBuilder {
        async fn build(self) -> FineControl {
            let local_credentials = Credentials::new("luser".into(), "lpass".into());
            let remote_credentials = Credentials::new("luser".into(), "lpass".into());
            let local_agent = Arc::new(Agent::default());
            let local_stream = local_agent.add_stream();
            let local_component = local_stream.add_component().unwrap();
            let router = ChannelRouter::default();

            let local_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(AsyncChannel::new(
                    router.clone(),
                    router.generate_addr(),
                    None,
                )))
                .foundation("0")
                .clock(self.clock.clone())
                .credentials(local_credentials.clone())
                .build()
                .await;
            local_peer
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    local_credentials.clone().into(),
                ));
            local_peer
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));

            let remote_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(AsyncChannel::new(
                    router.clone(),
                    router.generate_addr(),
                    None,
                )))
                .foundation("0")
                .clock(self.clock.clone())
                .credentials(remote_credentials.clone())
                .build()
                .await;
            remote_peer
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));
            remote_peer
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    local_credentials.clone().into(),
                ));

            let checklist_set = ConnCheckListSet::builder(0, true)
                .clock(self.clock.clone())
                .build();
            checklist_set.add_stream(local_stream.clone());
            let checklist = local_stream.checklist.clone();

            checklist
                .add_local_candidate(
                    &local_component,
                    local_peer.candidate.clone(),
                    local_peer.agent.clone(),
                )
                .await;
            checklist.add_remote_candidate(remote_peer.candidate.clone());
            checklist.set_local_credentials(local_credentials.clone());
            checklist.set_remote_credentials(remote_credentials);

            FineControl {
                local: FineControlPeer {
                    component: local_component,
                    peer: local_peer,
                    checklist_set,
                    checklist,
                },
                remote: remote_peer,
            }
        }
    }

    impl FineControl {
        fn builder() -> FineControlBuilder {
            FineControlBuilder::default()
        }
    }

    #[tracing::instrument(name = "test_send_check_and_get_response", skip(state, set_run))]
    async fn send_next_check_and_response(
        state: &FineControl,
        set_run: &mut RunningCheckListSet<'_>,
        error_response: Option<u16>,
    ) {
        let remote_s_recv = state.remote.channel.receive_stream();
        futures::pin_mut!(remote_s_recv);
        let local_s_recv = state.local.peer.agent.receive_stream();
        futures::pin_mut!(local_s_recv);

        // perform one tick which will start a connectivity check with the peer
        let set_ret = set_run.process_next().await;
        assert!(matches!(set_ret, CheckListSetProcess::HaveCheck(_)));
        debug!("tick");
        let check_task = async_std::task::spawn(async move {
            if let CheckListSetProcess::HaveCheck(check) = set_ret {
                check.perform().await.unwrap();
            } else {
                unreachable!()
            }
        });

        // receive and respond to the connectivity check
        let DataAddress {
            data,
            address: from,
        } = remote_s_recv.next().await.unwrap();
        debug!("received {:?}", data);
        assert_eq!(from, state.local.peer.channel.local_addr().unwrap());
        let msg = Message::from_bytes(&data).unwrap();
        assert_eq!(msg.method(), BINDING);
        assert_eq!(msg.class(), MessageClass::Request);

        // send a role confilict response
        let resp = handle_binding_request(
            &state.remote.agent,
            &state.remote.credentials,
            &msg,
            from,
            error_response,
        )
        .await
        .unwrap();
        info!("handle request {:?}", resp);
        state.remote.agent.send_to(resp, from).await.unwrap();

        // wait for the response to reach the checklist and update the state
        check_task.await;
        debug!("check done");
        let response = local_s_recv.next().await.unwrap();
        trace!("msg received {:?}", response);
    }

    #[test]
    fn very_fine_control1() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().build().await;
            assert_eq!(state.local.component.id, 1);

            state.local.checklist.generate_checks();

            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(check.state(), CandidatePairState::Frozen);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            state.local.checklist.initial_thaw(&mut thawn);
            assert_eq!(check.state(), CandidatePairState::Waiting);

            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);

            // perform one tick which will start a connectivity check with the peer
            send_next_check_and_response(&state, &mut set_run, None).await;
            assert_eq!(check.state(), CandidatePairState::Succeeded);

            // should have resulted in a nomination and therefore a triggered check (always a new
            // check in our implementation)
            let nominate_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::True)
                .unwrap();
            assert!(state.local.checklist.is_triggered(&nominate_check));

            // perform one tick which will perform the nomination check
            send_next_check_and_response(&state, &mut set_run, None).await;

            assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

            // check list is done
            assert_eq!(state.local.checklist.state(), CheckListState::Completed);

            // perform one final tick attempt which should end the processing
            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed
            ));
        });
    }

    #[test]
    fn role_conflict_response() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().build().await;

            // start of in the controlled mode, otherwise, the test needs to do the nomination
            // check
            state.local.checklist_set.set_controlling(false);
            state.local.checklist.generate_checks();

            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(check.state(), CandidatePairState::Frozen);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            state.local.checklist.initial_thaw(&mut thawn);
            assert_eq!(check.state(), CandidatePairState::Waiting);

            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);

            // perform one tick which will start a connectivity check with the peer
            send_next_check_and_response(&state, &mut set_run, Some(ErrorCode::ROLE_CONFLICT))
                .await;
            assert_eq!(check.state(), CandidatePairState::Failed);

            // should have resulted in the check being retriggered (always a new
            // check in our implementation)
            let triggered_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert!(state.local.checklist.is_triggered(&triggered_check));

            // perform the next tick which will have a different ice controlling/ed attribute
            send_next_check_and_response(&state, &mut set_run, None).await;
            assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);

            // should have resulted in a nomination and therefore a triggered check (always a new
            // check in our implementation)
            let nominate_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::True)
                .unwrap();
            assert!(state.local.checklist.is_triggered(&nominate_check));

            // perform one tick which will perform the nomination check
            send_next_check_and_response(&state, &mut set_run, None).await;

            // check list is done
            assert_eq!(state.local.checklist.state(), CheckListState::Completed);

            // perform one final tick attempt which should end the processing
            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed
            ));
        });
    }

    #[test]
    fn bad_username_conncheck() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().build().await;

            // set the wrong credentials and observe the failure
            let wrong_credentials =
                Credentials::new(String::from("wronguser"), String::from("wrongpass"));
            state
                .local
                .checklist
                .set_local_credentials(wrong_credentials);
            state.local.checklist.generate_checks();

            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(check.state(), CandidatePairState::Frozen);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            state.local.checklist.initial_thaw(&mut thawn);
            assert_eq!(check.state(), CandidatePairState::Waiting);

            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);

            // perform one tick which will start a connectivity check with the peer
            send_next_check_and_response(&state, &mut set_run, Some(ErrorCode::UNAUTHORIZED)).await;
            assert_eq!(check.state(), CandidatePairState::Failed);

            // TODO: properly failing the checklist on all checks failing
            // check should be failed
            // assert_eq!(state.local.checklist.state(), CheckListState::Failed);

            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::NothingToDo //CheckListSetProcess::Completed
            ));
        });
    }

    #[test]
    fn conncheck_tcp_host() {
        init();
        async_std::task::block_on(async move {
            let local_credentials = Credentials::new(String::from("luser"), String::from("lpass"));
            let remote_credentials = Credentials::new(String::from("ruser"), String::from("rpass"));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let remote_addr = listener.local_addr().unwrap();
            let listen_task = task::spawn({
                let local_credentials = local_credentials.clone();
                let remote_credentials = remote_credentials.clone();
                async move {
                    let mut incoming = listener.incoming();
                    while let Some(stream) = incoming.next().await {
                        let stream = stream.unwrap();
                        let remote_addr = stream.local_addr().unwrap();
                        let remote_cand = Candidate::builder(
                            0,
                            CandidateType::Host,
                            TransportType::Tcp,
                            "0",
                            0,
                            remote_addr,
                        )
                        .build();
                        let channel = StunChannel::Tcp(TcpChannel::new(stream));
                        let remote_peer = Peer::builder()
                            .channel(channel)
                            .candidate(remote_cand)
                            .build()
                            .await;
                        remote_peer.agent.set_local_credentials(
                            MessageIntegrityCredentials::ShortTerm(
                                remote_credentials.clone().into(),
                            ),
                        );
                        remote_peer.agent.set_remote_credentials(
                            MessageIntegrityCredentials::ShortTerm(
                                local_credentials.clone().into(),
                            ),
                        );
                        reply_to_conncheck_task(
                            remote_peer.agent.clone(),
                            remote_credentials.clone(),
                        );
                    }
                }
            });

            // set up the local peer
            let local_stream = TcpStream::connect(remote_addr).await.unwrap();
            let local_addr = local_stream.local_addr().unwrap();
            let local_channel = StunChannel::Tcp(TcpChannel::new(local_stream));
            let local_cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Tcp,
                "0",
                0,
                local_addr,
            )
            .build();
            let local = Peer::builder()
                .channel(local_channel)
                .candidate(local_cand)
                .build()
                .await;
            local
                .agent
                .set_local_credentials(MessageIntegrityCredentials::ShortTerm(
                    local_credentials.clone().into(),
                ));
            local
                .agent
                .set_remote_credentials(MessageIntegrityCredentials::ShortTerm(
                    remote_credentials.clone().into(),
                ));
            let remote_cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Tcp,
                "0",
                0,
                remote_addr,
            )
            .build();
            let pair = CandidatePair::new(local.candidate, remote_cand);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent, false));

            // this is what we're testing.  All of the above is setup for performing this check
            let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;
            let res =
                ConnCheckListSet::connectivity_check_cancellable(conncheck, username, true, 0)
                    .await
                    .unwrap();
            match res {
                ConnCheckResponse::Success(_check, addr) => {
                    assert_eq!(addr, local.channel.local_addr().unwrap());
                }
                _ => unreachable!(),
            }

            listen_task.cancel().await;
        });
    }
}
