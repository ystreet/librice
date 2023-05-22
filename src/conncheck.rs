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
use futures::future::AbortHandle;
use futures::prelude::*;
use tracing_futures::Instrument;

use crate::candidate::{Candidate, CandidatePair, CandidateType, TransportType};

use crate::agent::AgentError;
use crate::stream::Credentials;

use crate::clock::{get_clock, Clock, ClockType};
use crate::component::{Component, ComponentState, SelectedPair};
use crate::stun::agent::{StunAgent, StunError, StunRequest};
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
        f.pad(&format!("{:?}", self))
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
                if let Some(stun_request) = self.stun_request.take() {
                    stun_request.cancel();
                }
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
                stun_request: None,
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
        conncheck: Arc<ConnCheck>,
        username: String,
        controlling: bool,
        tie_breaker: u64,
    ) -> Result<StunRequest, StunError> {
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

        let to = conncheck.pair.remote.address;
        conncheck.agent.stun_request_transaction(&msg, to)?.build()
    }

    async fn do_stun_request(
        conncheck: Arc<ConnCheck>,
        stun_request: StunRequest,
    ) -> Result<ConnCheckResponse, AgentError> {
        // send binding request
        // wait for response
        // if timeout -> resend?
        // if longer timeout -> fail
        // TODO: optional: if icmp error -> fail
        let (response, from) = match stun_request.perform().await {
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
                    return Ok(ConnCheckResponse::RoleConflict(
                        conncheck,
                        stun_request.request().has_attribute(ICE_CONTROLLED),
                    ));
                }
            }
            // FIXME: some failures are recoverable
            return Ok(ConnCheckResponse::Failure(conncheck));
        }

        // if response success:
        // if mismatched address -> fail
        if from != stun_request.peer_address() {
            warn!(
                "response came from different ip {:?} than candidate {:?}",
                from,
                stun_request.peer_address()
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

#[derive(Debug)]
struct ConnCheckLocalCandidate {
    candidate: Candidate,
    stun_agent: StunAgent,
    #[allow(dead_code)]
    stun_recv_abort: AbortHandle,
    #[allow(dead_code)]
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
    nominated: Vec<CandidatePair>,
    controlling: bool,
    trickle_ice: bool,
    local_end_of_candidates: bool,
    remote_end_of_candidates: bool,
}

impl ConnCheckListInner {
    fn new(
        checklist_id: usize,
        set_inner: Weak<Mutex<CheckListSetInner>>,
        controlling: bool,
        trickle_ice: bool,
    ) -> Self {
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
            nominated: vec![],
            controlling,
            trickle_ice,
            local_end_of_candidates: false,
            remote_end_of_candidates: false,
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
            .position(|existing| candidate_pair_is_same_connection(&existing.pair, &check.pair))
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
        self.generate_checks();
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

                    if let Some(redundant_pair) = pair.redundant_with(pairs.iter()) {
                        if redundant_pair.remote.candidate_type == CandidateType::PeerReflexive {
                            redundant_pairs.push((
                                redundant_pair.clone(),
                                pair,
                                local.stun_agent.clone(),
                            ));
                        } else {
                            trace!("not adding redundant pair {:?}", pair);
                        }
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
        for (peer_reflexive_pair, pair, local_stun_agent) in redundant_pairs {
            if let Some(check) = self.take_matching_check(&peer_reflexive_pair) {
                check.cancel();
                checks.push(Arc::new(ConnCheck::new(pair, local_stun_agent, false)));
            }
        }

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

    fn take_matching_check(&mut self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        let pos = self
            .pairs
            .iter()
            .position(|check| Self::check_is_equal(check, pair, Nominate::DontCare));
        if let Some(position) = pos {
            self.pairs.remove(position)
        } else {
            None
        }
    }

    fn add_check(&mut self, check: Arc<ConnCheck>) {
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
    fn nominated_pair(&mut self, pair: &CandidatePair) -> Option<Arc<Component>> {
        if let Some(idx) = self
            .valid
            .iter()
            .position(|valid_pair| candidate_pair_is_same_connection(valid_pair, pair))
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
            if self.state != CheckListState::Running {
                warn!(
                    "cannot nominate a pair with checklist in state {:?}",
                    self.state
                );
                return None;
            }
            let component = self
                .components
                .iter()
                .filter_map(|component| component.upgrade())
                .find(|component| component.id == pair.local.component_id);
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
                    .any(|valid_pair| valid_pair.local.component_id == component_id)
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
                                    .find(|cand| {
                                        cand.candidate.base_address == pair.local.base_address
                                    })
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
                    from,
                )
                .priority(priority)
                .build();
                debug!("new reflexive remote {:?}", cand);
                self.add_remote_candidate(cand.clone());
                cand
            });
        // RFC 8445 Section 7.3.1.4. Triggered Checks
        let pair = CandidatePair::new(local.clone(), remote);
        if let Some(mut check) = self.take_matching_check(&pair) {
            // When the pair is already on the checklist:
            trace!("found existing {:?} check {:?}", check.state(), check);
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
                    check.cancel_retransmissions();
                    // TODO: ignore response timeouts

                    self.add_check(check.clone());
                    check = Arc::new(ConnCheck::new(
                        check.pair.clone(),
                        check.agent.clone(),
                        peer_nominating,
                    ));
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
                    if peer_nominating && !check.nominate() {
                        check.cancel();
                        self.add_check(check.clone());
                        check = Arc::new(ConnCheck::new(
                            check.pair.clone(),
                            check.agent.clone(),
                            peer_nominating,
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
            self.add_check(check.clone());
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
        matches!(self, Nominate::DontCare)
            || (*other && self.eq(&Nominate::True))
            || (!*other && self.eq(&Nominate::False))
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
                            checklist.controlling = false;
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
                            checklist.set_controlling(false);
                            for l in set.checklists.iter() {
                                if l.checklist_id == checklist.checklist_id {
                                    continue;
                                }
                                let mut l = l.inner.lock().unwrap();
                                l.set_controlling(false);
                            }
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
        {
            let inner = self.inner.lock().unwrap();
            if inner.local_end_of_candidates {
                panic!("Attempt made to add a local candidate after end-of-candidate received");
            }
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
                                _ => warn!("nothing to respond with"),
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

    #[tracing::instrument(
        level = "debug",
        skip(self, component),
        fields(
            checklist_id = self.checklist_id,
            component_id = component.id,
        )
    )]
    pub(crate) fn local_end_of_candidates(&self, component: &Arc<Component>) {
        let mut inner = self.inner.lock().unwrap();
        info!("end of local candidates");
        inner.local_end_of_candidates = true;
        inner.check_for_failure();
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, component),
        fields(
            checklist_id = self.checklist_id,
            component_id = component.id,
        )
    )]
    pub(crate) fn remote_end_of_candidates(&self, component: &Arc<Component>) {
        let mut inner = self.inner.lock().unwrap();
        info!("end of remote candidates");
        inner.remote_end_of_candidates = true;
        inner.check_for_failure();
    }

    pub(crate) fn add_remote_candidate(&self, remote: Candidate) {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.remote_end_of_candidates {
                error!(
                    "Attempt made to add a remote candidate after an end-of-candidates received"
                );
                return;
            }
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

    fn generate_checks(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.generate_checks();
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
        debug!("list state change from {:?} to Running", inner.state);
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
        trace!("adding {:?}", pair);
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
        inner.valid.retain(|valid_pair| {
            if !candidate_pair_is_same_connection(valid_pair, pair) {
                debug!("removing");
                false
            } else {
                true
            }
        });
    }

    async fn nominated_pair(&self, pair: &CandidatePair) {
        let component = self.inner.lock().unwrap().nominated_pair(pair);
        if let Some(component) = component {
            component.set_state(ComponentState::Connected).await;
        }
    }

    fn add_check(&self, check: Arc<ConnCheck>) {
        self.inner.lock().unwrap().add_check(check)
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

    #[tracing::instrument(
        name = "checklist_try_nominate"
        skip(self),
        fields(
            checklist_id = self.checklist_id,
        )
    )]
    fn try_nominate(&self) {
        let mut inner = self.inner.lock().unwrap();

        let retrigerred: Vec<_> = inner
            .component_ids
            .iter()
            .map(|&component_id| {
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
                    valid.get(0).cloned()
                } else {
                    None
                }
            })
            .collect();
        trace!("retriggered {:?}", retrigerred);
        // need to wait until all component have a valid pair before we send nominations
        if retrigerred.iter().all(|pair| pair.is_some()) {
            let _: Vec<_> = retrigerred
                .iter()
                .map(|pair| {
                    let pair = pair.as_ref().unwrap(); // checked earlier
                                                       // find the local stun agent for this pair
                    if let Some(agent) = inner
                        .local_candidates
                        .iter()
                        .find(|&local_cand| {
                            local_cand.candidate.base_address == pair.local.base_address
                        })
                        .map(|local| local.stun_agent.clone())
                    {
                        let check = Arc::new(ConnCheck::new(pair.clone(), agent, true));
                        check.set_state(CandidatePairState::Waiting);
                        debug!("attempting nomination with check {:?}", check);
                        inner.add_check(check.clone());
                        inner.add_triggered(check);
                    }
                })
                .collect();
        }
    }

    fn check_for_failure(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.check_for_failure();
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
    trickle_ice: bool,
}

impl ConnCheckListSetBuilder {
    fn new(tie_breaker: u64, controlling: bool) -> Self {
        Self {
            clock: None,
            tie_breaker,
            controlling,
            trickle_ice: false,
        }
    }

    pub(crate) fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
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
            trickle_ice: self.trickle_ice,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnCheckListSet {
    clock: Arc<dyn Clock>,
    inner: Arc<Mutex<CheckListSetInner>>,
    trickle_ice: bool,
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
                self.controlling(),
                self.trickle_ice,
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
        let stun_request = {
            let mut inner = conncheck.state.lock().unwrap();
            if inner.stun_request.is_some() {
                panic!("duplicate connection checks!");
                //            return Err(AgentError::AlreadyExists);
            }

            let stun_request = ConnCheck::generate_stun_request(
                conncheck.clone(),
                username,
                controlling,
                tie_breaker,
            )?;
            inner.stun_request = Some(stun_request.clone());
            stun_request
        };

        async_std::task::spawn(
            async move {
                match ConnCheck::do_stun_request(conncheck, stun_request).await {
                    Ok(v) => Ok(v),
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
                match e {
                    // ignore us calling conncheck.cancel()
                    AgentError::Aborted => trace!(error = ?e, "aborted"),
                    _ => {
                        warn!(error = ?e, "conncheck error: {:?}", conncheck);
                        conncheck.set_state(CandidatePairState::Failed);
                        checklist.remove_valid(&conncheck.pair);
                        checklist.set_state(CheckListState::Failed);
                    }
                }
            }
            Ok(ConnCheckResponse::Failure(conncheck)) => {
                warn!("conncheck failure: {:?}", conncheck);
                conncheck.set_state(CandidatePairState::Failed);
                checklist.remove_valid(&conncheck.pair);
                if conncheck.nominate() {
                    checklist.set_state(CheckListState::Failed);
                }
                checklist.check_for_failure();
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
                    xor_mapped_address = ?addr,
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
                    // TODO: need to construct correct pair priorities and foundations,
                    // just use whatever the conncheck produced for now
                    let ok_check = Arc::new(ConnCheck::new(
                        ok_pair.clone(),
                        conncheck.agent.clone(),
                        false,
                    ));
                    ok_check.set_state(CandidatePairState::Succeeded);
                    checklist.add_check(ok_check);
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
        if !self.trickle_ice {
            // perform initial set up for the non-trickle-ice case
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
        let mut all_failed = true;
        loop {
            let start_idx = self.checklist_i;
            let checklist = {
                let set_inner = self.set.inner.lock().unwrap();
                if set_inner.checklists.is_empty() {
                    // FIXME: will not be correct once we support adding streams at runtime
                    return CheckListSetProcess::Completed;
                }
                let checklist = &set_inner.checklists[self.checklist_i];
                self.checklist_i += 1;
                if self.checklist_i >= set_inner.checklists.len() {
                    self.checklist_i = 0;
                }
                let checklist_state = checklist.state();
                match checklist_state {
                    CheckListState::Running => {
                        any_running = true;
                        all_failed = false;
                    }
                    CheckListState::Completed => {
                        if all_failed {
                            all_failed = false;
                        }
                    }
                    CheckListState::Failed => (),
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
    use async_std::task::{self, JoinHandle};
    use std::sync::Arc;

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
        agent: StunAgent,
        local_credentials: Option<Credentials>,
    }

    impl Peer {
        async fn default() -> Self {
            Peer::builder().build().await
        }

        fn builder<'this>() -> PeerBuilder<'this> {
            PeerBuilder::default()
        }
    }

    #[derive(Debug, Default)]
    struct PeerBuilder<'this> {
        channel: Option<StunChannel>,
        foundation: Option<&'this str>,
        clock: Option<Arc<dyn Clock>>,
        local_credentials: Option<Credentials>,
        remote_credentials: Option<Credentials>,
        component_id: Option<usize>,
        priority: Option<u32>,
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
                let mut builder = Candidate::builder(
                    self.component_id.unwrap_or(1),
                    CandidateType::Host,
                    TransportType::Udp,
                    self.foundation.unwrap_or("0"),
                    addr,
                );
                if let Some(priority) = self.priority {
                    builder = builder.priority(priority);
                }
                builder.build()
            });
            let clock = self.clock.unwrap_or_else(|| get_clock(ClockType::System));
            let agent = StunAgent::builder(channel).clock(clock).build();
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

            Peer {
                candidate,
                agent,
                local_credentials: self.local_credentials,
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
        response_address: Option<SocketAddr>,
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
        response.add_message_integrity(&local_stun_credentials)?;
        response.add_fingerprint()?;
        Ok(response)
    }

    async fn reply_to_conncheck(
        agent: &StunAgent,
        credentials: &Credentials,
        stun_or_data: StunOrData,
        error_response: Option<u16>,
        response_address: Option<SocketAddr>,
    ) {
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
                                agent,
                                credentials,
                                &msg,
                                from,
                                error_response,
                                response_address,
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

    fn reply_to_conncheck_task(agent: StunAgent, credentials: Credentials) -> JoinHandle<()> {
        let mut remote_data_stream = agent.receive_stream();
        task::spawn({
            async move {
                while let Some(stun_or_data) = remote_data_stream.next().await {
                    reply_to_conncheck(&agent, &credentials, stun_or_data, None, None).await;
                }
            }
        })
    }

    #[test]
    fn conncheck_udp_host() {
        init();
        async_std::task::block_on(async move {
            let local_credentials = Credentials::new(String::from("luser"), String::from("lpass"));
            let remote_credentials = Credentials::new(String::from("ruser"), String::from("rpass"));
            // start the remote peer
            let remote = Peer::builder()
                .local_credentials(remote_credentials.clone())
                .remote_credentials(local_credentials.clone())
                .build()
                .await;
            // set up the local peer
            let local = Peer::builder()
                .local_credentials(local_credentials.clone())
                .remote_credentials(remote_credentials.clone())
                .build()
                .await;

            reply_to_conncheck_task(remote.agent.clone(), remote_credentials.clone());
            reply_to_conncheck_task(local.agent.clone(), local_credentials.clone());

            let pair = CandidatePair::new(local.candidate, remote.candidate);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent.clone(), false));

            // this is what we're testing.  All of the above is setup for performing this check
            let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;
            let res =
                ConnCheckListSet::connectivity_check_cancellable(conncheck, username, true, 0)
                    .await
                    .unwrap();
            match res {
                ConnCheckResponse::Success(_check, addr) => {
                    assert_eq!(addr, local.agent.channel().local_addr().unwrap());
                }
                _ => unreachable!(),
            }
        })
    }

    fn assert_list_contains_checks(list: &ConnCheckList, pairs: Vec<&CandidatePair>) {
        let inner = list.inner.lock().unwrap();

        trace!("checks {:?}", inner.pairs);
        trace!("pairs  {:?}", pairs);

        for (pair, check) in pairs.into_iter().zip(inner.pairs.iter()) {
            assert_eq!(&check.pair, pair);
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
            let local1 = Peer::builder().priority(1).build().await;
            let remote1 = Peer::builder().priority(2).build().await;
            let local2 = Peer::builder().component_id(2).priority(4).build().await;
            let remote2 = Peer::builder().component_id(2).priority(6).build().await;
            let local3 = Peer::builder().priority(10).build().await;
            let remote3 = Peer::builder().priority(15).build().await;

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
            let pair1 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
            let pair2 = CandidatePair::new(local2.candidate, remote2.candidate);
            let pair3 = CandidatePair::new(local3.candidate, remote1.candidate.clone());
            let pair4 = CandidatePair::new(local1.candidate.clone(), remote3.candidate);
            let pair5 = CandidatePair::new(local1.candidate, remote1.candidate);
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

            let local1 = Peer::builder().foundation("0").priority(1).build().await;
            let remote1 = Peer::builder().foundation("0").priority(2).build().await;
            let local2 = Peer::builder()
                .foundation("0")
                .component_id(2)
                .priority(3)
                .build()
                .await;
            let remote2 = Peer::builder()
                .foundation("0")
                .component_id(2)
                .priority(4)
                .build()
                .await;
            let local3 = Peer::builder()
                .foundation("1")
                .component_id(2)
                .priority(7)
                .build()
                .await;
            let remote3 = Peer::builder()
                .foundation("1")
                .component_id(2)
                .priority(10)
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
            let pair2 = CandidatePair::new(local3.candidate.clone(), remote3.candidate.clone());
            let pair3 = CandidatePair::new(local3.candidate, remote2.candidate.clone());
            let pair4 = CandidatePair::new(local2.candidate.clone(), remote3.candidate);
            let pair5 = CandidatePair::new(local2.candidate, remote2.candidate);
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
        });
    }

    struct FineControlPeer {
        component: Arc<Component>,
        peer: Peer,
        checklist_set: Arc<ConnCheckListSet>,
        checklist: Arc<ConnCheckList>,
    }

    struct FineControl {
        router: ChannelRouter,
        clock: Arc<dyn Clock>,
        local: FineControlPeer,
        remote: Peer,
    }

    struct FineControlBuilder {
        clock: Arc<dyn Clock>,
        trickle_ice: bool,
    }

    impl Default for FineControlBuilder {
        fn default() -> Self {
            Self {
                clock: Arc::new(crate::clock::tests::TestClock::default()),
                trickle_ice: false,
            }
        }
    }

    impl FineControlBuilder {
        fn trickle_ice(mut self, trickle_ice: bool) -> Self {
            self.trickle_ice = trickle_ice;
            self
        }

        async fn build(self) -> FineControl {
            let local_credentials = Credentials::new("luser".into(), "lpass".into());
            let remote_credentials = Credentials::new("ruser".into(), "rpass".into());
            let local_agent = Arc::new(
                Agent::builder()
                    .trickle_ice(self.trickle_ice)
                    .controlling(true)
                    .build(),
            );
            let local_stream = local_agent.add_stream();
            let local_component = local_stream.add_component().unwrap();
            let router = ChannelRouter::default();
            let local_host = router.add_host();

            let local_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(local_host.new_channel(None)))
                .foundation("0")
                .clock(self.clock.clone())
                .local_credentials(local_credentials.clone())
                .remote_credentials(remote_credentials.clone())
                .build()
                .await;

            let remote_host = router.add_host();
            let remote_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(remote_host.new_channel(None)))
                .foundation("0")
                .clock(self.clock.clone())
                .local_credentials(remote_credentials.clone())
                .remote_credentials(local_credentials.clone())
                .build()
                .await;

            let checklist_set = local_agent.check_list_set();
            let checklist = local_stream.checklist.clone();

            checklist.set_local_credentials(local_credentials.clone());
            checklist.set_remote_credentials(remote_credentials);
            if !self.trickle_ice {
                checklist
                    .add_local_candidate(
                        &local_component,
                        local_peer.candidate.clone(),
                        local_peer.agent.clone(),
                    )
                    .await;
                checklist.add_remote_candidate(remote_peer.candidate.clone());
            }

            FineControl {
                router: router.clone(),
                clock: self.clock,
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

    struct NextCheckAndResponse<'next> {
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

        #[tracing::instrument(
            name = "test_send_check_and_get_response",
            skip(self, set_run),
            fields(
                local_addr = %self.local_peer.agent.channel().local_addr().unwrap(),
                remote_addr = %self.remote_peer.agent.channel().local_addr().unwrap(),
            )
        )]
        async fn perform(self, set_run: &mut RunningCheckListSet<'_>) {
            let remote_s_recv = self.remote_peer.agent.receive_stream();
            futures::pin_mut!(remote_s_recv);
            let local_s_recv = self.local_peer.agent.receive_stream();
            futures::pin_mut!(local_s_recv);

            // perform one tick which will start a connectivity check with the peer
            let set_ret = set_run.process_next().await;
            let check = if let CheckListSetProcess::HaveCheck(check) = set_ret {
                check
            } else {
                unreachable!()
            };
            debug!("tick");
            let check_task = async_std::task::spawn(check.perform());

            let stun_or_data = remote_s_recv.next().await.unwrap();
            // send a response (success or some kind of error like role-conflict)
            reply_to_conncheck(
                &self.remote_peer.agent,
                &self.remote_peer.local_credentials.clone().unwrap(),
                stun_or_data,
                self.error_response,
                self.response_address,
            )
            .await;

            // wait for the response to reach the checklist and update the state
            check_task.await.unwrap();
            debug!("check done");
            let response = local_s_recv.next().await.unwrap();
            trace!("msg received {:?}", response);
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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;
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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;

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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .error_response(ErrorCode::ROLE_CONFLICT)
                .perform(&mut set_run)
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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;
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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;

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
            send_next_check_and_response(&state.local.peer, &state.remote)
                .error_response(ErrorCode::UNAUTHORIZED)
                .perform(&mut set_run)
                .await;
            assert_eq!(check.state(), CandidatePairState::Failed);

            // TODO: properly failing the checklist on all checks failing
            // check should be failed
            assert_eq!(state.local.checklist.state(), CheckListState::Failed);

            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed
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
                            remote_addr,
                        )
                        .tcp_type(TcpType::Active)
                        .build();
                        let channel = StunChannel::Tcp(TcpChannel::new(stream));
                        let remote_peer = Peer::builder()
                            .channel(channel)
                            .candidate(remote_cand)
                            .local_credentials(remote_credentials.clone())
                            .remote_credentials(local_credentials.clone())
                            .build()
                            .await;
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
            let local_cand =
                Candidate::builder(0, CandidateType::Host, TransportType::Tcp, "0", local_addr)
                    .tcp_type(TcpType::Active)
                    .build();
            let local = Peer::builder()
                .channel(local_channel)
                .candidate(local_cand)
                .local_credentials(local_credentials.clone())
                .remote_credentials(remote_credentials.clone())
                .build()
                .await;
            let remote_cand =
                Candidate::builder(0, CandidateType::Host, TransportType::Tcp, "0", remote_addr)
                    .tcp_type(TcpType::Passive)
                    .build();
            let pair = CandidatePair::new(local.candidate, remote_cand);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent.clone(), false));

            // this is what we're testing.  All of the above is setup for performing this check
            let username = remote_credentials.ufrag.clone() + ":" + &local_credentials.ufrag;
            let res =
                ConnCheckListSet::connectivity_check_cancellable(conncheck, username, true, 0)
                    .await
                    .unwrap();
            match res {
                ConnCheckResponse::Success(_check, addr) => {
                    assert_eq!(addr, local.agent.channel().local_addr().unwrap());
                }
                _ => unreachable!(),
            }

            listen_task.cancel().await;
        });
    }

    #[test]
    fn conncheck_incoming_prflx() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().build().await;

            // generate existing checks
            state.local.checklist.generate_checks();

            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let initial_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(initial_check.state(), CandidatePairState::Frozen);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            state.local.checklist.initial_thaw(&mut thawn);
            assert_eq!(initial_check.state(), CandidatePairState::Waiting);

            let unknown_remote_host = state.router.add_host();
            let unknown_remote_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(
                    unknown_remote_host.new_channel(None),
                ))
                .foundation("1")
                .clock(state.clock.clone())
                .local_credentials(state.remote.local_credentials.clone().unwrap())
                .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
                .build()
                .await;

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
                .add_message_integrity(&state.remote.agent.local_credentials().unwrap())
                .unwrap();
            request.add_fingerprint().unwrap();

            let local_addr = state.local.peer.agent.channel().local_addr().unwrap();
            let stun_request = unknown_remote_peer
                .agent
                .stun_request_transaction(&request, local_addr)
                .unwrap()
                .build()
                .unwrap();

            let (response, from) = stun_request.perform().await.unwrap();
            assert_eq!(from, local_addr);
            assert!(response.has_class(MessageClass::Success));

            // The stun request has created a new peer reflexive triggered check
            let mut prflx_remote_candidate = unknown_remote_peer.candidate.clone();
            prflx_remote_candidate.candidate_type = CandidateType::PeerReflexive;
            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                unknown_remote_peer.candidate.clone(),
            );
            {
                let checklist_inner = state.local.checklist.inner.lock().unwrap();
                checklist_inner.dump_check_state();
            }
            let triggered_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(triggered_check.state(), CandidatePairState::Waiting);

            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);

            // perform one tick which will start a connectivity check with the peer
            send_next_check_and_response(&state.local.peer, &unknown_remote_peer)
                .perform(&mut set_run)
                .await;
            assert_eq!(triggered_check.state(), CandidatePairState::Succeeded);
            let nominated_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::True)
                .unwrap();
            assert_eq!(nominated_check.state(), CandidatePairState::Waiting);
            send_next_check_and_response(&state.local.peer, &unknown_remote_peer)
                .perform(&mut set_run)
                .await;
            assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed,
            ));
        });
    }

    #[test]
    fn conncheck_response_prflx() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().build().await;

            // generate existing checks
            state.local.checklist.generate_checks();

            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let initial_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(initial_check.state(), CandidatePairState::Frozen);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            state.local.checklist.initial_thaw(&mut thawn);
            assert_eq!(initial_check.state(), CandidatePairState::Waiting);

            let unknown_remote_host = state.router.add_host();
            let unknown_remote_peer = Peer::builder()
                .channel(StunChannel::AsyncChannel(
                    unknown_remote_host.new_channel(None),
                ))
                .foundation("1")
                .clock(state.clock.clone())
                .local_credentials(state.remote.local_credentials.clone().unwrap())
                .remote_credentials(state.local.peer.local_credentials.clone().unwrap())
                .build()
                .await;

            // send the next connectivity check but response with a different xor-mapped-address
            // which should result in a PeerReflexive address being produced in the check list
            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);
            send_next_check_and_response(&state.local.peer, &state.remote)
                .response_address(unknown_remote_peer.agent.channel().local_addr().unwrap())
                .perform(&mut set_run)
                .await;
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
            let prflx_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(prflx_check.state(), CandidatePairState::Succeeded);
            let nominated_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::True)
                .unwrap();
            {
                let inner = state.local.checklist.inner.lock().unwrap();
                inner.dump_check_state();
            }
            assert_eq!(nominated_check.state(), CandidatePairState::Waiting);

            send_next_check_and_response(&state.local.peer, &state.remote)
                .response_address(unknown_remote_peer.agent.channel().local_addr().unwrap())
                .perform(&mut set_run)
                .await;
            assert_eq!(nominated_check.state(), CandidatePairState::Succeeded);

            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed,
            ));
        });
    }

    #[test]
    fn conncheck_trickle_ice() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().trickle_ice(true).build().await;
            assert_eq!(state.local.component.id, 1);

            // Don't generate any initial checks as they should be done as candidates are added to
            // the checklist
            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);
            let set_ret = set_run.process_next().await;
            // a checklist with no candidates has nothing to do
            assert!(matches!(set_ret, CheckListSetProcess::NothingToDo));

            state
                .local
                .checklist
                .add_local_candidate(
                    &state.local.component,
                    state.local.peer.candidate.clone(),
                    state.local.peer.agent.clone(),
                )
                .await;

            let set_ret = set_run.process_next().await;
            // a checklist with only a local candidates has nothing to do
            assert!(matches!(set_ret, CheckListSetProcess::NothingToDo));

            state
                .local
                .checklist
                .add_remote_candidate(state.remote.candidate.clone());

            // adding one local and one remote candidate that can be paired should have generated
            // the relevant waiting check. Not frozen because there is not other check with the
            // same foundation that already exists
            let pair = CandidatePair::new(
                state.local.peer.candidate.clone(),
                state.remote.candidate.clone(),
            );
            let check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::False)
                .unwrap();
            assert_eq!(check.state(), CandidatePairState::Waiting);

            // perform one tick which will start a connectivity check with the peer
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;
            assert_eq!(check.state(), CandidatePairState::Succeeded);

            {
                let checklist_inner = state.local.checklist.inner.lock().unwrap();
                checklist_inner.dump_check_state();
                error!("pair: {pair:?}");
            }

            // should have resulted in a nomination and therefore a triggered check (always a new
            // check in our implementation)
            let nominate_check = state
                .local
                .checklist
                .matching_check(&pair, Nominate::True)
                .unwrap();
            assert!(state.local.checklist.is_triggered(&nominate_check));

            // perform one tick which will perform the nomination check
            send_next_check_and_response(&state.local.peer, &state.remote)
                .perform(&mut set_run)
                .await;

            assert_eq!(nominate_check.state(), CandidatePairState::Succeeded);

            // check list is done
            // TODO: provide end-of-candidate notification and delay completed until we receive
            // end-of-candidate
            assert_eq!(state.local.checklist.state(), CheckListState::Completed);

            // perform one final tick attempt which should end the processing
            assert!(matches!(
                set_run.process_next().await,
                CheckListSetProcess::Completed
            ));
        });
    }

    #[test]
    fn conncheck_trickle_ice_no_remote_candidates_fail() {
        init();
        async_std::task::block_on(async move {
            let state = FineControl::builder().trickle_ice(true).build().await;
            assert_eq!(state.local.component.id, 1);

            // Don't generate any initial checks as they should be done as candidates are added to
            // the checklist
            let mut set_run = RunningCheckListSet::from_set(&state.local.checklist_set);
            let set_ret = set_run.process_next().await;
            // a checklist with no candidates has nothing to do
            assert!(matches!(set_ret, CheckListSetProcess::NothingToDo));

            state
                .local
                .checklist
                .add_local_candidate(
                    &state.local.component,
                    state.local.peer.candidate.clone(),
                    state.local.peer.agent.clone(),
                )
                .await;
            state
                .local
                .checklist
                .local_end_of_candidates(&state.local.component);

            let set_ret = set_run.process_next().await;
            // a checklist with only a local candidates has nothing to do
            assert!(matches!(set_ret, CheckListSetProcess::NothingToDo));

            state
                .local
                .checklist
                .remote_end_of_candidates(&state.local.component);

            let set_ret = set_run.process_next().await;
            // a checklist with only a local candidates but no more possible candidates will error
            assert_eq!(state.local.checklist.state(), CheckListState::Failed);
            assert!(matches!(set_ret, CheckListSetProcess::Completed));
        });
    }
}
