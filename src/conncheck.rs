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

use futures::future::{AbortHandle, Abortable};
use futures::prelude::*;
use futures_timer::Delay;

use crate::candidate::{Candidate, CandidatePair, CandidateType, TransportType};

use crate::agent::{AgentError, AgentMessage};

use crate::component::{Component, ComponentState};
use crate::stun::agent::StunAgent;
use crate::stun::attribute::*;
use crate::stun::message::*;
use crate::tasks::TaskList;
use crate::utils::{ChannelBroadcast, DropLogger};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

static CONN_CHECK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct ConnCheck {
    conncheck_id: usize,
    pub pair: CandidatePair,
    state: Mutex<ConnCheckState>,
    pub agent: StunAgent,
    nominate: bool,
}

#[derive(Debug)]
struct ConnCheckState {
    state: CandidatePairState,
    abort_handle: Option<AbortHandle>,
}

impl ConnCheck {
    fn new(pair: CandidatePair, agent: StunAgent, nominate: bool) -> Self {
        Self {
            conncheck_id: CONN_CHECK_COUNT.fetch_add(1, Ordering::SeqCst),
            pair,
            state: Mutex::new(ConnCheckState {
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
        trace!(
            "conncheck {} state change from '{:?}' to '{:?}' for {:?}",
            self.conncheck_id,
            inner.state,
            state,
            self.pair
        );
        if state == CandidatePairState::Succeeded || state == CandidatePairState::Failed {
            let _ = inner.abort_handle.take();
        }
        inner.state = state;
    }

    fn nominate(&self) -> bool {
        self.nominate
    }

    fn cancel(&self) {
        let mut inner = self.state.lock().unwrap();
        let abort_handle = inner.abort_handle.take();
        if let Some(handle) = abort_handle {
            debug!(
                "conncheck {} cancelling for {:?}",
                self.conncheck_id, self.pair
            );
            handle.abort();
            inner.state = CandidatePairState::Failed;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CheckListState {
    Running,
    Completed,
    Failed,
}

#[derive(Debug)]
pub struct ConnCheckList {
    inner: Arc<Mutex<ConnCheckListInner>>,
}

#[derive(Debug)]
struct ConnCheckLocalCandidate {
    component_id: usize,
    candidate: Candidate,
    stun_agent: StunAgent,
    stun_recv_abort: AbortHandle,
    data_recv_abort: AbortHandle,
}

#[derive(Debug)]
struct ConnCheckListInner {
    // TODO: move to BinaryHeap or similar
    state: CheckListState,
    component_ids: Vec<usize>,
    components: Vec<Weak<Component>>,
    local_candidates: Vec<ConnCheckLocalCandidate>,
    remote_candidates: Vec<(usize, Candidate)>,
    triggered: VecDeque<Arc<ConnCheck>>,
    pairs: VecDeque<Arc<ConnCheck>>,
    valid: Vec<CandidatePair>,
    controlling: bool,
}

impl ConnCheckListInner {
    fn new() -> Self {
        Self {
            state: CheckListState::Running,
            component_ids: vec![],
            components: vec![],
            local_candidates: vec![],
            remote_candidates: vec![],
            triggered: VecDeque::new(),
            pairs: VecDeque::new(),
            valid: vec![],
            controlling: false,
        }
    }

    fn controlling(&self) -> bool {
        self.controlling
    }

    fn set_controlling(&mut self, controlling: bool) {
        self.controlling = controlling
    }

    fn find_remote_candidate(
        &self,
        component_id: usize,
        ttype: TransportType,
        addr: SocketAddr,
    ) -> Option<Candidate> {
        trace!(
            "looking for comp {}, {:?} {:?} in {:?}",
            component_id,
            ttype,
            addr,
            self.remote_candidates
        );
        self.remote_candidates
            .iter()
            .find(|&remote| {
                remote.0 == component_id
                    && remote.1.transport_type == ttype
                    && remote.1.address == addr
            })
            .map(|(_, cand)| cand.clone())
    }

    fn add_triggered(&mut self, check: Arc<ConnCheck>) {
        if let Some(idx) = self
            .triggered
            .iter()
            .position(|existing| existing.pair == check.pair)
        {
            if check.nominate() != self.triggered[idx].nominate() {
                let existing = self.triggered.remove(idx).unwrap();
                debug!(
                    "removing existing triggered conncheck {} for {:?} nominate {}",
                    existing.conncheck_id, existing.pair, existing.nominate
                );
            } else {
                debug!(
                    "not adding duplicate triggered conncheck {} for {:?} nominate {}",
                    self.triggered[idx].conncheck_id,
                    self.triggered[idx].pair,
                    self.triggered[idx].nominate
                );
                return;
            }
        }
        debug!(
            "adding triggered conncheck {} for {:?} nominate {}",
            check.conncheck_id, check.pair, check.nominate
        );
        self.triggered.push_front(check)
    }

    fn add_remote_candidate(&mut self, component_id: usize, remote: Candidate) {
        debug!("adding remote component {} {:?}", component_id, remote);
        self.remote_candidates.push((component_id, remote));
    }

    fn get_matching_check(&self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        self.pairs
            .iter()
            .find(|&check| {
                check.pair.component_id == pair.component_id
                    && check.pair.local == pair.local
                    && check.pair.remote == pair.remote
            })
            .cloned()
    }

    fn take_matching_check(&mut self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        let pos = self.pairs.iter().position(|check| {
            check.pair.component_id == pair.component_id
                && check.pair.local == pair.local
                && check.pair.remote == pair.remote
        });
        if let Some(position) = pos {
            self.pairs.remove(position)
        } else {
            None
        }
    }

    fn add_check(&mut self, check: Arc<ConnCheck>) {
        self.pairs.push_front(check)
    }

    fn nominated_pair(
        &mut self,
        component_id: usize,
        pair: &CandidatePair,
    ) -> Option<Arc<Component>> {
        if let Some(idx) = self.valid.iter().position(|valid_pair| valid_pair == pair) {
            info!("nominated component {} pair {:?}", component_id, pair);
            self.valid[idx].nominate();
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
                self.triggered.retain(|check| {
                    if check.pair.component_id == component_id {
                        check.cancel();
                        false
                    } else {
                        true
                    }
                });
                self.pairs.retain(|check| {
                    if check.pair.component_id == component_id {
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
                        valid_pair.component_id == component_id && valid_pair.nominated()
                    })
                });
                if all_nominated {
                    info!("checklist state change from {:?} to Completed", self.state);
                    self.state = CheckListState::Completed;
                }
            }
            let ret = self
                .components
                .iter()
                .filter_map(|component| component.upgrade())
                .find(|component| component.id == component_id);
            debug!("trying to signal component {:?} {:?}", ret, self.components);
            return ret;
        } else {
            warn!(
                "unknown nominated component {} pair {:?}",
                component_id, pair
            );
        }
        None
    }
}

impl ConnCheckList {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ConnCheckListInner::new())),
        }
    }

    fn state(&self) -> CheckListState {
        self.inner.lock().unwrap().state
    }

    fn set_state(&self, state: CheckListState) {
        let mut inner = self.inner.lock().unwrap();
        info!(
            "checklist state change from {:?} to {:?}",
            inner.state, state
        );
        inner.state = state;
    }

    fn controlling(&self) -> bool {
        self.inner.lock().unwrap().controlling()
    }

    fn set_controlling(&self, controlling: bool) {
        self.inner.lock().unwrap().set_controlling(controlling)
    }

    async fn handle_binding_request(
        weak_inner: Weak<Mutex<ConnCheckListInner>>,
        component_id: usize,
        local: &Candidate,
        agent: StunAgent,
        msg: &Message,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Option<Message>, AgentError> {
        trace!("have request {}", msg);

        let local_credentials = agent
            .local_credentials()
            .ok_or(AgentError::ResourceNotFound)?;
        let remote_credentials = agent
            .remote_credentials()
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
            // TODO Validate USERNAME
            &[/*USERNAME, */ FINGERPRINT, MESSAGE_INTEGRITY, PRIORITY],
        ) {
            // failure -> send error response
            return Ok(Some(error_msg));
        }
        let priority = match msg.get_attribute::<Priority>(PRIORITY) {
            Some(p) => p.priority(),
            None => {
                return Ok(Some(Message::bad_request(msg)?));
            }
        };

        let peer_nominating = if let Some(use_candidate_raw) = msg.get_attribute::<RawAttribute>(USE_CANDIDATE) {
            if UseCandidate::from_raw(&use_candidate_raw).is_ok() {
                debug!("have valid use-candidate attr");
                true
            } else {
                return Ok(Some(Message::bad_request(msg)?));
            }
        } else {
            false
        };
        let mut component = None;
        {
            let checklist = weak_inner.upgrade().ok_or(AgentError::ConnectionClosed)?;
            let mut checklist = checklist.lock().unwrap();

            debug!(
                "have request peer nominating {} list state {:?}",
                peer_nominating, checklist.state
            );
            if checklist.state == CheckListState::Completed && !peer_nominating {
                // ignore binding requests if we are completed
                return Ok(None);
            }

            let remote = checklist
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
                    let cand = Candidate::new(
                        CandidateType::PeerReflexive,
                        local.transport_type,
                        /* FIXME */ "rflx",
                        priority,
                        from,
                        from,
                        None,
                    );
                    debug!("new reflexive remote {:?}", cand);
                    checklist.add_remote_candidate(component_id, cand.clone());
                    cand
                });
            // RFC 8445 Section 7.3.1.4. Triggered Checks
            let pair = CandidatePair::new(component_id, local.clone(), remote);
            if let Some(mut check) = checklist.take_matching_check(&pair) {
                // When the pair is already on the checklist:
                trace!(
                    "found existing check {} for pair {:?}",
                    check.conncheck_id, pair
                );
                match check.state() {
                    // If the state of that pair is Succeeded, nothing further is
                    // done.
                    CandidatePairState::Succeeded => {
                        if peer_nominating {
                            info!("existing pair succeeded -> nominate");
                            check = Arc::new(ConnCheck::new(
                                check.pair.clone(),
                                check.agent.clone(),
                                true,
                            ));
                            check.set_state(CandidatePairState::Succeeded);
                            checklist.add_check(check);
                            component = checklist.nominated_pair(pair.component_id, &pair);
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
                        if peer_nominating {
                            check = Arc::new(ConnCheck::new(
                                check.pair.clone(),
                                check.agent.clone(),
                                true,
                            ));
                        }
                        check.set_state(CandidatePairState::Waiting);
                        // FIXME: add iff not already triggered
                        checklist.add_triggered(check);
                    }
                }
            } else {
                debug!("creating new check for pair {:?}", pair);
                let check = Arc::new(ConnCheck::new(pair, agent.clone(), peer_nominating));
                check.set_state(CandidatePairState::Waiting);
                checklist.pairs.push_back(check.clone());
                checklist.add_triggered(check);
            }
        }

        msg.validate_integrity(data, &remote_credentials)?;

        let mut response = Message::new_success(msg);
        response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()).to_raw())?;
        response.add_message_integrity(&local_credentials)?;
        response.add_fingerprint()?;

        if let Some(component) = component {
            component.set_state(ComponentState::Connected).await;
        }

        Ok(Some(response))
    }

    pub(crate) async fn add_local_candidate(
        &self,
        component: &Arc<Component>,
        local: Candidate,
        agent: StunAgent,
    ) {
        let component_id = component.id;
        debug!("adding local component {} {:?}", component_id, local);
        let weak_inner = Arc::downgrade(&self.inner);
        let (stun_send, stun_recv) = async_channel::bounded(1);

        // We need to listen for and respond to stun binding requests for the local candidate
        let (abortable, stun_abort_handle) = futures::future::abortable({
            let agent = agent.clone();
            let local = local.clone();
            async move {
                let drop_log = DropLogger::new("dropping stun receive stream");
                let mut recv_stun = agent.stun_receive_stream();
                if stun_send.send(0u32).await.is_err() {
                    return;
                }
                while let Some((msg, data, from)) = recv_stun.next().await {
                    // RFC8445 Section 7.3. STUN Server Procedures
                    trace!("got from {} msg {}", from, msg);
                    if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                        match ConnCheckList::handle_binding_request(
                            weak_inner.clone(),
                            component_id,
                            &local,
                            agent.clone(),
                            &msg,
                            &data,
                            from,
                        )
                        .await
                        {
                            Ok(Some(response)) => {
                                info!("sending response {}", response);
                                if let Err(e) = agent.send(response, from).await {
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
                drop(drop_log);
            }
        });

        async_std::task::spawn(abortable);
        if stun_recv.recv().await.is_err() {
            warn!("Failed to start listening task");
            return;
        }
        let data_abort_handle = component.add_recv_agent(agent.clone()).await;
        trace!("added recv task for candidate {:?}", local);

        {
            let mut inner = self.inner.lock().unwrap();
            inner.local_candidates.push(ConnCheckLocalCandidate {
                component_id,
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
                trace!("not adding component {} twice", component_id);
            }
        }
    }

    pub(crate) fn add_remote_candidate(&self, component_id: usize, remote: Candidate) {
        debug!("adding remote component {} {:?}", component_id, remote);
        {
            let mut inner = self.inner.lock().unwrap();
            inner.add_remote_candidate(component_id, remote);
            if inner
                .component_ids
                .iter()
                .find(|&v| v == &component_id)
                .is_none()
            {
                inner.component_ids.push(component_id);
            }
        }
    }

    fn generate_checks(&self) {
        let mut inner = self.inner.lock().unwrap();
        let mut checks = vec![];
        for local in inner.local_candidates.iter() {
            for (remote_comp_id, remote) in inner.remote_candidates.iter() {
                if local.candidate.transport_type == remote.transport_type
                    && local.component_id == *remote_comp_id
                {
                    let pair = CandidatePair::new(
                        local.component_id,
                        local.candidate.clone(),
                        remote.clone(),
                    );
                    checks.push(Arc::new(ConnCheck::new(
                        pair,
                        local.stun_agent.clone(),
                        false,
                    )));
                }
            }
        }
        let pairs = checks.iter().map(|c| &c.pair).collect::<Vec<_>>();
        debug!("generated checks for pairs {:?}", pairs);
        inner.pairs.extend(checks);
    }

    fn initial_thaw(&self, thawn_foundations: &mut Vec<String>) {
        let mut inner = self.inner.lock().unwrap();
        info!("checklist state change from {:?} to Running", inner.state);
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
                thawn_foundations
                    .iter()
                    .find(|&foundation| &check.pair.get_foundation() == foundation)
                    .is_none()
            })
            .collect();
        let dbg_maybe: Vec<_> = maybe_thaw
            .iter()
            .map(|conncheck| (conncheck.pair.component_id, conncheck.pair.get_foundation()))
            .collect();
        debug!("maybe thaw {:?}", dbg_maybe);
        // sort by component_id
        maybe_thaw.sort_unstable_by(|a, b| {
            a.pair
                .component_id
                .partial_cmp(&b.pair.component_id)
                .unwrap()
        });

        // only keep the first candidate for a given foundation which should correspond to the
        // lowest component_id
        let mut seen_foundations = vec![];
        maybe_thaw.retain(|check| {
            if seen_foundations
                .iter()
                .any(|foundation| &check.pair.get_foundation() == foundation)
            {
                false
            } else {
                seen_foundations.push(check.pair.get_foundation());
                true
            }
        });

        debug!("thawing foundations {:?}", seen_foundations);
        debug!("thawing connchecks {:?}", maybe_thaw);

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

    // note this will change the state of the returned check to InProgress to avoid a race
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
                        .find(|&f| f == &check.pair.get_foundation())
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
                foundations.insert(check.pair.get_foundation());
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
                if accum && elem.pair.get_foundation() == foundation {
                    let state = elem.state();
                    accum
                        && state != CandidatePairState::InProgress
                        && state != CandidatePairState::Waiting
                } else {
                    accum
                }
            })
    }

    fn add_valid(&self, pair: CandidatePair) {
        debug!("adding valid {:?}", pair);
        self.inner.lock().unwrap().valid.push(pair);
    }

    fn remove_valid(&self, pair: &CandidatePair) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(idx) = inner.valid.iter().position(|valid_pair| valid_pair == pair) {
            inner.valid.remove(idx);
        }
    }

    async fn nominated_pair(&self, component_id: usize, pair: &CandidatePair) {
        let component = self
            .inner
            .lock()
            .unwrap()
            .nominated_pair(component_id, pair);
        if let Some(component) = component {
            component.set_state(ComponentState::Connected).await;
        }
    }

    fn get_matching_check(&self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        self.inner.lock().unwrap().get_matching_check(pair)
    }

    pub(crate) fn get_local_candidates(&self) -> Vec<Candidate> {
        self.inner
            .lock()
            .unwrap()
            .local_candidates
            .iter()
            .map(|local| local.candidate.clone())
            .collect()
    }

    pub(crate) fn get_remote_candidates(&self) -> Vec<Candidate> {
        self.inner
            .lock()
            .unwrap()
            .remote_candidates
            .iter()
            .map(|(_, cand)| cand.clone())
            .collect()
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
                    .filter(|pair| pair.component_id == component_id)
                    .collect();
                valid.sort_by(|pair1, pair2| {
                    pair1
                        .priority(true /* if we are nominating, we are controlling */)
                        .cmp(&pair2.priority(true))
                });
                // FIXME: Nominate when there are two valid candidates
                // what if there is only ever one valid?
                if valid.iter().count() >= 1 {
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
                        .find(|&local_cand| {
                            local_cand.component_id == pair.component_id
                                && local_cand.candidate == pair.local
                        })
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
    RoleConflict(Arc<ConnCheck>),
    Failure(Arc<ConnCheck>),
}

async fn connectivity_check(
    conncheck: Arc<ConnCheck>,
    controlling: bool,
    tie_breaker: u64,
    nominate: bool,
) -> Result<ConnCheckResponse, AgentError> {
    // generate binding request
    let msg = {
        let mut msg = Message::new_request(BINDING);

        // XXX: this needs to be the priority as if the candidate was peer-reflexive
        msg.add_attribute(Priority::new(conncheck.pair.local.priority).into())?;
        if controlling {
            msg.add_attribute(IceControlling::new(tie_breaker).into())?;
        } else {
            msg.add_attribute(IceControlled::new(tie_breaker).into())?;
        }
        if nominate {
            msg.add_attribute(UseCandidate::new().into())?;
        }
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
    let (response, orig_data, from) = match conncheck.agent.stun_request_transaction(&msg, to).await
    {
        Err(e) => {
            warn!("connectivity check produced error: {:?}", e);
            return Ok(ConnCheckResponse::Failure(conncheck));
        }
        Ok(v) => v,
    };
    debug!("have response: {}", response);
    response.validate_integrity(&orig_data, &conncheck.agent.remote_credentials().unwrap())?;

    if !response.is_response() {
        // response is not a response!
        return Ok(ConnCheckResponse::Failure(conncheck));
    }

    // if response error -> fail TODO: might be a recoverable error!
    if response.has_class(MessageClass::Error) {
        warn!("error response {}", response);
        if let Some(err) = response.get_attribute::<ErrorCode>(ERROR_CODE) {
            if err.code() == ROLE_CONFLICT {
                info!("Role conflict received {}", response);
                return Ok(ConnCheckResponse::RoleConflict(conncheck));
            }
        }
        // FIXME: some failures are recoverable
        return Ok(ConnCheckResponse::Failure(conncheck));
    }

    // if response success:
    // if mismatched address -> fail
    if from != to {
        info!(
            "response came from different ip {:?} than candidate {:?}",
            from, to
        );
        return Ok(ConnCheckResponse::Failure(conncheck));
    }

    if let Some(xor) = response.get_attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS) {
        let xor_addr = xor.addr(response.transaction_id());
        // TODO: if response mapped address not in remote candidate list -> new peer-reflexive candidate
        // TODO glare
        return Ok(ConnCheckResponse::Success(conncheck, xor_addr));
    }

    Ok(ConnCheckResponse::Failure(conncheck))
}

// XXX: maybe put inside ConnCheckList ?
async fn connectivity_check_cancellable(
    conncheck: Arc<ConnCheck>,
    controlling: bool,
    tie_breaker: u64,
    nominate: bool,
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
        connectivity_check(conncheck, controlling, tie_breaker, nominate),
        abort_registration,
    );
    async_std::task::spawn(async move {
        match abortable.await {
            Ok(v) => v,
            Err(_) => Err(AgentError::Aborted),
        }
    })
    .await
}

#[derive(Debug)]
pub(crate) struct ConnCheckListSet {
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    checklists: Vec<Arc<ConnCheckList>>,
    tasks: Arc<TaskList>,
}

impl ConnCheckListSet {
    // TODO: add/remove a stream after start
    // TODO: cancel when agent is stopped
    pub(crate) fn from_streams(
        streams: Vec<Arc<crate::stream::Stream>>,
        broadcast: Arc<ChannelBroadcast<AgentMessage>>,
        tasks: Arc<TaskList>,
        controlling: bool,
    ) -> Self {
        Self {
            broadcast,
            checklists: streams
                .iter()
                .map(|s| s.checklist.clone())
                .inspect(|checklist| checklist.set_controlling(controlling))
                .collect(),
            tasks,
        }
    }

    async fn perform_conncheck(
        conncheck: Arc<ConnCheck>,
        checklist: Arc<ConnCheckList>,
        checklists: Vec<Arc<ConnCheckList>>,
        controlling: bool,
        tie_breaker: u64,
    ) -> Result<(), AgentError> {
        debug!(
            "performing connectivity check {} {:?} nominate {}",
            conncheck.conncheck_id, conncheck.pair, conncheck.nominate
        );
        match connectivity_check_cancellable(
            conncheck.clone(),
            controlling,
            tie_breaker,
            conncheck.nominate(),
        )
        .await
        {
            Err(e) => {
                warn!("conncheck {} error: {:?}", conncheck.conncheck_id, e);
                conncheck.set_state(CandidatePairState::Failed);
                checklist.remove_valid(&conncheck.pair);
                match e {
                    AgentError::Aborted => (),
                    _ => checklist.set_state(CheckListState::Failed),
                }
            }
            Ok(ConnCheckResponse::Failure(conncheck)) => {
                warn!("conncheck {} failre", conncheck.conncheck_id);
                conncheck.set_state(CandidatePairState::Failed);
                checklist.remove_valid(&conncheck.pair);
                if conncheck.nominate() {
                    checklist.set_state(CheckListState::Failed);
                }
            }
            Ok(ConnCheckResponse::RoleConflict(_conncheck)) => error!("Unhandled Role Conflict"),
            Ok(ConnCheckResponse::Success(conncheck, addr)) => {
                debug!(
                    "conncheck {} succeeded in finding {:?}",
                    conncheck.conncheck_id, addr
                );
                conncheck.set_state(CandidatePairState::Succeeded);

                let mut pair_dealt_with = false;
                let ok_pair = conncheck.pair.construct_valid(addr);
                // 1.
                // If the valid pair equals the pair that generated the check, the
                // pair is added to the valid list associated with the checklist to
                // which the pair belongs; or
                if let Some(_check) = checklist.get_matching_check(&ok_pair) {
                    checklist.add_valid(ok_pair.clone());
                    if conncheck.nominate() {
                        info!("ConnCheck {} Succeeded -> nominate", conncheck.conncheck_id);
                        checklist
                            .nominated_pair(conncheck.pair.component_id, &conncheck.pair)
                            .await;
                        return Ok(());
                    }
                    pair_dealt_with = true;
                } else {
                    // 2.
                    // If the valid pair equals another pair in a checklist, that pair
                    // is added to the valid list associated with the checklist of that
                    // pair.  The pair that generated the check is not added to a vali
                    // list; or
                    for checklist in checklists.iter() {
                        if let Some(check) = checklist.get_matching_check(&ok_pair) {
                            checklist.add_valid(check.pair.clone());
                            if conncheck.nominate() {
                                info!(
                                    "ConnCheck {} Succeeded -> nominate",
                                    conncheck.conncheck_id
                                );
                                checklist
                                    .nominated_pair(conncheck.pair.component_id, &conncheck.pair)
                                    .await;
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
                        info!("ConnCheck {} Succeeded -> nominate", conncheck.conncheck_id);
                        checklist
                            .nominated_pair(conncheck.pair.component_id, &conncheck.pair)
                            .await;
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
    fn get_next_check(&self, checklist: Arc<ConnCheckList>) -> Option<Arc<ConnCheck>> {
        // 1.  If the triggered-check queue associated with the checklist
        //     contains one or more candidate pairs, the agent removes the top
        //     pair from the queue, performs a connectivity check on that pair,
        //     puts the candidate pair state to In-Progress, and aborts the
        //     subsequent steps.
        if let Some(check) = checklist.next_triggered() {
            trace!(
                "found trigerred check {} for {:?} nominate {}",
                check.conncheck_id,
                check.pair,
                check.nominate
            );
            Some(check)
        // 3.  If there are one or more candidate pairs in the Waiting state,
        //     the agent picks the highest-priority candidate pair (if there are
        //     multiple pairs with the same priority, the pair with the lowest
        //     component ID is picked) in the Waiting state, performs a
        //     connectivity check on that pair, puts the candidate pair state to
        //     In-Progress, and aborts the subsequent steps.
        } else if let Some(check) = checklist.next_waiting() {
            trace!(
                "found waiting check {} for {:?} nominate {}",
                check.conncheck_id,
                check.pair,
                check.nominate
            );
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
                trace!(
                    "found frozen check {} for {:?} nominate {}",
                    check.conncheck_id,
                    check.pair,
                    check.nominate
                );
                check.set_state(CandidatePairState::InProgress);
                Some(check)
            } else {
                trace!("nothing to be done for stream");
                None
            }
        }
    }

    pub(crate) async fn agent_conncheck_process(&self) -> Result<(), AgentError> {
        // perform initial set up
        for checklist in self.checklists.iter() {
            checklist.generate_checks();
        }

        let mut thawn_foundations = vec![];
        for checklist in self.checklists.iter() {
            checklist.initial_thaw(&mut thawn_foundations);
        }

        loop {
            let mut any_running = false;
            let mut processed = false;
            for checklist in self.checklists.iter() {
                trace!("current checklist state {:?}", checklist.state());
                if checklist.state() == CheckListState::Running {
                    any_running = true;
                }
                let conncheck = match self.get_next_check(checklist.clone()) {
                    Some(c) => c,
                    None => {
                        continue;
                    }
                };
                // FIXME: get these values from the agent
                let tie_breaker = 0;
                if self
                    .tasks
                    .add_task(
                        ConnCheckListSet::perform_conncheck(
                            conncheck,
                            checklist.clone(),
                            self.checklists.to_vec(),
                            checklist.controlling(),
                            tie_breaker,
                        )
                        .boxed(),
                    )
                    .await
                    .is_err()
                {
                    // receiver stopped -> no more timers
                    return Ok(());
                }
                processed = true;
                Delay::new(Duration::from_millis(100 /* FIXME */)).await;
            }
            if !any_running {
                info!("nothing to process");
                // exit condition is when no checklists are in the running state
                return Ok(());
            }
            if !processed {
                // nothing was processed however checklist state is still running, delay until next
                // tick
                Delay::new(Duration::from_millis(100 /* FIXME */)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::candidate::*;
    use crate::socket::*;
    use crate::stun::agent::*;
    use async_std::net::UdpSocket;
    use async_std::task;
    use std::sync::Arc;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    struct Peer {
        channel: Arc<UdpSocketChannel>,
        candidate: Candidate,
        agent: StunAgent,
    }

    async fn construct_peer_with_foundation(foundation: &str) -> Peer {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let candidate = Candidate::new(
            CandidateType::Host,
            TransportType::Udp,
            foundation,
            0,
            addr,
            addr,
            None,
        );
        let channel = Arc::new(UdpSocketChannel::new(socket));
        let agent = StunAgent::new(channel.clone());

        Peer {
            channel,
            candidate,
            agent,
        }
    }

    async fn construct_peer() -> Peer {
        construct_peer_with_foundation("0").await
    }

    #[test]
    fn get_candidates() {
        init();
        async_std::task::block_on(async move {
            let agent = Agent::default();
            let stream = agent.add_stream();
            let component = stream.add_component().unwrap();

            let local = construct_peer().await;
            let remote = construct_peer().await;

            let list = ConnCheckList::new();
            list.add_local_candidate(&component, local.candidate.clone(), local.agent.clone())
                .await;
            list.add_remote_candidate(component.id, remote.candidate.clone());

            // The candidate list is only what we put in
            let locals = list.get_local_candidates();
            assert_eq!(locals.len(), 1);
            assert_eq!(locals[0], local.candidate);
            let remotes = list.get_remote_candidates();
            assert_eq!(remotes.len(), 1);
            assert_eq!(remotes[0], remote.candidate);
        })
    }

    // simplified version of ConnCheckList handle_binding_request that doesn't
    // update any state like ConnCheckList or even do peer-reflexive candidate
    // things
    async fn handle_binding_request(
        agent: &StunAgent,
        msg: &Message,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<(), AgentError> {
        let local_credentials = agent.local_credentials().unwrap();
        let remote_credentials = agent.remote_credentials().unwrap();

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
            // TODO Validate USERNAME
            &[/*USERNAME, */ FINGERPRINT, MESSAGE_INTEGRITY, PRIORITY],
        ) {
            // failure -> send error response
            agent.send(error_msg, from).await?;
            return Ok(());
        }

        msg.validate_integrity(data, &remote_credentials)?;

        let mut response = Message::new_success(msg);
        response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()).to_raw())?;
        response.add_message_integrity(&local_credentials)?;
        response.add_fingerprint()?;
        agent.send(response, from).await?;
        Ok(())
    }

    #[test]
    fn conncheck_udp_host() {
        init();
        async_std::task::block_on(async move {
            let local_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "local".to_owned(),
            });
            let remote_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "remote".to_owned(),
            });
            // start the remote peer
            let remote = construct_peer().await;
            remote
                .agent
                .set_local_credentials(remote_credentials.clone());
            remote
                .agent
                .set_remote_credentials(local_credentials.clone());
            // set up the local peer
            let local = construct_peer().await;
            local.agent.set_local_credentials(local_credentials);
            local.agent.set_remote_credentials(remote_credentials);

            let mut remote_data_stream = remote.agent.data_receive_stream();
            task::spawn(async move {
                while let Some((data, from)) = remote_data_stream.next().await {
                    info!("received from {} data: {:?}", from, data);
                }
            });

            let mut remote_stun_stream = remote.agent.stun_receive_stream();
            task::spawn({
                let agent = remote.agent.clone();
                async move {
                    while let Some((msg, data, from)) = remote_stun_stream.next().await {
                        info!("received from {}: {:?}", from, msg);
                        if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                            handle_binding_request(&agent, &msg, &data, from)
                                .await
                                .unwrap();
                        }
                    }
                }
            });

            let mut data_stream = local.agent.data_receive_stream();
            task::spawn(async move {
                while let Some((data, from)) = data_stream.next().await {
                    info!("received from {} data: {:?}", from, data);
                }
            });

            let mut stun_stream = local.agent.stun_receive_stream();
            task::spawn({
                let agent = local.agent.clone();
                async move {
                    while let Some((msg, data, from)) = stun_stream.next().await {
                        info!("received from {}: {}", from, msg);
                        if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                            handle_binding_request(&agent, &msg, &data, from)
                                .await
                                .unwrap();
                        }
                    }
                }
            });

            let pair = CandidatePair::new(1, local.candidate, remote.candidate);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent, false));

            // this is what we're testing.  All of the above is setup for performing this check
            let nominate = conncheck.nominate();
            let res = connectivity_check_cancellable(conncheck, true, 0, nominate)
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

    #[test]
    fn checklist_fake_simple_success() {
        init();
        async_std::task::block_on(async move {
            let agent = Agent::default();
            let stream = agent.add_stream();
            let component = stream.add_component().unwrap();
            let local = construct_peer().await;
            let remote = construct_peer().await;
            let pair = CandidatePair::new(
                component.id,
                local.candidate.clone(),
                remote.candidate.clone(),
            );

            let list = ConnCheckList::new();
            list.add_local_candidate(&component, local.candidate, local.agent)
                .await;
            list.add_remote_candidate(component.id, remote.candidate);

            // fake the connection process state changes without any actual connections
            list.generate_checks();
            let mut foundations = vec![];
            list.initial_thaw(&mut foundations);
            assert_eq!(foundations.len(), 1);
            assert_eq!(foundations[0], pair.get_foundation());
            assert!(list.next_triggered().is_none());
            let check = list.next_waiting().unwrap();
            assert_eq!(check.pair, pair);
            let matching = list.get_matching_check(&pair).unwrap();
            assert_eq!(matching.pair, pair);
            check.set_state(CandidatePairState::Succeeded);
            list.add_valid(check.pair.clone());
        });
    }

    fn assert_list_does_not_contain_checks(list: &ConnCheckList, pairs: Vec<&CandidatePair>) {
        for pair in pairs.iter() {
            assert!(list.get_matching_check(pair).is_none());
        }
    }

    fn assert_list_contains_checks(list: &ConnCheckList, pairs: Vec<&CandidatePair>) {
        for pair in pairs.iter() {
            let check = list.get_matching_check(pair).unwrap();
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
            let local1 = construct_peer().await;
            let remote1 = construct_peer().await;
            let local2 = construct_peer().await;
            let remote2 = construct_peer().await;
            let local3 = construct_peer().await;
            let remote3 = construct_peer().await;

            let list = ConnCheckList::new();
            list.add_local_candidate(&component1, local1.candidate.clone(), local1.agent)
                .await;
            list.add_remote_candidate(component1.id, remote1.candidate.clone());
            list.add_local_candidate(&component2, local2.candidate.clone(), local2.agent)
                .await;
            list.add_remote_candidate(component2.id, remote2.candidate.clone());
            list.add_local_candidate(&component1, local3.candidate.clone(), local3.agent)
                .await;
            list.add_remote_candidate(component1.id, remote3.candidate.clone());

            list.generate_checks();
            let pair1 = CandidatePair::new(
                component1.id,
                local1.candidate.clone(),
                remote1.candidate.clone(),
            );
            let pair2 = CandidatePair::new(
                component2.id,
                local2.candidate.clone(),
                remote2.candidate.clone(),
            );
            let pair3 = CandidatePair::new(
                component1.id,
                local3.candidate.clone(),
                remote3.candidate.clone(),
            );
            let pair4 =
                CandidatePair::new(component1.id, local1.candidate.clone(), remote3.candidate);
            let pair5 = CandidatePair::new(component1.id, local3.candidate, remote1.candidate);
            assert_list_contains_checks(&list, vec![&pair1, &pair2, &pair3, &pair4, &pair5]);
            assert_list_does_not_contain_checks(
                &list,
                vec![
                    &CandidatePair::new(1, local2.candidate.clone(), remote2.candidate),
                    &CandidatePair::new(1, local1.candidate, local2.candidate),
                ],
            );
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
            let list1 = ConnCheckList::new();
            let list2 = ConnCheckList::new();

            let local1 = construct_peer_with_foundation("0").await;
            let remote1 = construct_peer_with_foundation("0").await;
            let local2 = construct_peer_with_foundation("0").await;
            let remote2 = construct_peer_with_foundation("0").await;
            let local3 = construct_peer_with_foundation("1").await;
            let remote3 = construct_peer_with_foundation("1").await;

            list1
                .add_local_candidate(&component1, local1.candidate.clone(), local1.agent)
                .await;
            list1.add_remote_candidate(component1.id, remote1.candidate.clone());
            list2
                .add_local_candidate(&component2, local2.candidate.clone(), local2.agent)
                .await;
            list2.add_remote_candidate(component2.id, remote2.candidate.clone());
            list2
                .add_local_candidate(&component2, local3.candidate.clone(), local3.agent)
                .await;
            list2.add_remote_candidate(component2.id, remote3.candidate.clone());

            list1.generate_checks();
            list2.generate_checks();

            // generated pairs
            let pair1 = CandidatePair::new(component1.id, local1.candidate, remote1.candidate);
            let pair2 = CandidatePair::new(
                component2.id,
                local2.candidate.clone(),
                remote2.candidate.clone(),
            );
            let pair3 = CandidatePair::new(
                component2.id,
                local3.candidate.clone(),
                remote3.candidate.clone(),
            );
            let pair4 = CandidatePair::new(component2.id, local2.candidate, remote3.candidate);
            let pair5 = CandidatePair::new(component2.id, local3.candidate, remote2.candidate);
            assert_list_contains_checks(&list1, vec![&pair1]);
            assert_list_contains_checks(&list2, vec![&pair2, &pair3, &pair4, &pair5]);

            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            list1.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 1);
            assert_eq!(&thawn[0], &pair1.get_foundation());
            // thaw the second checklist with 2*2 pairs will unfreeze only the foundations not
            // unfrozen by the first checklist, which means unfreezing 3 pairs
            list2.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 4);
            assert!(thawn.iter().any(|f| f == &pair2.get_foundation()));
            assert!(thawn.iter().any(|f| f == &pair3.get_foundation()));
            assert!(thawn.iter().any(|f| f == &pair4.get_foundation()));
            assert!(thawn.iter().any(|f| f == &pair5.get_foundation()));
            let check1 = list1.get_matching_check(&pair1).unwrap();
            assert_eq!(check1.pair, pair1);
            assert_eq!(check1.state(), CandidatePairState::Waiting);
            let check2 = list2.get_matching_check(&pair2).unwrap();
            assert_eq!(check2.pair, pair2);
            assert_eq!(check2.state(), CandidatePairState::Frozen);
            let check3 = list2.get_matching_check(&pair3).unwrap();
            assert_eq!(check3.pair, pair3);
            assert_eq!(check3.state(), CandidatePairState::Waiting);
            let check4 = list2.get_matching_check(&pair4).unwrap();
            assert_eq!(check4.pair, pair4);
            assert_eq!(check4.state(), CandidatePairState::Waiting);
            let check5 = list2.get_matching_check(&pair5).unwrap();
            assert_eq!(check5.pair, pair5);
            assert_eq!(check5.state(), CandidatePairState::Waiting);
        });
    }
}
