// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures::prelude::*;

use crate::candidate::{Candidate, CandidatePair};

use crate::agent::AgentError;

use crate::stun::agent::StunAgent;
use crate::stun::attribute::*;
use crate::stun::message::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
    Frozen,
}

#[derive(Debug)]
pub(crate) struct ConnCheck {
    pub pair: CandidatePair,
    state: Mutex<CandidatePairState>,
    pub agent: Arc<StunAgent>,
}

impl ConnCheck {
    pub(crate) fn new(pair: CandidatePair, agent: Arc<StunAgent>) -> Self {
        Self {
            pair,
            state: Mutex::new(CandidatePairState::Frozen),
            agent,
        }
    }

    pub(crate) fn state(&self) -> CandidatePairState {
        *self.state.lock().unwrap()
    }

    pub(crate) fn set_state(&self, state: CandidatePairState) {
        let mut inner = self.state.lock().unwrap();
        // TODO: validate state change
        trace!(
            "state change from '{:?}' to '{:?}' for {:?}",
            inner,
            state,
            self.pair
        );
        *inner = state;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CheckListState {
    Running,
    Completed,
    Failed,
}

#[derive(Debug)]
pub struct ConnCheckList {
    inner: Mutex<ConnCheckListInner>,
}

impl Default for ConnCheckList {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Default::default()),
        }
    }
}

#[derive(Debug)]
struct ConnCheckListInner {
    // TODO: move to BinaryHeap or similar
    state: CheckListState,
    local_candidates: Vec<(usize, Candidate, Arc<StunAgent>)>,
    remote_candidates: Vec<(usize, Candidate)>,
    triggered: VecDeque<Arc<ConnCheck>>,
    pairs: VecDeque<Arc<ConnCheck>>,
    valid: Vec<CandidatePair>,
}

impl Default for ConnCheckListInner {
    fn default() -> Self {
        Self {
            state: CheckListState::Running,
            local_candidates: vec![],
            remote_candidates: vec![],
            triggered: VecDeque::new(),
            pairs: VecDeque::new(),
            valid: vec![],
        }
    }
}

impl ConnCheckList {
    pub(crate) fn add_local_candidate(
        &self,
        component_id: usize,
        local: Candidate,
        agent: Arc<StunAgent>,
    ) {
        debug!("adding local {:?}", local);
        self.inner
            .lock()
            .unwrap()
            .local_candidates
            .push((component_id, local, agent));
    }

    pub(crate) fn add_remote_candidate(&self, component_id: usize, remote: Candidate) {
        debug!("adding remote {:?}", remote);
        self.inner
            .lock()
            .unwrap()
            .remote_candidates
            .push((component_id, remote));
    }

    pub(crate) fn generate_checks(&self) {
        let mut inner = self.inner.lock().unwrap();
        let mut pairs = vec![];
        for (local_comp_id, local, local_agent) in inner.local_candidates.iter() {
            for (remote_comp_id, remote) in inner.remote_candidates.iter() {
                if local.transport_type == remote.transport_type && local_comp_id == remote_comp_id
                {
                    let pair = CandidatePair::new(*local_comp_id, local.clone(), remote.clone());
                    pairs.push(Arc::new(ConnCheck::new(pair, local_agent.clone())));
                }
            }
        }
        inner.pairs.extend(pairs);
    }

    pub(crate) fn add_triggered(&self, check: Arc<ConnCheck>) {
        debug!("adding trigerred {:?}", check);
        self.inner.lock().unwrap().triggered.push_front(check)
    }

    pub(crate) fn initial_thaw(&self, thawn_foundations: &mut Vec<String>) {
        let mut inner = self.inner.lock().unwrap();
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
        info!("maybe thaw {:?}", dbg_maybe);
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
            if let Some(_) = seen_foundations
                .iter()
                .find(|&foundation| &check.pair.get_foundation() == foundation)
            {
                false
            } else {
                seen_foundations.push(check.pair.get_foundation().clone());
                true
            }
        });

        debug!("thawing foundations {:?}", seen_foundations);

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

    pub(crate) fn next_triggered(&self) -> Option<Arc<ConnCheck>> {
        self.inner.lock().unwrap().triggered.pop_back()
    }

    // note this will change the state of the returned check to InProgress to avoid a race
    pub(crate) fn next_waiting(&self) -> Option<Arc<ConnCheck>> {
        self.inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            // first look for any that are waiting
            // FIXME: should be highest priority pair: make the data structure give us that by
            // default
            .filter_map(|check| {
                if check.state() == CandidatePairState::Waiting {
                    check.set_state(CandidatePairState::InProgress);
                    Some(check)
                } else {
                    None
                }
            })
            .cloned()
            .next()
    }

    // note this will change the returned check state to waiting to avoid a race
    pub(crate) fn next_frozen(&self, from_foundations: &[String]) -> Option<Arc<ConnCheck>> {
        self.inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            .filter_map(|check| {
                if check.state() == CandidatePairState::Frozen {
                    from_foundations
                        .iter()
                        .filter(|&f| f == &check.pair.get_foundation())
                        .next()
                        .and(Some(check))
                } else {
                    None
                }
            })
            .cloned()
            .inspect(|check| check.set_state(CandidatePairState::Waiting))
            .next()
    }

    fn unfreeze_foundations(&self, frozen_foundations: &[&str]) {
        let _: Vec<_> = self
            .inner
            .lock()
            .unwrap()
            .pairs
            .iter_mut()
            .map(|check| {
                if check.state() == CandidatePairState::Frozen {
                    frozen_foundations
                        .iter()
                        .find(|&foundation| foundation == &check.pair.get_foundation())
                        .map(|_| check.set_state(CandidatePairState::Waiting));
                }
            })
            .collect();
    }

    pub(crate) fn foundations(&self) -> std::collections::HashSet<String> {
        let mut foundations = std::collections::HashSet::new();
        let _: Vec<_> = self
            .inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            .cloned()
            .inspect(|check| {
                foundations.insert(check.pair.get_foundation().clone());
            })
            .collect();
        foundations
    }

    pub(crate) fn foundation_not_waiting_in_progress(&self, foundation: &str) -> bool {
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

    pub(crate) fn add_valid(&self, pair: CandidatePair) {
        self.inner.lock().unwrap().valid.push(pair);
    }

    pub(crate) fn get_matching_check(&self, pair: &CandidatePair) -> Option<Arc<ConnCheck>> {
        self.inner
            .lock()
            .unwrap()
            .pairs
            .iter()
            .find(|&check| {
                check.pair.component_id == pair.component_id
                    && check.pair.local == pair.local
                    && check.pair.remote == pair.remote
            })
            .cloned()
    }

    pub(crate) fn get_local_candidates(&self) -> Vec<Candidate> {
        self.inner
            .lock()
            .unwrap()
            .local_candidates
            .iter()
            .map(|(_, cand, _)| cand.clone())
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
}

#[derive(Debug)]
pub(crate) enum ConnCheckResponse {
    Success(Arc<ConnCheck>, SocketAddr),
    Failure(Arc<ConnCheck>),
    Timeout(Arc<ConnCheck>),
}

pub(crate) async fn connectivity_check(
    conncheck: Arc<ConnCheck>,
    controlling: bool,
    tie_breaker: u64,
) -> Result<ConnCheckResponse, AgentError> {
    // generate binding request
    let msg = {
        let mut msg = Message::new_request_method(BINDING);

        msg.add_attribute(
            XorMappedAddress::new(
                conncheck.pair.local.base_address.clone(),
                msg.transaction_id(),
            )
            .unwrap()
            .into(),
        )?;
        msg.add_attribute(Priority::new(conncheck.pair.local.priority).into())?;
        if controlling {
            msg.add_attribute(IceControlling::new(tie_breaker).into())?;
        } else {
            msg.add_attribute(IceControlled::new(tie_breaker).into())?;
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
    let (response, from) = conncheck.agent.stun_request_transaction(&msg, to).await?;

    if !response.is_response() {
        // response is not a response!
        return Ok(ConnCheckResponse::Failure(conncheck));
    }

    // if response error -> fail TODO: might be a recoverable error!
    if response.has_class(MessageClass::Error) {
        // FIXME: some failures are recoverable
        info!("error response {}", response);
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

    if let Some(xor_attr) = response.get_attribute(XOR_MAPPED_ADDRESS) {
        if let Ok(xor) = XorMappedAddress::from_raw(xor_attr) {
            let xor_addr = xor.addr(response.transaction_id());
            // TODO: if response mapped address not in remote candidate list -> new peer-reflexive candidate
            // TODO glare
            return Ok(ConnCheckResponse::Success(conncheck, xor_addr));
        }
    }

    Ok(ConnCheckResponse::Failure(conncheck))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::*;
    use crate::socket::*;
    use crate::stun::agent::*;
    use async_std::net::UdpSocket;
    use async_std::task;
    use std::sync::Arc;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn get_candidates() {
        init();
        task::block_on(async move {
            let local_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local_channel = Arc::new(UdpSocketChannel::new(local_socket));
            let local_addr = local_channel.local_addr().unwrap();
            let local_candidate = Candidate::new(
                CandidateType::Host,
                TransportType::Udp,
                "0",
                0,
                local_addr.clone(),
                local_addr,
                None,
            );
            let remote_addr: SocketAddr = "127.0.0.1:9998".parse().unwrap();
            let remote_candidate = Candidate::new(
                CandidateType::Host,
                TransportType::Udp,
                "0",
                0,
                remote_addr.clone(),
                remote_addr,
                None,
            );
            let list = ConnCheckList::default();
            let local_agent = Arc::new(StunAgent::new(local_channel));
            list.add_local_candidate(1, local_candidate.clone(), local_agent);
            list.add_remote_candidate(1, remote_candidate.clone());

            let locals = list.get_local_candidates();
            assert_eq!(locals.len(), 1);
            assert_eq!(locals[0], local_candidate);
            let remotes = list.get_remote_candidates();
            assert_eq!(remotes.len(), 1);
            assert_eq!(remotes[0], remote_candidate);
        })
    }

    struct Peer {
        channel: Arc<UdpSocketChannel>,
        candidate: Candidate,
        agent: Arc<StunAgent>,
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
        let agent = Arc::new(StunAgent::new(channel.clone()));

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
    fn conncheck_udp_host() {
        init();
        task::block_on(async move {
            // start the remote peer
            let remote = construct_peer().await;

            let mut remote_data_stream = remote.agent.data_receive_stream();
            task::spawn(async move {
                while let Some((data, from)) = remote_data_stream.next().await {
                    info!("received from {} data: {:?}", from, data);
                }
            });

            let mut remote_stun_stream = remote.agent.stun_receive_stream();
            task::spawn(async move {
                while let Some((msg, from)) = remote_stun_stream.next().await {
                    info!("received from {}: {:?}", from, msg);
                }
            });

            // set up the local peer
            let local = construct_peer().await;

            let mut data_stream = local.agent.data_receive_stream();
            task::spawn(async move {
                while let Some((data, from)) = data_stream.next().await {
                    info!("received from {} data: {:?}", from, data);
                }
            });

            let mut stun_stream = local.agent.stun_receive_stream();
            task::spawn(async move {
                while let Some((msg, from)) = stun_stream.next().await {
                    info!("received from {}: {}", from, msg);
                }
            });

            let local_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "local".to_owned(),
            });
            let remote_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "remote".to_owned(),
            });
            local.agent.set_local_credentials(local_credentials.clone());
            local
                .agent
                .set_remote_credentials(remote_credentials.clone());
            remote.agent.set_local_credentials(remote_credentials);
            remote.agent.set_remote_credentials(local_credentials);
            let pair = CandidatePair::new(1, local.candidate, remote.candidate);
            let conncheck = Arc::new(ConnCheck::new(pair, local.agent));

            // this is what we're testing.  All of the above is setup for performing this check
            let res = connectivity_check(conncheck, true, 0).await.unwrap();
            match res {
                ConnCheckResponse::Success(_check, addr) => {
                    assert_eq!(addr, local.channel.local_addr().unwrap());
                }
                _ => unreachable!(),
            }
        })
    }

    #[test]
    fn checklist_success() {
        init();
        task::block_on(async move {
            let local = construct_peer().await;
            let remote = construct_peer().await;
            let pair = CandidatePair::new(1, local.candidate.clone(), remote.candidate.clone());

            let list = ConnCheckList::default();
            list.add_local_candidate(1, local.candidate, local.agent);
            list.add_remote_candidate(1, remote.candidate);

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

    #[test]
    fn checklist_generate_checks() {
        init();
        task::block_on(async move {
            let local1 = construct_peer().await;
            let remote1 = construct_peer().await;
            let local2 = construct_peer().await;
            let remote2 = construct_peer().await;
            let local3 = construct_peer().await;
            let remote3 = construct_peer().await;

            let list = ConnCheckList::default();
            list.add_local_candidate(1, local1.candidate.clone(), local1.agent);
            list.add_remote_candidate(1, remote1.candidate.clone());
            list.add_local_candidate(2, local2.candidate.clone(), local2.agent);
            list.add_remote_candidate(2, remote2.candidate.clone());
            list.add_local_candidate(1, local3.candidate.clone(), local3.agent);
            list.add_remote_candidate(1, remote3.candidate.clone());

            list.generate_checks();
            let pair2 = CandidatePair::new(2, local2.candidate.clone(), remote2.candidate.clone());
            let check2 = list.get_matching_check(&pair2).unwrap();
            assert_eq!(check2.pair, pair2);
            let pair1 = CandidatePair::new(1, local1.candidate.clone(), remote1.candidate.clone());
            let check1 = list.get_matching_check(&pair1).unwrap();
            assert_eq!(check1.pair, pair1);
            let pair3 = CandidatePair::new(1, local3.candidate.clone(), remote3.candidate.clone());
            let check3 = list.get_matching_check(&pair3).unwrap();
            assert_eq!(check3.pair, pair3);
            let pair4 = CandidatePair::new(1, local1.candidate.clone(), remote3.candidate);
            let check4 = list.get_matching_check(&pair4).unwrap();
            assert_eq!(check4.pair, pair4);
            let pair5 = CandidatePair::new(1, local3.candidate, remote1.candidate);
            let check5 = list.get_matching_check(&pair5).unwrap();
            assert_eq!(check5.pair, pair5);
            assert!(list
                .get_matching_check(&CandidatePair::new(
                    1,
                    local2.candidate.clone(),
                    remote2.candidate
                ))
                .is_none());
            assert!(list
                .get_matching_check(&CandidatePair::new(1, local1.candidate, local2.candidate))
                .is_none());
        });
    }

    #[test]
    fn checklists_initial_thaw() {
        task::block_on(async move {
            let list1 = ConnCheckList::default();
            let list2 = ConnCheckList::default();

            let local1 = construct_peer_with_foundation("0").await;
            let remote1 = construct_peer_with_foundation("0").await;
            let local2 = construct_peer_with_foundation("0").await;
            let remote2 = construct_peer_with_foundation("0").await;
            let local3 = construct_peer_with_foundation("1").await;
            let remote3 = construct_peer_with_foundation("1").await;

            list1.add_local_candidate(1, local1.candidate.clone(), local1.agent);
            list1.add_remote_candidate(1, remote1.candidate.clone());
            list2.add_local_candidate(1, local2.candidate.clone(), local2.agent);
            list2.add_remote_candidate(1, remote2.candidate.clone());
            list2.add_local_candidate(1, local3.candidate.clone(), local3.agent);
            list2.add_remote_candidate(1, remote3.candidate.clone());

            list1.generate_checks();
            list2.generate_checks();

            // generated pairs
            let pair1 = CandidatePair::new(1, local1.candidate, remote1.candidate);
            let pair2 = CandidatePair::new(1, local2.candidate.clone(), remote2.candidate.clone());
            let pair3 = CandidatePair::new(1, local3.candidate.clone(), remote3.candidate.clone());
            let pair4 = CandidatePair::new(1, local2.candidate, remote3.candidate);
            let pair5 = CandidatePair::new(1, local3.candidate, remote2.candidate);
            let mut thawn = vec![];
            // thaw the first checklist with only a single pair will unfreeze that pair
            list1.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 1);
            assert_eq!(&thawn[0], &pair1.get_foundation());
            // thaw the second checklist with 2*2 pairs will unfreeze only the foundations not
            // unfrozen by the first checklist, which means unfreezing 3 pairs
            list2.initial_thaw(&mut thawn);
            assert_eq!(thawn.len(), 4);
            assert!(thawn
                .iter()
                .find(|&f| f == &pair2.get_foundation())
                .is_some());
            assert!(thawn
                .iter()
                .find(|&f| f == &pair3.get_foundation())
                .is_some());
            assert!(thawn
                .iter()
                .find(|&f| f == &pair4.get_foundation())
                .is_some());
            assert!(thawn
                .iter()
                .find(|&f| f == &pair5.get_foundation())
                .is_some());
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
