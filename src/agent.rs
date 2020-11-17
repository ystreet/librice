// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::Display;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures;
use futures::prelude::*;
use futures::stream::StreamExt;
use futures_timer::Delay;

use crate::candidate::Candidate;
use crate::component::{Component, ComponentState};
use crate::socket::ChannelBroadcast;
use crate::stream::Stream;

#[derive(Debug)]
pub enum AgentError {
    AlreadyExists,
    AlreadyInProgress,
    ResourceNotFound,
    NotEnoughData,
    InvalidSize,
    Malformed,
    NotStun,
    WrongImplementation,
    TooBig,
    ConnectionClosed,
    IntegrityCheckFailed,
    IoError(std::io::Error),
}

impl Error for AgentError {}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[derive(Debug, Clone)]
pub enum AgentMessage {
    NewLocalCandidate(Arc<Component>, Candidate),
    GatheringCompleted(Arc<Component>),
    ComponentStateChange(Arc<Component>, ComponentState),
}

#[derive(Debug)]
pub struct Agent {
    inner: Arc<Mutex<AgentInner>>,
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    tasks: Arc<TaskList>,
}

#[derive(Debug)]
pub(crate) struct AgentInner {
    streams: Vec<Arc<Stream>>,
    checklistset: Option<Arc<ConnCheckListSet>>,
}

type AgentFuture = Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send>>;

impl AgentInner {
    fn new() -> Self {
        Self {
            streams: vec![],
            checklistset: None,
        }
    }
}

impl Default for Agent {
    fn default() -> Self {
        Agent {
            inner: Arc::new(Mutex::new(AgentInner::new())),
            broadcast: Arc::new(ChannelBroadcast::default()),
            tasks: Arc::new(TaskList::new()),
        }
    }
}

#[derive(Debug)]
enum TaskReturn {
    NoMoreFutures,
    Wakeup,
    FutureReturn(Result<(), AgentError>),
}

type TaskFuture = Pin<Box<dyn Future<Output = TaskReturn> + Send>>;

#[derive(Debug)]
struct TaskList {
    task_sender: Mutex<Option<async_channel::Sender<TaskFuture>>>,
    task_receiver: Mutex<Option<async_channel::Receiver<TaskFuture>>>,
}

impl TaskList {
    pub(crate) fn new() -> Self {
        let (send, recv) = async_channel::bounded(16);
        Self {
            task_sender: Mutex::new(Some(send)),
            task_receiver: Mutex::new(Some(recv)),
        }
    }

    pub(crate) async fn add_task(&self, fut: AgentFuture) -> Result<(), AgentError> {
        trace!("sending future");
        let sender = {
            self.task_sender
                .lock()
                .unwrap()
                .clone()
                .ok_or(AgentError::ConnectionClosed)?
        };
        sender
            .send(async move { TaskReturn::FutureReturn(fut.await) }.boxed())
            .await
            .map_err(|_| AgentError::ConnectionClosed)
    }

    async fn add_future_to_task_list(
        future_list: Arc<Mutex<VecDeque<TaskFuture>>>,
        mut receiver: async_channel::Receiver<TaskFuture>,
    ) -> TaskReturn {
        if let Some(task) = receiver.next().await {
            trace!("receiving future");
            future_list.lock().unwrap().push_back(task);
            TaskReturn::Wakeup
        } else {
            TaskReturn::NoMoreFutures
        }
    }

    pub(crate) async fn iterate_tasks(&self) -> Result<(), AgentError> {
        let receiver =
            { self.task_receiver.lock().unwrap().take() }.ok_or(AgentError::AlreadyInProgress)?;

        let mut futures = futures::stream::FuturesUnordered::new();
        let new_futures = Arc::new(Mutex::new(VecDeque::new()));
        futures
            .push(TaskList::add_future_to_task_list(new_futures.clone(), receiver.clone()).boxed());
        while let Some(ret) = futures.next().await {
            trace!("iterating over future");
            match ret {
                TaskReturn::Wakeup => {
                    trace!("wakeup, readding wakeup future");
                    futures.push(
                        TaskList::add_future_to_task_list(new_futures.clone(), receiver.clone())
                            .boxed(),
                    )
                }
                TaskReturn::NoMoreFutures => {
                    info!("no more futures, exiting");
                }
                TaskReturn::FutureReturn(ret) => ret?,
            }
            {
                let mut add_futures = new_futures.lock().unwrap();
                trace!("adding {} futures to tasklist", add_futures.len());
                while let Some(new_fut) = add_futures.pop_front() {
                    futures.push(new_fut);
                }
            }
        }

        {
            self.task_receiver.lock().unwrap().replace(receiver);
        }
        Ok(())
    }

    pub(crate) async fn stop(&self) -> Result<(), AgentError> {
        self.task_sender.lock().unwrap().take();
        Ok(())
    }
}

impl Agent {
    /// Add a new `Stream` to this agent
    ///
    /// # Examples
    ///
    /// Add a `Stream`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// let agent = Agent::default();
    /// let s = agent.add_stream();
    /// ```
    pub fn add_stream(&self) -> Arc<Stream> {
        let s = Arc::new(Stream::new(Arc::downgrade(&self.inner)));
        {
            let mut inner = self.inner.lock().unwrap();
            inner.streams.push(s.clone());
        }
        s
    }

    /// Run the agent loop
    pub async fn run_loop(&self) -> Result<(), AgentError> {
        self.tasks.iterate_tasks().await
    }

    pub fn start(&self) {
        let set = {
            let mut inner = self.inner.lock().unwrap();
            if inner.checklistset.is_some() {
                // already started?
                // TODO: ICE restart
                return;
            }
            let set = Arc::new(ConnCheckListSet::from_streams(
                inner.streams.clone(),
                self.broadcast.clone(),
                self.tasks.clone(),
            ));
            inner.checklistset = Some(set.clone());
            set
        };
        async_std::task::spawn(async move {
            set.agent_conncheck_process().await;
        });
    }

    pub fn message_channel(&self) -> impl futures::Stream<Item = AgentMessage> {
        self.broadcast.channel()
    }

    /// Close the agent loop
    pub async fn close(&self) -> Result<(), AgentError> {
        self.tasks.stop().await
    }
}

use crate::conncheck::{
    connectivity_check, CandidatePairState, ConnCheck, ConnCheckList, ConnCheckResponse,
};

#[derive(Debug)]
struct ConnCheckListSet {
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    checklists: Vec<Arc<ConnCheckList>>,
    tasks: Arc<TaskList>,
}

impl ConnCheckListSet {
    // TODO: add/remove a stream after start
    // TODO: cancel when agent is stopped
    pub(crate) fn from_streams(
        streams: Vec<Arc<Stream>>,
        broadcast: Arc<ChannelBroadcast<AgentMessage>>,
        tasks: Arc<TaskList>,
    ) -> Self {
        Self {
            broadcast,
            checklists: streams.iter().map(|s| s.checklist.clone()).collect(),
            tasks,
        }
    }

    async fn perform_conncheck(
        conncheck: Arc<ConnCheck>,
        checklist: Arc<ConnCheckList>,
        checklists: Vec<Arc<ConnCheckList>>,
    ) -> Result<(), AgentError> {
        connectivity_check(
            conncheck, /* FIXME */ true, /* FIXME */ 0, /* FIXME */ false,
        )
        .map(|response| {
            match response {
                Err(e) => warn!("{:?}", e),
                Ok(ConnCheckResponse::Failure(conncheck)) => {
                    warn!("conncheck timeout/failure");
                    conncheck.set_state(CandidatePairState::Failed);
                }
                Ok(ConnCheckResponse::RoleConflict(_conncheck)) => error!("Role Conflict"),
                Ok(ConnCheckResponse::Success(conncheck, addr)) => {
                    debug!("conncheck succeeded in finding {:?}", addr);
                    conncheck.set_state(CandidatePairState::Succeeded);
                    let mut pair_dealt_with = false;
                    let ok_pair = conncheck.pair.construct_valid(addr);
                    // 1.
                    // If the valid pair equals the pair that generated the check, the
                    // pair is added to the valid list associated with the checklist to
                    // which the pair belongs; or
                    if let Some(_check) = checklist.get_matching_check(&ok_pair) {
                        checklist.add_valid(ok_pair.clone());
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
                        checklist.add_valid(conncheck.pair.clone());
                    }
                } // TODO: continue binding keepalives/implement RFC7675
            };
        })
        .await;
        Ok(())
    }

    async fn agent_conncheck_process(&self) -> Result<(), AgentError> {
        // perform initial set up
        for checklist in self.checklists.iter() {
            checklist.generate_checks();
        }

        let mut thawn_foundations = vec![];
        for checklist in self.checklists.iter() {
            checklist.initial_thaw(&mut thawn_foundations);
        }

        loop {
            let mut processed = false;
            for checklist in self.checklists.iter() {
                let conncheck = {
                    if let Some(check) = checklist.next_triggered() {
                        trace!("found trigerred check {:?}", check);
                        check.clone()
                    } else if let Some(check) = checklist.next_waiting() {
                        trace!("found waiting check {:?}", check);
                        check.clone()
                    } else {
                        // TODO: cache this locally somewhere
                        // TODO: iter()ize this
                        // If there is no candidate pair in the Waiting state, and if there
                        // are one or more pairs in the Frozen state, the agent checks the
                        // foundation associated with each pair in the Frozen state.  For a
                        // given foundation, if there is no pair (in any checklist in the
                        // checklist set) in the Waiting or In-Progress state, the agent
                        // puts the candidate pair state to Waiting and continues with the
                        // next step.
                        let mut foundations = std::collections::HashSet::new();
                        for checklist in self.checklists.iter() {
                            for f in checklist.foundations() {
                                foundations.insert(f);
                            }
                        }
                        let mut foundations_not_waiting_in_progress =
                            std::collections::HashSet::new();
                        let _: Vec<_> = foundations
                            .into_iter()
                            .map(|f| {
                                if self.checklists.iter().all(|checklist| {
                                    checklist.foundation_not_waiting_in_progress(&f)
                                }) {
                                    foundations_not_waiting_in_progress.insert(f);
                                }
                            })
                            .collect();
                        let next: Vec<_> =
                            foundations_not_waiting_in_progress.into_iter().collect();
                        trace!("current foundations not waiting or in progress: {:?}", next);

                        if let Some(check) = checklist.next_frozen(&next) {
                            trace!("found frozen check {:?}", check);
                            check.set_state(CandidatePairState::InProgress);
                            check.clone()
                        } else {
                            trace!("nothing to be done for stream");
                            continue;
                        }
                    }
                };
                if let Err(_) = self
                    .tasks
                    .add_task(
                        ConnCheckListSet::perform_conncheck(
                            conncheck,
                            checklist.clone(),
                            self.checklists.iter().cloned().collect(),
                        )
                        .boxed(),
                    )
                    .await
                {
                    // receiver stopped -> no more timers
                    break;
                }
                processed = true;
                Delay::new(Duration::from_millis(20 /* FIXME */)).await;
            }
            if !processed {
                // exit condition is when no connchecks could be processed.
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::Credentials;
    use async_std::task;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    struct Counter(usize);

    #[test]
    fn task_list() {
        init();
        let tl = Arc::new(TaskList::new());
        async fn inc_sleep_start(tl: Arc<TaskList>, counter: Arc<Mutex<Counter>>) {
            let task_i = {
                let mut inner = counter.lock().unwrap();
                inner.0 += 1;
                inner.0 - 1
            };
            info!("executing task {}", task_i);
            task::sleep(Duration::from_millis(100)).await;
            tl.clone()
                .add_task(inc_sleep(tl, counter).map(|r| Ok(r)).boxed())
                .await
                .unwrap();
            info!("executed task {}", task_i);
        }
        async fn inc_sleep(tl: Arc<TaskList>, counter: Arc<Mutex<Counter>>) {
            let task_i = {
                let mut inner = counter.lock().unwrap();
                inner.0 += 1;
                inner.0 - 1
            };
            info!("executing task {}", task_i);
            task::sleep(Duration::from_millis(100)).await;
            tl.stop().await.unwrap();
            info!("executed task {}", task_i);
        }

        task::block_on(async move {
            let counter = Arc::new(Mutex::new(Counter(0)));

            tl.add_task(inc_sleep_start(tl.clone(), counter).map(|r| Ok(r)).boxed())
                .await
                .unwrap();
            tl.iterate_tasks().await.unwrap();
        });
    }

    #[test]
    fn connchecklistset() {
        init();
        let ragent = Agent::default();
        let rstream = ragent.add_stream();
        let _rcomponent = rstream.add_component().unwrap();

        let lagent = Agent::default();
        let lstream = lagent.add_stream();
        let _lcomponent = lstream.add_component().unwrap();

        let lcredentials = Credentials::new("l1user".to_owned(), "l1pass".to_owned());
        let rcredentials = Credentials::new("r1user".to_owned(), "r1pass".to_owned());
        lstream.set_local_credentials(lcredentials.clone());
        rstream.set_local_credentials(rcredentials.clone());
        lstream.set_remote_credentials(rcredentials.clone());
        rstream.set_remote_credentials(lcredentials.clone());

        task::block_on(async move {
            futures::try_join!(lstream.gather_candidates(), rstream.gather_candidates()).unwrap();

            for cand in lstream.get_local_candidates().into_iter() {
                rstream.add_remote_candidate(1, cand).unwrap();
            }
            for cand in rstream.get_local_candidates().into_iter() {
                lstream.add_remote_candidate(1, cand).unwrap();
            }

            let tasks = Arc::new(TaskList::new());

            let broadcast = Arc::new(ChannelBroadcast::default());
            let lstreams = vec![lstream];
            let lset = ConnCheckListSet::from_streams(lstreams, broadcast.clone(), tasks.clone());
            let rstreams = vec![rstream];
            let rset = ConnCheckListSet::from_streams(rstreams, broadcast.clone(), tasks.clone());

            let thandle = task::spawn({
                let tasks = tasks.clone();
                async move { tasks.iterate_tasks().await }
            });

            let (res1, res2) = futures::join!(
                lset.agent_conncheck_process(),
                rset.agent_conncheck_process()
            );
            res1.unwrap();
            res2.unwrap();
            tasks.stop().await.unwrap();
            thandle.await.unwrap();
        })
    }
}
