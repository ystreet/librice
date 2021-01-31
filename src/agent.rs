// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error;
use std::fmt::Display;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use rand::prelude::*;

use crate::candidate::Candidate;
use crate::component::{Component, ComponentState};
use crate::conncheck::ConnCheckListSet;
use crate::stream::Stream;
use crate::tasks::TaskList;
use crate::utils::ChannelBroadcast;

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
    Aborted,
    TimedOut,
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
    controlling: bool,
    tie_breaker: u64,
}

pub(crate) type AgentFuture = Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send>>;

impl AgentInner {
    fn new() -> Self {
        let mut rnd = rand::thread_rng();
        error!("new agent");
        Self {
            streams: vec![],
            checklistset: None,
            controlling: false,
            tie_breaker: rnd.gen::<u64>(),
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
        let s = Arc::new(Stream::new(
            Arc::downgrade(&self.inner),
            self.broadcast.clone(),
        ));
        {
            let mut inner = self.inner.lock().unwrap();
            inner.streams.push(s.clone());
            // TODO: add stream to connchecklist
        }
        s
    }

    /// Run the agent loop
    pub async fn run_loop(&self) -> Result<(), AgentError> {
        self.tasks.iterate_tasks().await
    }

    // XXX: TEMPORARY needs to become dynamic for trickle-ice
    pub fn start(&self) -> Result<(), AgentError> {
        let set = {
            let mut inner = self.inner.lock().unwrap();
            if inner.checklistset.is_some() {
                // already started?
                // TODO: ICE restart
                return Ok(());
            }
            let set = Arc::new(ConnCheckListSet::from_streams(
                inner.streams.clone(),
                self.broadcast.clone(),
                self.tasks.clone(),
                inner.controlling,
            ));
            inner.checklistset = Some(set.clone());
            set
        };
        self.tasks
            .add_task_block(async move { set.agent_conncheck_process().await }.boxed())
    }

    pub fn message_channel(&self) -> impl futures::Stream<Item = AgentMessage> {
        self.broadcast.channel()
    }

    /// Close the agent loop
    pub async fn close(&self) -> Result<(), AgentError> {
        info!("closing agent");
        self.tasks.stop().await
    }

    pub fn set_controlling(&self, controlling: bool) {
        self.inner.lock().unwrap().controlling = controlling
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::Credentials;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn gather() {
        init();
        async_std::task::block_on(async move {
            let lagent = Arc::new(Agent::default());
            lagent.set_controlling(true);
            let ragent = Arc::new(Agent::default());

            let lcreds = Credentials::new("luser".into(), "lpass".into());
            let rcreds = Credentials::new("ruser".into(), "rpass".into());

            let mut l_msg_s = lagent.message_channel();
            let lstream = lagent.add_stream();
            lstream.set_local_credentials(lcreds.clone());
            lstream.set_remote_credentials(rcreds.clone());
            let lcomp = lstream.add_component().unwrap();

            let mut r_msg_s = ragent.message_channel();
            let rstream = ragent.add_stream();
            rstream.set_local_credentials(rcreds);
            rstream.set_remote_credentials(lcreds);
            let rcomp = rstream.add_component().unwrap();

            async_std::task::spawn({
                let agent = lagent.clone();
                async move {
                    agent.run_loop().await.unwrap();
                }
            });
            async_std::task::spawn({
                let agent = ragent.clone();
                async move {
                    agent.run_loop().await.unwrap();
                }
            });

            // poor-man's async semaphore
            let (lgatherdone_send, lgatherdone_recv) = async_channel::bounded::<i32>(1);
            let lgather = async_std::task::spawn({
                let rstream = rstream.clone();
                async move {
                    while let Some(msg) = l_msg_s.next().await {
                        match msg {
                            AgentMessage::NewLocalCandidate(comp, cand) => {
                                rstream.add_remote_candidate(comp.id, cand).unwrap()
                            }
                            AgentMessage::GatheringCompleted(_comp) => {
                                lgatherdone_send.send(0).await.unwrap()
                            }
                            AgentMessage::ComponentStateChange(_comp, state) => {
                                if state == ComponentState::Connected
                                    || state == ComponentState::Failed
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            let (rgatherdone_send, rgatherdone_recv) = async_channel::bounded::<i32>(1);
            let rgather = async_std::task::spawn({
                let lstream = lstream.clone();
                async move {
                    while let Some(msg) = r_msg_s.next().await {
                        match msg {
                            AgentMessage::NewLocalCandidate(comp, cand) => {
                                lstream.add_remote_candidate(comp.id, cand).unwrap()
                            }
                            AgentMessage::GatheringCompleted(_comp) => {
                                rgatherdone_send.send(0).await.unwrap()
                            }
                            AgentMessage::ComponentStateChange(_comp, state) => {
                                if state == ComponentState::Connected
                                    || state == ComponentState::Failed
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            futures::try_join!(lstream.gather_candidates(), rstream.gather_candidates()).unwrap();

            futures::try_join!(lgatherdone_recv.recv(), rgatherdone_recv.recv()).unwrap();

            lagent.start().unwrap();
            ragent.start().unwrap();

            futures::join!(lgather, rgather);
            error!("gather done");

            let rcomp_recv_stream = rcomp.receive_stream();
            let data = vec![5;8];
            lcomp.send(&data).await.unwrap();
            futures::pin_mut!(rcomp_recv_stream);
            let received = rcomp_recv_stream.next().await.unwrap();
            assert_eq!(data, received);

            let lcomp_recv_stream = lcomp.receive_stream();
            let data = vec![3;8];
            rcomp.send(&data).await.unwrap();
            futures::pin_mut!(lcomp_recv_stream);
            let received = lcomp_recv_stream.next().await.unwrap();
            assert_eq!(data, received);

            futures::try_join!(lagent.close(), ragent.close()).unwrap();
            error!("closed");
        });
    }
}
