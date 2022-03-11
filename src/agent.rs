// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error;
use std::fmt::Display;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use rand::prelude::*;

use crate::candidate::parse::ParseCandidateError;
use crate::candidate::Candidate;
use crate::candidate::TransportType;
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
    CandidateParse(ParseCandidateError),
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

impl From<ParseCandidateError> for AgentError {
    fn from(e: ParseCandidateError) -> Self {
        Self::CandidateParse(e)
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
    id: usize,
    inner: Arc<Mutex<AgentInner>>,
    checklistset: Arc<ConnCheckListSet>,
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    tasks: Arc<TaskList>,
}

#[derive(Debug)]
pub(crate) struct AgentInner {
    started: bool,
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
}

pub(crate) type AgentFuture = Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send>>;

impl AgentInner {
    fn new() -> Self {
        Self {
            started: false,
            stun_servers: vec![],
        }
    }
}

static AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

impl Default for Agent {
    fn default() -> Self {
        let id = AGENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let broadcast = Arc::new(ChannelBroadcast::default());
        let tasks = Arc::new(TaskList::new());
        let mut rnd = rand::thread_rng();
        let tie_breaker = rnd.gen::<u64>();
        let controlling = true;
        Agent {
            id,
            inner: Arc::new(Mutex::new(AgentInner::new())),
            checklistset: Arc::new(
                ConnCheckListSet::builder(
                    tasks.clone(),
                    tie_breaker,
                    controlling,
                )
                .build(),
            ),
            broadcast,
            tasks,
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
        let checklist = self.checklistset.new_list();
        let s = Arc::new(Stream::new(
            Arc::downgrade(&self.inner),
            self.broadcast.clone(),
            checklist,
        ));
        self.checklistset.add_stream(s.clone());
        s
    }

    /// Run the agent loop
    #[tracing::instrument(
        name = "ice_loop",
        err,
        skip(self),
        fields(
            ice_id = self.id
        )
    )]
    pub async fn run_loop(&self) -> Result<(), AgentError> {
        self.tasks.iterate_tasks().await
    }

    // XXX: TEMPORARY needs to become dynamic for trickle-ice
    #[tracing::instrument(
        name = "ice_start",
        err,
        skip(self),
        fields(
            ice_id = self.id
        )
    )]
    pub fn start(&self) -> Result<(), AgentError> {
        let set = {
            let mut inner = self.inner.lock().unwrap();
            if inner.started {
                // already started?
                // TODO: ICE restart
                return Ok(());
            }
            inner.started = true;
            self.checklistset.clone()
        };
        self.tasks
            .add_task_block(async move { set.agent_conncheck_process().await }.boxed())
    }

    pub fn message_channel(&self) -> impl futures::Stream<Item = AgentMessage> {
        self.broadcast.channel()
    }

    /// Close the agent loop
    #[tracing::instrument(
        name = "ice_close",
        skip(self),
        fields(
            ice_id = self.id
        )
    )]
    pub async fn close(&self) -> Result<(), AgentError> {
        info!("closing agent");
        self.tasks.stop().await
    }

    #[tracing::instrument(
        name = "ice_set_controlling",
        skip(self),
        fields(
            ice_id = self.id
        )
    )]
    pub fn set_controlling(&self, controlling: bool) {
        self.checklistset.set_controlling(controlling);
    }

    pub fn controlling(&self) -> bool {
        self.checklistset.controlling()
    }

    pub fn add_stun_server(&self, ttype: TransportType, addr: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        info!("Adding stun server {}", addr);
        inner.stun_servers.push((ttype, addr));
        // TODO: propagate towards the gatherer as required
    }

    #[cfg(test)]
    pub(crate) fn check_list_set(&self) -> Arc<ConnCheckListSet> {
        self.checklistset.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn controlling() {
        init();
        let agent = Agent::default();
        agent.set_controlling(true);
        assert!(agent.controlling());
        agent.set_controlling(false);
        assert!(!agent.controlling());
    }
}
