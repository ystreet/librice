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
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    tasks: Arc<TaskList>,
}

#[derive(Debug)]
pub(crate) struct AgentInner {
    id: usize,
    streams: Vec<Arc<Stream>>,
    checklistset: Option<Arc<ConnCheckListSet>>,
    controlling: bool,
    tie_breaker: u64,
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
}

pub(crate) type AgentFuture = Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send>>;

impl AgentInner {
    fn new(id: usize) -> Self {
        let mut rnd = rand::thread_rng();
        Self {
            id,
            streams: vec![],
            checklistset: None,
            controlling: false,
            tie_breaker: rnd.gen::<u64>(),
            stun_servers: vec![],
        }
    }
}

static AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

impl Default for Agent {
    fn default() -> Self {
        let id = AGENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Agent {
            id,
            inner: Arc::new(Mutex::new(AgentInner::new(id))),
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
            if inner.checklistset.is_some() {
                // already started?
                // TODO: ICE restart
                return Ok(());
            }
            let set = Arc::new(
                ConnCheckListSet::builder(
                    inner.streams.clone(),
                    self.broadcast.clone(),
                    self.tasks.clone(),
                    inner.controlling,
                )
                .build(),
            );
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
        let mut inner = self.inner.lock().unwrap();
        info!(
            "agent set controlling from {} to {}",
            inner.controlling, controlling
        );
        inner.controlling = controlling
    }

    pub fn controlling(&self) -> bool {
        self.inner.lock().unwrap().controlling
    }

    pub fn add_stun_server(&self, ttype: TransportType, addr: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        info!("Adding stun server {}", addr);
        inner.stun_servers.push((ttype, addr));
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
        assert_eq!(agent.controlling(), true);
        agent.set_controlling(false);
        assert_eq!(agent.controlling(), false);
    }
}
