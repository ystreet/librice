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
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use async_std::task;

use rand::prelude::*;
use tracing_futures::Instrument;

use crate::candidate::parse::ParseCandidateError;
use crate::candidate::Candidate;
use crate::candidate::TransportType;
use crate::component::{Component, ComponentState};
use crate::conncheck::ConnCheckListSet;
use crate::stream::Stream;
use crate::stun::agent::StunError;
use crate::stun::attribute::StunParseError;
use crate::utils::ChannelBroadcast;

#[derive(Debug)]
pub enum AgentError {
    Failed,
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
    StunParse,
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

impl From<StunError> for AgentError {
    fn from(e: StunError) -> Self {
        match e {
            StunError::Failed => AgentError::Failed,
            StunError::WrongImplementation => AgentError::WrongImplementation,
            StunError::AlreadyExists => AgentError::AlreadyExists,
            StunError::ResourceNotFound => AgentError::ResourceNotFound,
            StunError::TimedOut => AgentError::TimedOut,
            StunError::IntegrityCheckFailed => AgentError::IntegrityCheckFailed,
            StunError::ParseError(_) => AgentError::StunParse,
            StunError::IoError(e) => AgentError::IoError(e),
            StunError::Aborted => AgentError::Aborted,
        }
    }
}

impl From<StunParseError> for AgentError {
    fn from(e: StunParseError) -> Self {
        let se: StunError = e.into();
        se.into()
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
}

#[derive(Debug, Default)]
pub struct AgentBuilder {
    trickle_ice: bool,
    controlling: bool,
}

impl AgentBuilder {
    pub fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
        self
    }

    pub fn controlling(mut self, controlling: bool) -> Self {
        self.controlling = controlling;
        self
    }

    pub fn build(self) -> Agent {
        let id = AGENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let broadcast = Arc::new(ChannelBroadcast::default());
        let mut rnd = rand::thread_rng();
        let tie_breaker = rnd.gen::<u64>();
        let controlling = self.controlling;
        Agent {
            id,
            inner: Arc::new(Mutex::new(AgentInner::new())),
            checklistset: Arc::new(
                ConnCheckListSet::builder(tie_breaker, controlling)
                    .trickle_ice(self.trickle_ice)
                    .build(),
            ),
            broadcast,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AgentInner {
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
    task: Option<task::JoinHandle<Result<(), AgentError>>>,
}

impl AgentInner {
    fn new() -> Self {
        Self {
            stun_servers: vec![],
            task: None,
        }
    }
}

static AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

impl Default for Agent {
    fn default() -> Self {
        Agent::builder().build()
    }
}

impl Agent {
    pub fn builder() -> AgentBuilder {
        AgentBuilder::default()
    }

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
        let mut inner = self.inner.lock().unwrap();
        if inner.task.is_some() {
            // already started?
            // TODO: ICE restart
            return Ok(());
        }
        inner.task = Some(async_std::task::spawn({
            let set = self.checklistset.clone();
            let span = debug_span!("ice_loop");
            async move { set.agent_conncheck_process().await }.instrument(span)
        }));
        Ok(())
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
        let mut inner = self.inner.lock().unwrap();
        let task = inner.task.take();
        task.map(|t| t.cancel());
        Ok(())
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
