// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICE Agent implementation as specified in RFC 8445

use std::error::Error;
use std::fmt::Display;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use rand::prelude::*;

use crate::component::{Component, ComponentState, SelectedPair};
use crate::stream::Stream;
use librice_proto::candidate::{ParseCandidateError, TransportType};
use librice_proto::conncheck::{CheckListSetPollRet, ConnCheckEvent, ConnCheckListSet};
use librice_proto::stun::agent::{StunError, Transmit};
use librice_proto::stun::attribute::StunParseError;
//use crate::turn::agent::TurnCredentials;

/// Errors that can be returned as a result of agent operations.
#[derive(Debug)]
pub enum AgentError {
    Failed,
    /// The specified resource already exists and cannot be added.
    AlreadyExists,
    /// The operation is already in progress.
    AlreadyInProgress,
    /// The operation is not in progress.
    NotInProgress,
    /// Could not find the specified resource.
    ResourceNotFound,
    /// Too little data provided.
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
    /// Parsing the candidate failed.
    CandidateParse(ParseCandidateError),
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// Data was received that does not match the protocol specifications.
    ProtocolViolation,
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
            StunError::ProtocolViolation => AgentError::ProtocolViolation,
            StunError::ParseError(_) => AgentError::StunParse,
            StunError::IoError(e) => AgentError::IoError(e),
            StunError::Aborted => AgentError::Aborted,
            StunError::AlreadyInProgress => AgentError::AlreadyInProgress,
        }
    }
}

impl From<StunParseError> for AgentError {
    fn from(e: StunParseError) -> Self {
        e.into()
    }
}

/// Events that the application may like to know about.
#[derive(Debug, Clone)]
pub enum AgentMessage {
    /// A [`Component`] has changed its state
    ComponentStateChange(Component, ComponentState),
}

/// An ICE agent as specified in RFC 8445
#[derive(Debug)]
pub struct Agent {
    id: usize,
    inner: Arc<Mutex<AgentInner>>,
    checklistset: Arc<Mutex<ConnCheckListSet>>,
}

/// A builder for an [`Agent`]
#[derive(Debug, Default)]
pub struct AgentBuilder {
    trickle_ice: bool,
    controlling: bool,
}

impl AgentBuilder {
    /// Whether candidates can trickle in during ICE negotiation
    pub fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
        self
    }

    /// The initial value of the controlling attribute.  During the ICE negotiation, the
    /// controlling value may change.
    pub fn controlling(mut self, controlling: bool) -> Self {
        self.controlling = controlling;
        self
    }

    /// Construct a new [`Agent`]
    pub fn build(self) -> Agent {
        let id = AGENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut rnd = rand::thread_rng();
        let tie_breaker = rnd.gen::<u64>();
        let controlling = self.controlling;
        Agent {
            id,
            inner: Arc::new(Mutex::new(AgentInner::new())),
            checklistset: Arc::new(Mutex::new(
                ConnCheckListSet::builder(tie_breaker, controlling)
                    .trickle_ice(self.trickle_ice)
                    .build(),
            )),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AgentInner {
    closed: bool,
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
    //pub(crate) turn_servers: Vec<(TransportType, SocketAddr, TurnCredentials)>,
    streams: Vec<Stream>,
    pub(crate) waker: Option<Waker>,
}

impl AgentInner {
    fn new() -> Self {
        Self {
            closed: false,
            stun_servers: vec![],
            //turn_servers: vec![],
            streams: vec![],
            waker: None,
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
    /// Create a new [`AgentBuilder`]
    pub fn builder() -> AgentBuilder {
        AgentBuilder::default()
    }

    /// A (futures) Stream for any application messages.  This is also the future that drives the
    /// ICE state machine and it must be driven until it completes.
    pub fn messages(&self) -> impl futures::Stream<Item = AgentMessage> {
        AgentStream {
            set: self.checklistset.clone(),
            agent: self.inner.clone(),
            timer: None,
            pending_transmit: None,
        }
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
    pub fn add_stream(&self) -> Stream {
        let mut set = self.checklistset.lock().unwrap();
        let checklist_id = set.new_list();
        let stream = Stream::new(
            Arc::downgrade(&self.inner),
            self.checklistset.clone(),
            checklist_id,
        );
        drop(set);
        let mut inner = self.inner.lock().unwrap();
        inner.streams.push(stream.clone());
        stream
    }

    /// Close the agent loop
    #[tracing::instrument(
        name = "ice_close",
        skip(self),
        fields(
            ice_id = self.id
        )
    )]
    pub fn close(&self) -> Result<(), AgentError> {
        info!("closing agent");
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
        // TODO: TURN close things
        Ok(())
    }

    /// The controlling state of this ICE agent.  This value may change throughout the ICE
    /// negotiation process.
    pub fn controlling(&self) -> bool {
        self.checklistset.lock().unwrap().controlling()
    }

    /// Add a STUN server by address and transport to use for gathering potential candidates
    pub fn add_stun_server(&self, ttype: TransportType, addr: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        info!("Adding stun server {addr} transport {ttype:?}");
        inner.stun_servers.push((ttype, addr));
        // TODO: propagate towards the gatherer as required
    }
    /*
    pub fn add_turn_server(&self, ttype: TransportType, addr: SocketAddr, credentials: TurnCredentials) {
        let mut inner = self.inner.lock().unwrap();
        info!("Adding stun server {addr} transport {ttype:?}");
        inner.turn_servers.push((ttype, addr, credentials));
        */
    // TODO: propagate towards the gatherer as required
    //    }
}

#[derive(Debug)]
struct AgentStream {
    set: Arc<Mutex<ConnCheckListSet>>,
    agent: Arc<Mutex<AgentInner>>,
    timer: Option<Pin<Box<async_io::Timer>>>,
    pending_transmit: Option<(usize, Transmit)>,
}

impl futures::stream::Stream for AgentStream {
    type Item = AgentMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some((checklist_id, transmit)) = self.pending_transmit.take() {
            let mut agent = self.agent.lock().unwrap();
            if let Some(stream) = agent
                .streams
                .iter()
                .find(|s| s.checklist_id == checklist_id)
            {
                if let Some(transmit) = stream.handle_transmit(transmit, cx.waker().clone()) {
                    agent.waker = Some(cx.waker().clone());
                    drop(agent);
                    self.as_mut().pending_transmit = Some((checklist_id, transmit));
                    return Poll::Pending;
                }
            }
        }
        let now = Instant::now();

        {
            let agent = self.agent.lock().unwrap();
            if agent.closed {
                // TODO: wait for some sockets to be closed
                return Poll::Ready(None);
            }
        }

        let mut set = self.set.lock().unwrap();
        let wait = match set.poll(now) {
            CheckListSetPollRet::Completed => {
                let mut agent = self.agent.lock().unwrap();
                agent.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            CheckListSetPollRet::WaitUntil(earliest_wait) => {
                drop(set);
                Some(earliest_wait)
            }
            CheckListSetPollRet::Transmit(checklist_id, _cid, transmit) => {
                drop(set);
                let mut agent = self.agent.lock().unwrap();
                if let Some(stream) = agent
                    .streams
                    .iter()
                    .find(|s| s.checklist_id == checklist_id)
                {
                    if let Some(transmit) = stream.handle_transmit(transmit, cx.waker().clone()) {
                        agent.waker = Some(cx.waker().clone());
                        drop(agent);
                        self.as_mut().pending_transmit = Some((checklist_id, transmit));
                        return Poll::Pending;
                    }
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            CheckListSetPollRet::TcpConnect(checklist_id, cid, from, to) => {
                drop(set);
                let agent = self.agent.lock().unwrap();
                if let Some(stream) = agent
                    .streams
                    .iter()
                    .find(|s| s.checklist_id == checklist_id)
                {
                    stream.handle_tcp_connect(cid, from, to, cx.waker().clone());
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            CheckListSetPollRet::Event(checklist_id, ConnCheckEvent::ComponentState(cid, state)) => {
                drop(set);
                let agent = self.agent.lock().unwrap();
                if let Some(stream) = agent
                    .streams
                    .iter()
                    .find(|s| s.checklist_id == checklist_id)
                {
                    if let Some(component) = stream.component(cid) {
                        return Poll::Ready(Some(AgentMessage::ComponentStateChange(
                            component, state,
                        )));
                    }
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            CheckListSetPollRet::Event(checklist_id, ConnCheckEvent::SelectedPair(cid, pair)) => {
                drop(set);
                let agent = self.agent.lock().unwrap();
                if let Some(stream) = agent
                    .streams
                    .iter()
                    .find(|s| s.checklist_id == checklist_id)
                {
                    if let Some(component) = stream.component(cid) {
                        if let Some(socket) = stream.socket_for_pair(pair.candidate_pair()) {
                            component.set_selected_pair(SelectedPair::new(*pair, socket));
                        }
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if let Some(wait) = wait {
            match self.as_mut().timer.as_mut() {
                Some(timer) => timer.set_at(wait),
                None => self.as_mut().timer = Some(Box::pin(async_io::Timer::at(wait))),
            }
            if core::future::Future::poll(self.as_mut().timer.as_mut().unwrap().as_mut(), cx)
                .is_pending()
            {
                let mut agent = self.agent.lock().unwrap();
                agent.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            // timeout value passed, rerun our loop which will make more progress
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut agent = self.agent.lock().unwrap();
        agent.waker = Some(cx.waker().clone());
        Poll::Pending
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
        let agent = Agent::builder().controlling(true).build();
        assert!(agent.controlling());
        let agent = Agent::builder().controlling(false).build();
        assert!(!agent.controlling());
    }
}
