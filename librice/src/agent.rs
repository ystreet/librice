// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICE Agent implementation as specified in RFC 8445

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use rice_c::agent::{AgentError as ProtoAgentError, AgentPoll, AgentTransmit};
use rice_c::component::ComponentConnectionState;

use crate::component::{Component, SelectedPair};
use crate::stream::Stream;
pub use rice_c::agent::TurnCredentials;
use rice_c::candidate::{Candidate, CandidatePair, TransportType};

/// Errors that can be returned as a result of agent operations.
#[derive(Debug)]
pub enum AgentError {
    Proto(ProtoAgentError),
    IoError(std::io::Error),
}

impl From<ProtoAgentError> for AgentError {
    fn from(value: ProtoAgentError) -> Self {
        Self::Proto(value)
    }
}

impl From<std::io::Error> for AgentError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An ICE agent as specified in RFC 8445
#[derive(Debug)]
pub struct Agent {
    agent: Arc<Mutex<rice_c::agent::Agent>>,
    base_instant: Instant,
    base_micros: u64,
    inner: Arc<Mutex<AgentInner>>,
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
        let agent = rice_c::agent::Agent::builder()
            .trickle_ice(self.trickle_ice)
            .controlling(self.controlling)
            .build();
        let base_instant = Instant::now();
        let base_micros = agent.now();

        let agent = Arc::new(Mutex::new(agent));
        Agent {
            agent,
            base_instant,
            base_micros,
            inner: Arc::new(Mutex::new(AgentInner::default())),
        }
    }
}

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

    fn id(&self) -> u64 {
        self.agent.lock().unwrap().id()
    }

    /// A (futures) Stream for any application messages.  This is also the future that drives the
    /// ICE state machine and it must be driven until it completes.
    pub fn messages(&self) -> impl futures::Stream<Item = AgentMessage> {
        AgentStream {
            agent: self.agent.clone(),
            timer: None,
            base_micros: self.base_micros,
            base_instant: self.base_instant,
            pending_transmit: None,
            inner: self.inner.clone(),
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
    #[tracing::instrument(
        name = "ice_add_stream",
        skip(self),
        fields(
            ice.id = self.id()
        )
    )]
    pub fn add_stream(&self) -> Stream {
        let proto_stream = self.agent.lock().unwrap().add_stream();
        let weak_proto_agent = Arc::downgrade(&self.agent);
        let weak_inner = Arc::downgrade(&self.inner);
        let mut inner = self.inner.lock().unwrap();
        let ret = crate::stream::Stream::new(
            weak_proto_agent,
            weak_inner,
            proto_stream,
            inner.streams.len(),
        );
        inner.streams.push(ret.clone());
        ret
    }

    pub fn stream(&self, id: usize) -> Option<Stream> {
        let inner = self.inner.lock().unwrap();
        inner.streams.get(id).cloned()
    }

    /// Close the agent loop
    pub fn close(&self) {
        let now = Instant::now();
        let now_micros = (now - self.base_instant).as_micros() as u64 + self.base_micros;
        self.agent.lock().unwrap().close(now_micros);
        let mut inner = self.inner.lock().unwrap();
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
    }

    /// The controlling state of this ICE agent.  This value may change throughout the ICE
    /// negotiation process.
    pub fn controlling(&self) -> bool {
        self.agent.lock().unwrap().controlling()
    }

    /// Add a STUN server by address and transport to use for gathering potential candidates
    pub fn add_stun_server(&self, transport: TransportType, addr: SocketAddr) {
        self.agent
            .lock()
            .unwrap()
            .add_stun_server(transport, addr.into())
    }

    /// Add a TURN server by address and transport to use for gathering potential candidates
    pub fn add_turn_server(
        &self,
        transport: TransportType,
        addr: SocketAddr,
        credentials: TurnCredentials,
    ) {
        self.agent
            .lock()
            .unwrap()
            .add_turn_server(transport, addr.into(), credentials)
        // TODO: propagate towards the gatherer as required
    }
}

#[derive(Debug, Default)]
pub(crate) struct AgentInner {
    pub(crate) waker: Option<Waker>,
    streams: Vec<Stream>,
}

/// Events that users might like to know
pub enum AgentMessage {
    /// A [`Component`] has changed state.
    ComponentStateChange(Component, ComponentConnectionState),
    /// A [`Component`] has gathered a candidate.
    GatheredCandidate(Stream, Candidate),
    /// A [`Component`] has completed gathering.
    GatheringComplete(Component),
}

#[derive(Debug)]
struct AgentStream {
    agent: Arc<Mutex<rice_c::agent::Agent>>,
    base_instant: Instant,
    base_micros: u64,
    inner: Arc<Mutex<AgentInner>>,
    timer: Option<Pin<Box<async_io::Timer>>>,
    pending_transmit: Option<AgentTransmit>,
}

impl futures::stream::Stream for AgentStream {
    type Item = AgentMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(transmit) = self.pending_transmit.take() {
            let mut inner = self.inner.lock().unwrap();
            inner.waker = Some(cx.waker().clone());
            if let Some(stream) = inner.streams.get(transmit.stream_id) {
                if let Some(retry) = stream.handle_transmit(transmit) {
                    drop(inner);
                    self.as_mut().pending_transmit = Some(retry);
                    return Poll::Pending;
                }
            }
        } else {
            let mut inner = self.inner.lock().unwrap();
            inner.waker = Some(cx.waker().clone());
        }

        let weak_proto_agent = Arc::downgrade(&self.agent);
        let weak_agent_inner = Arc::downgrade(&self.inner);
        let agent = self.agent.lock().unwrap();
        let now = Instant::now();
        let now_micros = (now - self.base_instant).as_micros() as u64 + self.base_micros;

        let wait = {
            let wait = match agent.poll(now_micros) {
                AgentPoll::Closed => return Poll::Ready(None),
                AgentPoll::AllocateSocket(ref allocate) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(allocate.stream_id) {
                        let weak_stream = Arc::downgrade(&stream.inner);
                        drop(inner);
                        Stream::handle_allocate_socket(
                            weak_stream,
                            weak_proto_agent,
                            weak_agent_inner,
                            allocate.stream_id,
                            allocate.component_id,
                            allocate.transport,
                            allocate.from.clone(),
                            allocate.to.clone(),
                        );
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                AgentPoll::RemoveSocket(ref remove) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(remove.stream_id) {
                        let weak_stream = Arc::downgrade(&stream.inner);
                        drop(inner);
                        Stream::handle_remove_socket(
                            weak_stream,
                            remove.transport,
                            remove.from.clone(),
                            remove.to.clone(),
                        );
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                AgentPoll::WaitUntilMicros(time) => Some(time),
                AgentPoll::SelectedPair(ref pair) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(pair.stream_id) {
                        if let Some(component) = stream.component(pair.component_id) {
                            if let Some(socket) = stream.socket_for_pair(&pair.local, &pair.remote)
                            {
                                if let Err(e) = component.set_selected_pair(SelectedPair::new(
                                    CandidatePair::new(pair.local.clone(), pair.remote.clone()),
                                    socket,
                                )) {
                                    warn!("Failed setting the selected pair: {e:?}");
                                }
                            }
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                AgentPoll::ComponentStateChange(ref state) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(state.stream_id) {
                        if let Some(component) = stream.component(state.component_id) {
                            return Poll::Ready(Some(AgentMessage::ComponentStateChange(
                                component.clone(),
                                state.state,
                            )));
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                AgentPoll::GatheredCandidate(ref mut gathered) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(gathered.stream_id) {
                        let candidate = gathered.gathered.candidate();
                        if stream.add_local_gathered_candidates(gathered.gathered.take()) {
                            return Poll::Ready(Some(AgentMessage::GatheredCandidate(
                                stream.clone(),
                                candidate,
                            )));
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                AgentPoll::GatheringComplete(ref complete) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(complete.stream_id) {
                        if let Some(component) = stream.component(complete.component_id) {
                            return Poll::Ready(Some(AgentMessage::GatheringComplete(
                                component.clone(),
                            )));
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            };

            if let Some(transmit) = agent.poll_transmit(now_micros) {
                drop(agent);
                let inner = self.inner.lock().unwrap();
                if let Some(stream) = inner.streams.get(transmit.stream_id) {
                    if let Some(retry) = stream.handle_transmit(transmit) {
                        drop(inner);
                        self.as_mut().pending_transmit = Some(retry);
                        return Poll::Pending;
                    }
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            wait
        };
        drop(agent);

        if let Some(wait) = wait {
            let wait_instant = self.base_instant + Duration::from_micros(wait - self.base_micros);
            match self.as_mut().timer.as_mut() {
                Some(timer) => timer.set_at(wait_instant),
                None => self.as_mut().timer = Some(Box::pin(async_io::Timer::at(wait_instant))),
            }
            if core::future::Future::poll(self.as_mut().timer.as_mut().unwrap().as_mut(), cx)
                .is_pending()
            {
                return Poll::Pending;
            }
            // timeout value passed, rerun our loop which will make more progress
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
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
