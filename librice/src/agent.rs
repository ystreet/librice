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

use rice_c::agent::{AgentError as ProtoAgentError, AgentPoll, AgentTransmit};
use rice_c::component::ComponentConnectionState;
use rice_c::stream::GatheredCandidate;
use rice_c::Instant;
use tracing::warn;

use crate::component::{Component, SelectedPair};
use crate::stream::Stream;
use rice_c::candidate::{CandidatePair, TransportType};
pub use rice_c::turn::{TurnConfig, TurnCredentials};

/// Errors that can be returned as a result of agent operations.
#[derive(Debug)]
pub enum AgentError {
    /// An ICE protocol error.
    Proto(ProtoAgentError),
    /// An IO error.
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
        write!(f, "{self:?}")
    }
}

/// An ICE agent as specified in RFC 8445
#[derive(Debug)]
pub struct Agent {
    agent: Arc<Mutex<rice_c::agent::Agent>>,
    base_instant: std::time::Instant,
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
        let base_instant = std::time::Instant::now();

        let agent = Arc::new(Mutex::new(agent));
        Agent {
            agent,
            base_instant,
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
            self.base_instant,
        );
        inner.streams.push(ret.clone());
        ret
    }

    /// Retrieve a [`Stream`] by its ID from this [`Agent`].
    pub fn stream(&self, id: usize) -> Option<Stream> {
        let inner = self.inner.lock().unwrap();
        inner.streams.get(id).cloned()
    }

    /// Close the agent loop
    pub fn close(&self) {
        let now_nanos = Instant::from_std(self.base_instant);
        self.agent.lock().unwrap().close(now_nanos);
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
    pub fn add_turn_server(&self, config: TurnConfig) {
        self.inner.lock().unwrap().turn_servers.push(config);
        // TODO: propagate towards the gatherer as required
    }
}

#[derive(Debug, Default)]
pub(crate) struct AgentInner {
    pub(crate) waker: Option<Waker>,
    streams: Vec<Stream>,
    pub(crate) turn_servers: Vec<TurnConfig>,
}

/// Events that users might like to know
#[derive(Debug)]
pub enum AgentMessage {
    /// A [`Component`] has changed state.
    ComponentStateChange(Component, ComponentConnectionState),
    /// A [`Component`] has gathered a candidate.
    GatheredCandidate(Stream, GatheredCandidate),
    /// A [`Component`] has completed gathering.
    GatheringComplete(Component),
}

#[derive(Debug)]
struct AgentStream {
    agent: Arc<Mutex<rice_c::agent::Agent>>,
    base_instant: std::time::Instant,
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
        let now_nanos = Instant::from_std(self.base_instant);

        let wait = {
            let wait = match agent.poll(now_nanos) {
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
                            self.base_instant,
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
                AgentPoll::WaitUntilNanos(time) => Some(Instant::from_nanos(time)),
                AgentPoll::SelectedPair(ref pair) => {
                    drop(agent);
                    let inner = self.inner.lock().unwrap();
                    if let Some(stream) = inner.streams.get(pair.stream_id) {
                        if let Some(component) = stream.component(pair.component_id) {
                            if let Some(socket) =
                                stream.socket_for_pair(&pair.local, &pair.remote, &pair.turn)
                            {
                                if let Err(e) = component.set_selected_pair(SelectedPair::new(
                                    CandidatePair::new(
                                        pair.local.to_owned(),
                                        pair.remote.to_owned(),
                                    ),
                                    socket,
                                )) {
                                    warn!("Failed setting the selected pair: {e:?}");
                                }
                            } else {
                                warn!("Could not find existing socket for pair (local: {:?}, remote: {:?}, turn: {:?})", pair.local, pair.remote, pair.turn);
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
                        return Poll::Ready(Some(AgentMessage::GatheredCandidate(
                            stream.clone(),
                            rice_c::stream::GatheredCandidate::take(&mut gathered.gathered),
                        )));
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

            if let Some(transmit) = agent.poll_transmit(now_nanos) {
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
            let wait_instant = wait.to_std(self.base_instant);
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
