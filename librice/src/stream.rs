// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An ICE Stream

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use futures::StreamExt;
use rice_c::Address;
use rice_c::{Instant, prelude::*};
use tracing::{debug, info, trace, warn};

use crate::agent::{AgentError, AgentInner};
use crate::component::{Component, ComponentInner};
use crate::gathering::{GatherSocket, iface_sockets};
use crate::runtime::{AsyncTcpListenerExt, Runtime};
use crate::socket::{StunChannel, TcpChannel, Transmit};

use rice_c::agent::{AgentError as ProtoAgentError, AgentTransmit, SelectedTurn};
use rice_c::candidate::{Candidate, TransportType};
use rice_c::stream::GatheredCandidate;

pub use rice_c::stream::Credentials;

/// An ICE [`Stream`]
#[derive(Debug, Clone)]
pub struct Stream {
    pub(crate) state: Arc<StreamState>,
}

#[derive(Debug)]
pub(crate) struct StreamState {
    runtime: Arc<dyn Runtime>,
    proto_agent: rice_c::agent::Agent,
    proto_stream: rice_c::stream::Stream,
    base_instant: std::time::Instant,
    id: usize,
    weak_agent_inner: Weak<Mutex<AgentInner>>,
    transmit_send: futures::channel::mpsc::Sender<AgentTransmit>,
    inner: Mutex<StreamInner>,
}

#[derive(Debug, Default)]
pub(crate) struct StreamInner {
    sockets: Vec<StunChannel>,
    components: Vec<Component>,
}

impl StreamInner {
    fn socket_for_5tuple(
        &self,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Option<&StunChannel> {
        self.sockets
            .iter()
            .find(|socket| socket_matches(socket, transport, from, to))
    }

    fn remove_socket_for_5tuple(
        &mut self,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Option<StunChannel> {
        let position = self
            .sockets
            .iter()
            .position(|socket| socket_matches(socket, transport, from, to))?;
        Some(self.sockets.swap_remove(position))
    }

    fn component(&self, component_id: usize) -> Option<&Component> {
        self.components.get(component_id - 1)
    }
}

fn socket_matches(
    socket: &StunChannel,
    transport: TransportType,
    from: SocketAddr,
    to: SocketAddr,
) -> bool {
    match transport {
        TransportType::Udp => {
            if socket.transport() != transport {
                return false;
            }
            if from != socket.local_addr().unwrap() {
                return false;
            }
            true
        }
        TransportType::Tcp => {
            if socket.transport() != transport {
                return false;
            }
            if from != socket.local_addr().unwrap() {
                return false;
            }
            if to != socket.remote_addr().unwrap() {
                return false;
            }
            true
        }
    }
}

impl Stream {
    pub(crate) fn new(
        runtime: Arc<dyn Runtime>,
        proto_agent: rice_c::agent::Agent,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        proto_stream: rice_c::stream::Stream,
        id: usize,
        base_instant: std::time::Instant,
    ) -> Self {
        let inner = Mutex::new(StreamInner::default());
        let (transmit_send, mut transmit_recv) =
            futures::channel::mpsc::channel::<AgentTransmit>(16);
        let state = Arc::new(StreamState {
            runtime: runtime.clone(),
            proto_agent,
            proto_stream,
            id,
            weak_agent_inner,
            transmit_send,
            inner,
            base_instant,
        });
        let weak_state = Arc::downgrade(&state);
        runtime.spawn(Box::pin(async move {
            while let Some(transmit) = transmit_recv.next().await {
                let Some(state) = weak_state.upgrade() else {
                    break;
                };
                let from = transmit.from.as_socket();
                let to = transmit.to.as_socket();
                let socket = {
                    let inner = state.inner.lock().unwrap();
                    inner
                        .socket_for_5tuple(transmit.transport, from, to)
                        .cloned()
                };
                if let Some(mut socket) = socket {
                    if let Err(e) = socket.send_to(transmit.data, to).await {
                        warn!("failed to send: {e:?}");
                    }
                } else {
                    warn!(
                        "Could not find socket for transmit {} from {from} to {to}",
                        transmit.transport,
                    );
                }
            }
        }));
        Self { state }
    }

    /// The id of the [`Stream`]
    pub fn id(&self) -> usize {
        self.state.id
    }

    pub(crate) fn from_state(state: Arc<StreamState>) -> Self {
        Self { state }
    }

    /// The [`Agent`](crate::agent::Agent) that handles this [`Stream`].
    pub fn agent(&self) -> crate::agent::Agent {
        crate::agent::Agent::from_parts(
            self.state.proto_agent.clone(),
            self.state.base_instant,
            self.state.weak_agent_inner.upgrade().unwrap(),
            self.state.runtime.clone(),
        )
    }

    /// Add a `Component` to this stream.
    ///
    /// # Examples
    ///
    /// Add a `Component`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id(), component::RTP);
    /// ```
    pub fn add_component(&self) -> Result<Component, AgentError> {
        let component = self.state.proto_stream.add_component();

        let component = Component::new(
            self.state.id,
            component,
            self.state.base_instant,
            Arc::downgrade(&self.state),
        );
        let mut inner = self.state.inner.lock().unwrap();
        inner.components.push(component.clone());
        Ok(component)
    }

    /// Retrieve a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, `None` is returned
    ///
    /// # Examples
    ///
    /// Remove a `Component`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id(), component::RTP);
    /// assert!(stream.component(component::RTP).is_some());
    /// ```
    ///
    /// Retrieving a `Component` that doesn't exist will return `None`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// assert!(stream.component(component::RTP).is_none());
    /// ```
    pub fn component(&self, index: usize) -> Option<Component> {
        if index < 1 {
            return None;
        }
        let inner = self.state.inner.lock().unwrap();
        inner.components.get(index - 1).cloned()
    }

    /// Set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_local_credentials(&credentials);
    /// ```
    pub fn set_local_credentials(&self, credentials: &Credentials) {
        self.state.proto_stream.set_local_credentials(credentials)
    }

    /// Retreive the previouly set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_local_credentials(&credentials);
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn local_credentials(&self) -> Option<Credentials> {
        self.state.proto_stream.local_credentials()
    }

    /// Set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_remote_credentials(&credentials);
    /// ```
    pub fn set_remote_credentials(&self, credentials: &Credentials) {
        self.state.proto_stream.set_remote_credentials(credentials)
    }

    /// Retreive the previouly set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_remote_credentials(&credentials);
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn remote_credentials(&self) -> Option<Credentials> {
        self.state.proto_stream.remote_credentials()
    }

    /// Add a remote candidate for connection checks for use with this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::candidate::{Candidate, CandidateType, TransportType};
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// let addr = "127.0.0.1:9999".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     addr
    /// )
    /// .build();
    /// stream.add_remote_candidate(&candidate);
    /// ```
    pub fn add_remote_candidate(&self, cand: &Candidate) {
        self.state.proto_stream.add_remote_candidate(cand);

        if let Some(agent) = self.state.weak_agent_inner.upgrade() {
            let mut agent = agent.lock().unwrap();
            if let Some(waker) = agent.waker.take() {
                waker.wake();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        name = "stream_handle_incoming_data",
        skip(proto_agent, weak_agent_inner, weak_component, stream_id, component_id, transmit),
        fields(
            stream.id = stream_id,
            component.id = component_id,
        )
    )]
    fn handle_incoming_data<T: AsRef<[u8]> + std::fmt::Debug>(
        proto_agent: rice_c::agent::Agent,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        weak_component: Weak<Mutex<ComponentInner>>,
        stream_id: usize,
        component_id: usize,
        transmit: Transmit<T>,
        base_instant: std::time::Instant,
    ) {
        trace!(
            "incoming data of {} bytes from {} to {} via {}",
            transmit.data.as_ref().len(),
            transmit.from,
            transmit.to,
            transmit.transport
        );
        let proto_stream = proto_agent.stream(stream_id).unwrap();

        let reply = proto_stream.handle_incoming_data(
            component_id,
            transmit.transport,
            Address::from(transmit.from),
            Address::from(transmit.to),
            transmit.data.as_ref(),
            Instant::from_std(base_instant),
        );

        let Some(component) = weak_component.upgrade() else {
            return;
        };
        let mut component = component.lock().unwrap();
        if let Some(data) = reply.data {
            component.handle_incoming_data(data.to_vec().into());
        }
        if reply.have_more_data {
            while let Some(data) = proto_stream.poll_recv() {
                component.handle_incoming_data(data.data.into());
            }
        }
        drop(proto_agent);
        drop(component);

        if let Some(agent) = weak_agent_inner.upgrade() {
            let mut agent = agent.lock().unwrap();
            if let Some(waker) = agent.waker.take() {
                waker.wake();
            }
        }
    }

    /// Start gathering local candidates.  Credentials must have been set before this function can
    /// be called.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let local_credentials = Credentials::new("luser", "lpass");
    /// stream.set_local_credentials(&local_credentials);
    /// let remote_credentials = Credentials::new("ruser", "rpass");
    /// stream.set_remote_credentials(&remote_credentials);
    /// let component = stream.add_component().unwrap();
    /// # #[cfg(feature = "runtime-smol")]
    /// smol::block_on(async move {
    ///     stream.gather_candidates().await.unwrap();
    /// });
    /// # #[cfg(all(not(feature = "runtime-smol"), feature = "runtime-tokio"))]
    /// # runtime.block_on(async move {
    /// #     stream.gather_candidates().await.unwrap();
    /// # });
    /// ```
    pub async fn gather_candidates(&self) -> Result<(), AgentError> {
        let agent_inner = self
            .state
            .weak_agent_inner
            .upgrade()
            .ok_or(AgentError::Proto(ProtoAgentError::ResourceNotFound))?;
        let component_ids = self.state.proto_stream.component_ids();
        let weak_state = Arc::downgrade(&self.state);
        let base_instant = self.state.base_instant;
        let turn_configs = agent_inner.lock().unwrap().turn_servers.clone();

        for component_id in component_ids {
            let weak_component = Arc::downgrade(&self.component(component_id).unwrap().inner);
            let mut sockets = iface_sockets(self.state.runtime.clone())
                .await
                .unwrap()
                .into_iter()
                .filter_map(|s| s.ok())
                .collect::<Vec<_>>();
            let proto_stun_sockets = sockets
                .iter()
                .map(|s| (s.transport(), s.local_addr().into()))
                .collect::<Vec<_>>();

            let mut proto_turn_configs = vec![];
            for turn_config in turn_configs.iter() {
                let turn_sockets = iface_sockets(self.state.runtime.clone())
                    .await
                    .unwrap()
                    .into_iter()
                    .filter_map(|s| {
                        let turn_config = turn_config.clone();
                        s.ok().filter(|s| {
                            s.transport() == turn_config.client_transport()
                                && s.local_addr().is_ipv4()
                                    == turn_config.addr().as_socket().is_ipv4()
                        })
                    })
                    .collect::<Vec<_>>();
                for s in turn_sockets.iter() {
                    proto_turn_configs.push((s.local_addr().into(), turn_config.clone()));
                }
                sockets.extend(turn_sockets);
            }

            for socket in sockets {
                let weak_state = weak_state.clone();
                let weak_agent_inner = self.state.weak_agent_inner.clone();
                let proto_agent = self.state.proto_agent.clone();
                let weak_component = weak_component.clone();
                let local_addr = socket.local_addr();
                let transport = socket.transport();
                let stream_id = self.state.id;
                match socket {
                    GatherSocket::Udp(udp) => {
                        let mut inner = self.state.inner.lock().unwrap();
                        inner.sockets.push(StunChannel::Udp(udp.clone()));
                        self.state.runtime.spawn(Box::pin(async move {
                            let recv = udp.recv();
                            let mut recv = core::pin::pin!(recv);
                            while let Some((data, from)) = recv.next().await {
                                Self::handle_incoming_data(
                                    proto_agent.clone(),
                                    weak_agent_inner.clone(),
                                    weak_component.clone(),
                                    stream_id,
                                    component_id,
                                    Transmit::new(
                                        data.into_boxed_slice(),
                                        transport,
                                        from,
                                        local_addr,
                                    ),
                                    base_instant,
                                )
                            }
                            debug!("receive task closed for udp socket {:?}", udp.local_addr());
                        }));
                    }
                    GatherSocket::Tcp(tcp) => {
                        let weak_state = weak_state.clone();
                        let runtime = self.state.runtime.clone();
                        self.state.runtime.spawn(Box::pin(async move {
                            loop {
                                let Ok(stream) = tcp.accept().await else {
                                    continue;
                                };
                                let proto_agent = proto_agent.clone();
                                let weak_agent_inner = weak_agent_inner.clone();
                                let weak_component = weak_component.clone();
                                let weak_state = weak_state.clone();
                                let rt = runtime.clone();
                                runtime.spawn(Box::pin(async move {
                                    let Some(state) = weak_state.upgrade() else {
                                        return;
                                    };
                                    let mut channel = {
                                        let mut inner = state.inner.lock().unwrap();
                                        let channel = TcpChannel::new(rt, stream);
                                        inner.sockets.push(StunChannel::Tcp(channel.clone()));
                                        channel
                                    };

                                    let recv = channel.recv();
                                    let mut recv = core::pin::pin!(recv);
                                    while let Some((data, from)) = recv.next().await {
                                        Self::handle_incoming_data(
                                            proto_agent.clone(),
                                            weak_agent_inner.clone(),
                                            weak_component.clone(),
                                            stream_id,
                                            component_id,
                                            Transmit::new(
                                                data.into_boxed_slice(),
                                                transport,
                                                from,
                                                local_addr,
                                            ),
                                            base_instant,
                                        )
                                    }
                                }));
                            }
                        }));
                    }
                }
            }
            {
                let proto_stream = self.state.proto_agent.stream(self.state.id).unwrap();
                let component = proto_stream.component(component_id).unwrap();
                component.gather_candidates(
                    proto_stun_sockets
                        .iter()
                        .map(|(transport, addr)| (*transport, addr)),
                    proto_turn_configs
                        .iter()
                        .map(|(addr, config)| (addr, config.clone())),
                )?;
            }
        }
        Ok(())
    }
    /*
    pub async fn add_local_candidate(&self, candidate: &Candidate) -> Result<(), AgentError> {
        let weak_set = Arc::downgrade(&self.set);
        let weak_state = Arc::downgrade(&self.state);
        let weak_agent = self.agent.clone();
        let checklist_id = self.checklist_id;
        let component_id = candidate.component_id;
        match candidate.transport_type {
            TransportType::Udp => {
                let socket = UdpSocketChannel::new(UdpSocket::bind(candidate.base_address).await?);
                self.state
                    .lock()
                    .unwrap()
                    .sockets
                    .push(StunChannel::Udp(socket.clone()));
                let local_addr = socket.local_addr().unwrap();
                async_std::task::spawn(async move {
                    let recv = socket.recv();
                    let mut recv = core::pin::pin!(recv);
                    while let Some((data, from)) = recv.next().await {
                        Self::handle_incoming_data(
                            weak_set.clone(),
                            weak_agent.clone(),
                            stream_id,
                            checklist_id,
                            component_id,
                            Transmit {
                                data,
                                transport: TransportType::Udp,
                                from,
                                to: local_addr,
                            },
                        )
                    }
                });
            }
            TransportType::Tcp => {
                 match candidate.tcp_type {
                     Some(TcpType::Passive) => {
                         let stream = TcpListener::bind(candidate.base_address).await?;
                         async_std::task::spawn(async move {
                             while let Some(stream) =
                             Self::handle_incoming_data(weak_set, stream_id, checklist_id, component_id, transmit)
                         });
                     }
                     _ => return Err(AgentError::WrongImplementation);
                 }
            }
        }

        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(checklist_id).unwrap();
        checklist.add_local_candidate(candidate.clone(), false);

        Ok(())
    }*/
    /*
        /// Retrieve previously gathered local candidates
        pub fn local_candidates(&self) -> Vec<Candidate> {
            self.proto_stream.local_candidates()
        }

        /// Retrieve previously set remote candidates for connection checks from this stream
        ///
        /// # Examples
        ///
        /// ```
        /// # use librice::agent::Agent;
        /// # use librice::candidate::*;
        /// let agent = Agent::default();
        /// let stream = agent.add_stream();
        /// let component = stream.add_component().unwrap();
        /// let addr = "127.0.0.1:9999".parse().unwrap();
        /// let candidate = Candidate::builder(
        ///     0,
        ///     CandidateType::Host,
        ///     TransportType::Udp,
        ///     "0",
        ///     addr
        /// )
        /// .build();
        /// stream.add_remote_candidate(candidate.clone());
        /// let remote_cands = stream.remote_candidates();
        /// assert_eq!(remote_cands.len(), 1);
        /// assert_eq!(remote_cands[0], candidate);
        /// ```
        pub fn remote_candidates(&self) -> Vec<Candidate> {
            self.proto_stream.remote_candidates()
        }
    */
    /// Indicate that no more candidates are expected from the peer.  This may allow the ICE
    /// process to complete.
    #[tracing::instrument(
        skip(self),
        fields(
            component.id = self.state.id,
        )
    )]
    pub fn end_of_remote_candidates(&self) {
        self.state.proto_stream.end_of_remote_candidates()
    }

    pub(crate) fn handle_transmit(&self, transmit: AgentTransmit) -> Option<AgentTransmit> {
        if let Err(e) = self.state.transmit_send.clone().try_send(transmit) {
            if e.is_full() {
                return Some(e.into_inner());
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_allocate_socket(
        weak_state: Weak<StreamState>,
        proto_agent: rice_c::agent::Agent,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        stream_id: usize,
        component_id: usize,
        transport: TransportType,
        from: Address,
        to: Address,
        base_instant: std::time::Instant,
        runtime: Arc<dyn Runtime>,
    ) {
        if transport != TransportType::Tcp {
            unreachable!();
        }

        let rt = runtime.clone();
        runtime.spawn(Box::pin(async move {
            let stream = rt.tcp_connect(to.as_socket()).await;
            let mut weak_component = None;
            let channel = match stream {
                Ok(stream) => {
                    let Some(state) = weak_state.upgrade() else {
                        return;
                    };
                    let mut inner = state.inner.lock().unwrap();
                    let channel = StunChannel::Tcp(TcpChannel::new(rt.clone(), stream));
                    inner.sockets.push(channel.clone());
                    weak_component = Some(Arc::downgrade(
                        &inner.component(component_id).unwrap().inner,
                    ));
                    Ok(channel)
                }
                Err(_e) => Err(rice_c::agent::AgentError::ResourceNotFound),
            };

            let channel = {
                let (local_addr, channel) = match channel {
                    Ok(channel) => {
                        let local_addr = channel.local_addr().unwrap();
                        (Some(Address::from(local_addr)), Some(channel))
                    }
                    Err(_) => (None, None),
                };

                let proto_stream = proto_agent.stream(stream_id).unwrap();
                proto_stream.allocated_socket(
                    component_id,
                    transport,
                    &from,
                    &to,
                    local_addr,
                    Instant::from_std(base_instant),
                );
                channel
            };

            if let Some(agent) = weak_agent_inner.upgrade() {
                let mut agent = agent.lock().unwrap();
                if let Some(waker) = agent.waker.take() {
                    waker.wake();
                }
            }

            if let Some(mut channel) = channel {
                let local_addr = channel.local_addr().unwrap();
                let recv = channel.recv();
                let mut recv = core::pin::pin!(recv);
                while let Some((data, from)) = recv.next().await {
                    Self::handle_incoming_data(
                        proto_agent.clone(),
                        weak_agent_inner.clone(),
                        weak_component.clone().unwrap(),
                        stream_id,
                        component_id,
                        Transmit::new(
                            data.into_boxed_slice(),
                            TransportType::Tcp,
                            from,
                            local_addr,
                        ),
                        base_instant,
                    )
                }
            }
        }));
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_remove_socket(
        runtime: Arc<dyn Runtime>,
        weak_state: Weak<StreamState>,
        transport: TransportType,
        from: Address,
        to: Address,
    ) {
        let Some(state) = weak_state.upgrade() else {
            return;
        };

        let from = from.as_socket();
        let to = to.as_socket();
        let mut inner = state.inner.lock().unwrap();
        let Some(mut channel) = inner.remove_socket_for_5tuple(transport, from, to) else {
            warn!("no {transport} socket for {from} -> {to}");
            return;
        };
        info!("removing {transport} socket for {from} -> {to}");
        runtime.spawn(Box::pin(async move {
            if let Err(e) = channel.close().await {
                warn!("error on close() for {transport} socket for {from} -> {to}: {e:?}");
            }
        }));
    }

    pub(crate) fn socket_for_pair(
        &self,
        local: &Candidate,
        remote: &Candidate,
        local_turn: &Option<SelectedTurn>,
    ) -> Option<StunChannel> {
        let inner = self.state.inner.lock().unwrap();
        let (transport, local_addr, remote_addr) = if let Some(turn) = local_turn {
            (
                turn.transport,
                turn.local_addr.as_socket(),
                turn.remote_addr.as_socket(),
            )
        } else {
            (
                local.transport(),
                local.base_address().as_socket(),
                remote.address().as_socket(),
            )
        };
        inner
            .socket_for_5tuple(transport, local_addr, remote_addr)
            .cloned()
    }

    /// Add a local candidate for this stream.
    ///
    /// Returns whether the candidate was added internally.
    pub fn add_local_gathered_candidates(&self, gathered: GatheredCandidate) -> bool {
        self.state
            .proto_stream
            .add_local_gathered_candidate(gathered)
    }
}

#[cfg(test)]
mod tests {
    use tracing::error;

    use super::*;
    use crate::agent::{Agent, AgentMessage};

    fn init() {
        crate::tests::test_init_log();
    }

    #[cfg(feature = "runtime-smol")]
    #[test]
    fn smol_gather_candidates() {
        smol::block_on(gather_candidates());
    }

    #[cfg(feature = "runtime-tokio")]
    #[test]
    fn tokio_send_recv() {
        crate::tests::tokio_runtime().block_on(gather_candidates());
    }

    async fn gather_candidates() {
        init();
        let agent = Arc::new(Agent::default());
        let s = agent.add_stream();
        s.set_local_credentials(&Credentials::new("luser", "lpass"));
        s.set_remote_credentials(&Credentials::new("ruser", "rpass"));
        let _c = s.add_component().unwrap();

        s.gather_candidates().await.unwrap();
        let mut messages = agent.messages();
        loop {
            if matches!(
                messages.next().await,
                Some(AgentMessage::GatheringComplete(_))
            ) {
                break;
            }
        }
        //let local_cands = s.local_candidates();
        //info!("gathered local candidates {:?}", local_cands);
        //assert!(!local_cands.is_empty());
        let ret = s.gather_candidates().await;
        error!("ret: {ret:?}");
        assert!(matches!(
            ret,
            Err(AgentError::Proto(ProtoAgentError::AlreadyInProgress))
        ));
    }

    #[test]
    fn getters_setters() {
        #[cfg(feature = "runtime-tokio")]
        let _runtime = crate::tests::tokio_runtime().enter();
        init();
        let lcreds = Credentials::new("luser", "lpass");
        let rcreds = Credentials::new("ruser", "rpass");

        let agent = Agent::default();
        let stream = agent.add_stream();
        assert!(stream.component(0).is_none());
        assert!(stream.component(1).is_none());
        let comp = stream.add_component().unwrap();
        assert_eq!(comp.id(), stream.component(comp.id()).unwrap().id());

        stream.set_local_credentials(&lcreds);
        assert_eq!(stream.local_credentials().unwrap(), lcreds);
        stream.set_remote_credentials(&rcreds);
        assert_eq!(stream.remote_credentials().unwrap(), rcreds);
    }
}
