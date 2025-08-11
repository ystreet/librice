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

use async_std::net::TcpStream;
use futures::StreamExt;
use rice_c::Address;

use crate::agent::{AgentError, AgentInner};
use crate::component::{Component, ComponentInner};
use crate::gathering::{iface_sockets, GatherSocket};
use crate::socket::{StunChannel, TcpChannel, Transmit};

use rice_c::agent::{AgentError as ProtoAgentError, AgentTransmit};
use rice_c::candidate::{Candidate, TransportType};
use rice_c::stream::GatheredCandidate;

pub use rice_c::stream::Credentials;

/// An ICE [`Stream`]
#[derive(Debug, Clone)]
pub struct Stream {
    weak_proto_agent: Weak<Mutex<rice_c::agent::Agent>>,
    proto_stream: rice_c::stream::Stream,
    pub(crate) id: usize,
    weak_agent_inner: Weak<Mutex<AgentInner>>,
    transmit_send: async_std::channel::Sender<AgentTransmit>,
    pub(crate) inner: Arc<Mutex<StreamInner>>,
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
        weak_proto_agent: Weak<Mutex<rice_c::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        proto_stream: rice_c::stream::Stream,
        id: usize,
    ) -> Self {
        let inner = Arc::new(Mutex::new(StreamInner::default()));
        let (transmit_send, mut transmit_recv) = async_std::channel::bounded::<AgentTransmit>(16);
        let weak_inner = Arc::downgrade(&inner);
        async_std::task::spawn(async move {
            while let Some(transmit) = transmit_recv.next().await {
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let from = transmit.from.as_socket();
                let to = transmit.to.as_socket();
                let socket = {
                    let inner = inner.lock().unwrap();
                    inner
                        .socket_for_5tuple(transmit.transport, from, to)
                        .cloned()
                };
                if let Some(socket) = socket {
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
        });
        Self {
            weak_proto_agent,
            proto_stream,
            id,
            weak_agent_inner,
            transmit_send,
            inner,
        }
    }

    /// The id of the [`Stream`]
    pub fn id(&self) -> usize {
        self.id
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
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id(), component::RTP);
    /// ```
    pub fn add_component(&self) -> Result<Component, AgentError> {
        let component = self.proto_stream.add_component();

        let component = Component::new(self.weak_proto_agent.clone(), self.id, component);
        let mut inner = self.inner.lock().unwrap();
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
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// assert!(stream.component(component::RTP).is_none());
    /// ```
    pub fn component(&self, index: usize) -> Option<Component> {
        if index < 1 {
            return None;
        }
        let inner = self.inner.lock().unwrap();
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
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_local_credentials(&credentials);
    /// ```
    pub fn set_local_credentials(&self, credentials: &Credentials) {
        self.proto_stream.set_local_credentials(credentials)
    }

    /// Retreive the previouly set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_local_credentials(&credentials);
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn local_credentials(&self) -> Option<Credentials> {
        self.proto_stream.local_credentials()
    }

    /// Set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_remote_credentials(&credentials);
    /// ```
    pub fn set_remote_credentials(&self, credentials: &Credentials) {
        self.proto_stream.set_remote_credentials(credentials)
    }

    /// Retreive the previouly set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_remote_credentials(&credentials);
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn remote_credentials(&self) -> Option<Credentials> {
        self.proto_stream.remote_credentials()
    }

    /// Add a remote candidate for connection checks for use with this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::candidate::{Candidate, CandidateType, TransportType};
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
        self.proto_stream.add_remote_candidate(cand);

        if let Some(agent) = self.weak_agent_inner.upgrade() {
            let mut agent = agent.lock().unwrap();
            if let Some(waker) = agent.waker.take() {
                waker.wake();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        name = "stream_handle_incoming_data",
        skip(weak_proto_agent, weak_agent_inner, weak_component, stream_id, component_id, transmit),
        fields(
            stream.id = stream_id,
            component.id = component_id,
        )
    )]
    fn handle_incoming_data<T: AsRef<[u8]> + std::fmt::Debug>(
        weak_proto_agent: Weak<Mutex<rice_c::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        weak_component: Weak<Mutex<ComponentInner>>,
        stream_id: usize,
        component_id: usize,
        transmit: Transmit<T>,
    ) {
        trace!(
            "incoming data of {} bytes from {} to {} via {}",
            transmit.data.as_ref().len(),
            transmit.from,
            transmit.to,
            transmit.transport
        );
        let Some(proto_agent) = weak_proto_agent.upgrade() else {
            return;
        };
        let proto_agent = proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(stream_id).unwrap();

        let reply = proto_stream.handle_incoming_data(
            component_id,
            transmit.transport,
            Address::from(transmit.from),
            Address::from(transmit.to),
            transmit.data.as_ref(),
            proto_agent.now(),
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
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let local_credentials = Credentials::new("luser", "lpass");
    /// stream.set_local_credentials(&local_credentials);
    /// let remote_credentials = Credentials::new("ruser", "rpass");
    /// stream.set_remote_credentials(&remote_credentials);
    /// let component = stream.add_component().unwrap();
    /// async_std::task::block_on(async move {
    ///     stream.gather_candidates().await.unwrap();
    /// });
    /// ```
    pub async fn gather_candidates(&self) -> Result<(), AgentError> {
        let proto_agent = self
            .weak_proto_agent
            .upgrade()
            .ok_or(AgentError::Proto(ProtoAgentError::ResourceNotFound))?;
        let component_ids = self.proto_stream.component_ids();
        let weak_inner = Arc::downgrade(&self.inner);

        for component_id in component_ids {
            let weak_component = Arc::downgrade(&self.component(component_id).unwrap().inner);
            let sockets = iface_sockets()
                .unwrap()
                .filter_map(|s| async move { s.ok() })
                .collect::<Vec<_>>()
                .await;
            let proto_sockets = sockets
                .iter()
                .map(|s| (s.transport(), s.local_addr().into()))
                .collect::<Vec<_>>();

            for socket in sockets {
                let weak_inner = weak_inner.clone();
                let weak_agent_inner = self.weak_agent_inner.clone();
                let weak_proto_agent = self.weak_proto_agent.clone();
                let weak_component = weak_component.clone();
                let local_addr = socket.local_addr();
                let transport = socket.transport();
                let stream_id = self.id;
                match socket {
                    GatherSocket::Udp(udp) => {
                        let mut inner = self.inner.lock().unwrap();
                        inner.sockets.push(StunChannel::Udp(udp.clone()));
                        async_std::task::spawn(async move {
                            let recv = udp.recv();
                            let mut recv = core::pin::pin!(recv);
                            while let Some((data, from)) = recv.next().await {
                                Self::handle_incoming_data(
                                    weak_proto_agent.clone(),
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
                                )
                            }
                            debug!("receive task closed for udp socket {:?}", udp.local_addr());
                        });
                    }
                    GatherSocket::Tcp(tcp) => {
                        let weak_inner = weak_inner.clone();
                        async_std::task::spawn(async move {
                            while let Some(stream) = tcp.incoming().next().await {
                                let Ok(stream) = stream else {
                                    continue;
                                };
                                let weak_proto_agent = weak_proto_agent.clone();
                                let weak_agent_inner = weak_agent_inner.clone();
                                let weak_component = weak_component.clone();
                                let weak_inner = weak_inner.clone();
                                async_std::task::spawn(async move {
                                    let Some(inner) = weak_inner.upgrade() else {
                                        return;
                                    };
                                    let channel = {
                                        let mut inner = inner.lock().unwrap();
                                        let channel = TcpChannel::new(stream);
                                        inner.sockets.push(StunChannel::Tcp(channel.clone()));
                                        channel
                                    };

                                    let recv = channel.recv();
                                    let mut recv = core::pin::pin!(recv);
                                    while let Some((data, from)) = recv.next().await {
                                        Self::handle_incoming_data(
                                            weak_proto_agent.clone(),
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
                                        )
                                    }
                                });
                            }
                        });
                    }
                }
            }
            {
                let proto_agent = proto_agent.lock().unwrap();
                let proto_stream = proto_agent.stream(self.id).unwrap();
                let component = proto_stream.component(component_id).unwrap();
                component.gather_candidates(proto_sockets)?;
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
            component.id = self.id,
        )
    )]
    pub fn end_of_remote_candidates(&self) {
        self.proto_stream.end_of_remote_candidates()
    }

    pub(crate) fn handle_transmit(&self, transmit: AgentTransmit) -> Option<AgentTransmit> {
        if let Err(async_std::channel::TrySendError::Full(transmit)) =
            self.transmit_send.try_send(transmit)
        {
            return Some(transmit);
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_allocate_socket(
        weak_inner: Weak<Mutex<StreamInner>>,
        weak_proto_agent: Weak<Mutex<rice_c::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        stream_id: usize,
        component_id: usize,
        transport: TransportType,
        from: Address,
        to: Address,
    ) {
        if transport != TransportType::Tcp {
            unreachable!();
        }

        async_std::task::spawn(async move {
            let stream = TcpStream::connect(to.as_socket()).await;
            let mut weak_component = None;
            let channel = match stream {
                Ok(stream) => {
                    let Some(inner) = weak_inner.upgrade() else {
                        return;
                    };
                    let mut inner = inner.lock().unwrap();
                    let channel = StunChannel::Tcp(TcpChannel::new(stream.clone()));
                    inner.sockets.push(channel.clone());
                    weak_component = Some(Arc::downgrade(
                        &inner.component(component_id).unwrap().inner,
                    ));
                    Ok(channel)
                }
                Err(_e) => Err(rice_c::agent::AgentError::ResourceNotFound),
            };
            let Some(proto_agent) = weak_proto_agent.upgrade() else {
                return;
            };

            let channel = {
                let proto_agent = proto_agent.lock().unwrap();
                let (local_addr, channel) = match channel {
                    Ok(channel) => {
                        let local_addr = channel.local_addr().unwrap();
                        (Some(Address::from(local_addr)), Some(channel))
                    }
                    Err(_) => (None, None),
                };

                let proto_stream = proto_agent.stream(stream_id).unwrap();
                proto_stream.allocated_socket(component_id, transport, &from, &to, local_addr);
                channel
            };

            if let Some(agent) = weak_agent_inner.upgrade() {
                let mut agent = agent.lock().unwrap();
                if let Some(waker) = agent.waker.take() {
                    waker.wake();
                }
            }

            if let Some(channel) = channel {
                let recv = channel.recv();
                let mut recv = core::pin::pin!(recv);
                let local_addr = channel.local_addr().unwrap();
                while let Some((data, from)) = recv.next().await {
                    Self::handle_incoming_data(
                        weak_proto_agent.clone(),
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
                    )
                }
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_remove_socket(
        weak_inner: Weak<Mutex<StreamInner>>,
        transport: TransportType,
        from: Address,
        to: Address,
    ) {
        let Some(inner) = weak_inner.upgrade() else {
            return;
        };

        let from = from.as_socket();
        let to = to.as_socket();
        let mut inner = inner.lock().unwrap();
        let Some(channel) = inner.remove_socket_for_5tuple(transport, from, to) else {
            warn!("no {transport} socket for {from} -> {to}");
            return;
        };
        info!("removing {transport} socket for {from} -> {to}");
        async_std::task::spawn(async move {
            if let Err(e) = channel.close().await {
                warn!("error on close() for {transport} socket for {from} -> {to}: {e:?}");
            }
        });
    }

    pub(crate) fn socket_for_pair(
        &self,
        local: &Candidate,
        remote: &Candidate,
    ) -> Option<StunChannel> {
        let inner = self.inner.lock().unwrap();
        inner
            .socket_for_5tuple(
                local.transport(),
                local.base_address().as_socket(),
                remote.address().as_socket(),
            )
            .cloned()
    }

    pub(crate) fn add_local_gathered_candidates(&self, gathered: GatheredCandidate) -> bool {
        self.proto_stream.add_local_gathered_candidate(gathered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentMessage};

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn gather_candidates() {
        init();
        let agent = Arc::new(Agent::default());
        let s = agent.add_stream();
        s.set_local_credentials(&Credentials::new("luser", "lpass"));
        s.set_remote_credentials(&Credentials::new("ruser", "rpass"));
        let _c = s.add_component().unwrap();
        async_std::task::block_on(async move {
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
        });
    }

    #[test]
    fn getters_setters() {
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
