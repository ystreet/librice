// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An ICE Stream

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};
use std::time::Instant;

use async_std::net::TcpStream;
use futures::StreamExt;
use librice_proto::gathering::GatherPoll;
use librice_proto::stun::agent::{StunAgent, StunError, Transmit};
use librice_proto::stun::TransportType;

use crate::agent::{AgentError, AgentInner};
use crate::component::{Component, ComponentInner};
use crate::gathering::{iface_sockets, GatherSocket};
use crate::socket::{StunChannel, TcpChannel};

use librice_proto::candidate::{Candidate, CandidatePair};
//use crate::turn::agent::TurnCredentials;

pub use librice_proto::stream::Credentials;

/// An ICE [`Stream`]
#[derive(Debug, Clone)]
pub struct Stream {
    weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
    pub(crate) id: usize,
    weak_agent_inner: Weak<Mutex<AgentInner>>,
    transmit_send: async_std::channel::Sender<Transmit<'static>>,
    pub(crate) inner: Arc<Mutex<StreamInner>>,
}

#[derive(Debug, Default)]
pub(crate) struct StreamInner {
    sockets: Vec<StunChannel>,
    transmit_waker: Vec<Waker>,
    components: Vec<Option<Component>>,
    gather_waker: Option<Waker>,
}

impl StreamInner {
    fn socket_for_5tuple(
        &self,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Option<&StunChannel> {
        self.sockets.iter().find(|socket| match transport {
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
        })
    }

    fn component(&self, component_id: usize) -> Option<&Component> {
        self.components
            .get(component_id - 1)
            .and_then(|c| c.as_ref())
    }
}

/// A Future that completes the candidate gathering process.
#[derive(Debug)]
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct Gather {
    weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
    weak_agent_inner: Weak<Mutex<AgentInner>>,
    stream_id: usize,
    stream: Arc<Mutex<StreamInner>>,
    timer: Option<Pin<Box<async_io::Timer>>>,
    transmit_send: async_std::channel::Sender<Transmit<'static>>,
    pending_transmit_send: Option<Transmit<'static>>,
}

impl futures::stream::Stream for Gather {
    type Item = Candidate;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let now = Instant::now();
        let mut lowest_wait = None;
        let transmit_send = self.transmit_send.clone();
        if let Some(transmit) = self.pending_transmit_send.take() {
            // if we are still trying to send some data for this gather, ensure it is sent
            // before the next data is asked for.
            if let Err(async_std::channel::TrySendError::Full(transmit)) =
                transmit_send.try_send(transmit)
            {
                self.pending_transmit_send = Some(transmit);
                let mut stream = self.stream.lock().unwrap();
                stream.transmit_waker.push(cx.waker().clone());
                error!("gather pending cause transmit queue full");
                return Poll::Pending;
            }
        }
        let weak_stream = Arc::downgrade(&self.stream);
        let mut pending_transmit_send = None;
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return Poll::Ready(None);
        };
        let weak_proto_agent = Arc::downgrade(&proto_agent);
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(self.stream_id).unwrap();

        loop {
            match proto_stream.poll_gather(now) {
                Ok(GatherPoll::Complete) => {
                    proto_stream.end_of_local_candidates();
                    return Poll::Ready(None);
                }
                Ok(GatherPoll::NeedAgent(component_id, transport, local_addr, server_addr)) => {
                    error!("gather need agent {transport:?} {server_addr:?}");
                    if transport == TransportType::Tcp {
                        Stream::handle_gather_tcp_connect(
                            weak_stream.clone(),
                            weak_proto_agent.clone(),
                            self.weak_agent_inner.clone(),
                            self.stream_id,
                            component_id,
                            local_addr,
                            server_addr,
                            cx.waker().clone(),
                        );
                        continue;
                    }
                }
                Ok(GatherPoll::NewCandidate(cand)) => {
                    proto_stream.add_local_candidate(cand.clone());
                    return Poll::Ready(Some(cand));
                }
                Ok(GatherPoll::SendData(_component_id, transmit)) => {
                    if let Err(async_std::channel::TrySendError::Full(transmit)) =
                        transmit_send.try_send(transmit.into_owned())
                    {
                        pending_transmit_send = Some(transmit);
                        error!("gather pending cause transmit queue full (reply)");
                        break;
                    }
                }
                Ok(GatherPoll::WaitUntil(wait_time)) => {
                    match lowest_wait {
                        Some(wait) => {
                            if wait_time < wait {
                                lowest_wait = Some(wait_time);
                            }
                        }
                        None => lowest_wait = Some(wait_time),
                    }
                    error!("gather pending cause timeout");
                    break;
                }
                Err(e) => warn!("error produced while gathering: {e:?}"),
            }
        }
        self.stream.lock().unwrap().gather_waker = Some(cx.waker().clone());
        drop(proto_agent);

        if let Some(pending_transmit) = pending_transmit_send {
            self.pending_transmit_send = Some(pending_transmit);
            let mut stream = self.stream.lock().unwrap();
            stream.transmit_waker.push(cx.waker().clone());
            error!("gather pending cause transmit queue full (handling)");
            return Poll::Pending;
        }

        if let Some(lowest_wait) = lowest_wait {
            match self.as_mut().timer.as_mut() {
                Some(timer) => timer.set_at(lowest_wait),
                None => self.as_mut().timer = Some(Box::pin(async_io::Timer::at(lowest_wait))),
            }
            if core::future::Future::poll(self.as_mut().timer.as_mut().unwrap().as_mut(), cx)
                .is_pending()
            {
                error!("gather pending cause timeout pending");
                return Poll::Pending;
            }
            // timeout value passed, rerun our loop which will make more progress
            cx.waker().wake_by_ref();
        } else {
            error!("gather pending cause unknown");
        }
        Poll::Pending
    }
}

impl Stream {
    pub(crate) fn new(
        weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        id: usize,
    ) -> Self {
        let inner = Arc::new(Mutex::new(StreamInner::default()));
        let (transmit_send, mut transmit_recv) = async_std::channel::bounded::<Transmit>(16);
        let weak_inner = Arc::downgrade(&inner);
        async_std::task::spawn(async move {
            while let Some(transmit) = transmit_recv.next().await {
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let socket = {
                    let mut inner = inner.lock().unwrap();
                    while let Some(waker) = inner.transmit_waker.pop() {
                        waker.wake_by_ref();
                    }
                    inner
                        .socket_for_5tuple(transmit.transport, transmit.from, transmit.to)
                        .cloned()
                };
                if let Some(socket) = socket {
                    if let Err(e) = socket.send_to(&transmit.data, transmit.to).await {
                        warn!("failed to send: {e:?}");
                    }
                } else {
                    warn!(
                        "Could not find socket for transmit {} from {} to {}",
                        transmit.transport, transmit.from, transmit.to
                    );
                }
            }
        });
        Self {
            weak_proto_agent,
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
        let proto_agent = self
            .weak_proto_agent
            .upgrade()
            .ok_or(AgentError::ResourceNotFound)?;
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
        let index = proto_stream.add_component()? - 1;

        let mut inner = self.inner.lock().unwrap();
        while inner.components.len() <= index {
            inner.components.push(None);
        }
        let component = Component::new(self.weak_proto_agent.clone(), self.id, index + 1);
        inner.components[index] = Some(component.clone());
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
        inner
            .components
            .get(index - 1)
            .unwrap_or(&None)
            .as_ref()
            .cloned()
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
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials);
    /// ```
    pub fn set_local_credentials(&self, credentials: Credentials) {
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return;
        };
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
        proto_stream.set_local_credentials(credentials)
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
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials.clone());
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn local_credentials(&self) -> Option<Credentials> {
        let proto_agent = self.weak_proto_agent.upgrade()?;
        let proto_agent = proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(self.id)?;
        proto_stream.local_credentials()
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
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials);
    /// ```
    pub fn set_remote_credentials(&self, credentials: Credentials) {
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return;
        };
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
        proto_stream.set_remote_credentials(credentials)
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
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials.clone());
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn remote_credentials(&self) -> Option<Credentials> {
        let proto_agent = self.weak_proto_agent.upgrade()?;
        let proto_agent = proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(self.id)?;
        proto_stream.remote_credentials()
    }

    /// Add a remote candidate for connection checks for use with this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice_proto::candidate::*;
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
    /// stream.add_remote_candidate(candidate).unwrap();
    /// ```
    pub fn add_remote_candidate(&self, cand: Candidate) -> Result<(), AgentError> {
        let ret = {
            let proto_agent = self
                .weak_proto_agent
                .upgrade()
                .ok_or(AgentError::ResourceNotFound)?;
            let mut proto_agent = proto_agent.lock().unwrap();
            let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
            proto_stream.add_remote_candidate(cand)
        };

        if let Some(agent) = self.weak_agent_inner.upgrade() {
            let mut agent = agent.lock().unwrap();
            if let Some(waker) = agent.waker.take() {
                waker.wake();
            }
        }
        ret
    }

    #[tracing::instrument(
        name = "stream_handle_incoming_data",
        skip(weak_inner, weak_proto_agent, weak_agent_inner, weak_component, stream_id, component_id, transmit),
        fields(
            stream.id = stream_id,
            component.id = component_id,
        )
    )]
    fn handle_incoming_data(
        weak_inner: Weak<Mutex<StreamInner>>,
        weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        weak_component: Weak<Mutex<ComponentInner>>,
        stream_id: usize,
        component_id: usize,
        transmit: Transmit,
    ) {
        error!("librice::stream incoming data");
        let Some(proto_agent) = weak_proto_agent.upgrade() else {
            return;
        };
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(stream_id).unwrap();

        let reply = proto_stream.handle_incoming_data(component_id, transmit);

        let Some(component) = weak_component.upgrade() else {
            return;
        };
        let mut component = component.lock().unwrap();
        for data in reply.data {
            component.handle_incoming_data(data);
        }

        if reply.gather_handled {
            error!("gather handled");
            if let Some(stream) = weak_inner.upgrade() {
                let mut stream = stream.lock().unwrap();
                if let Some(waker) = stream.gather_waker.take() {
                    error!("gather handled woken");
                    waker.wake()
                }
            }
        }
        if reply.conncheck_handled {
            if let Some(agent) = weak_agent_inner.upgrade() {
                let mut agent = agent.lock().unwrap();
                if let Some(waker) = agent.waker.take() {
                    waker.wake();
                }
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
    /// let local_credentials = Credentials {ufrag: "luser".to_owned(), passwd: "lpass".to_owned()};
    /// stream.set_local_credentials(local_credentials);
    /// let remote_credentials = Credentials {ufrag: "ruser".to_owned(), passwd: "rpass".to_owned()};
    /// stream.set_remote_credentials(remote_credentials);
    /// let component = stream.add_component().unwrap();
    /// async_std::task::block_on(async move {
    ///     stream.gather_candidates().await.unwrap();
    /// });
    /// ```
    pub async fn gather_candidates(&self) -> Result<Gather, AgentError> {
        let proto_agent = self
            .weak_proto_agent
            .upgrade()
            .ok_or(AgentError::ResourceNotFound)?;
        let (stun_servers, component_ids) = {
            let proto_agent = proto_agent.lock().unwrap();
            let proto_stream = proto_agent.stream(self.id).unwrap();
            let component_ids = proto_stream.component_ids_iter().collect::<Vec<_>>();
            (proto_agent.stun_servers().clone(), component_ids)
        };
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
                .map(|s| (s.transport(), s.local_addr()))
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
                                    weak_inner.clone(),
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
                    GatherSocket::Tcp(tcp) => {
                        let weak_inner = weak_inner.clone();
                        async_std::task::spawn(async move {
                            while let Some(stream) = tcp.incoming().next().await {
                                let Ok(stream) = stream else {
                                    continue;
                                };
                                error!("incoming tcp connection");
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
                                            weak_inner.clone(),
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
                let mut proto_agent = proto_agent.lock().unwrap();
                let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
                let mut component = proto_stream.mut_component(component_id).unwrap();
                component.gather_candidates(proto_sockets, stun_servers.clone())?;
            }
        }

        let stream_id = self.id;
        let transmit_send = self.transmit_send.clone();
        Ok(Gather {
            weak_proto_agent: self.weak_proto_agent.clone(),
            weak_agent_inner: self.weak_agent_inner.clone(),
            stream_id,
            stream: self.inner.clone(),
            timer: None,
            transmit_send,
            pending_transmit_send: None,
        })
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
                            weak_state.clone(),
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
                             Self::handle_incoming_data(weak_state, weak_set, stream_id, checklist_id, component_id, transmit)
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

    /// Retrieve previously gathered local candidates
    pub fn local_candidates(&self) -> Vec<Candidate> {
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return vec![];
        };
        let proto_agent = proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(self.id).unwrap();
        proto_stream.local_candidates()
    }

    /// Retrieve previously set remote candidates for connection checks from this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice_proto::candidate::*;
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
    /// stream.add_remote_candidate(candidate.clone()).unwrap();
    /// let remote_cands = stream.remote_candidates();
    /// assert_eq!(remote_cands.len(), 1);
    /// assert_eq!(remote_cands[0], candidate);
    /// ```
    pub fn remote_candidates(&self) -> Vec<Candidate> {
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return vec![];
        };
        let proto_agent = proto_agent.lock().unwrap();
        let proto_stream = proto_agent.stream(self.id).unwrap();
        proto_stream.remote_candidates()
    }

    /// Indicate that no more candidates are expected from the peer.  This may allow the ICE
    /// process to complete.
    #[tracing::instrument(
        skip(self),
        fields(
            component.id = self.id,
        )
    )]
    pub fn end_of_remote_candidates(&self) {
        // FIXME: how to deal with ice restarts?
        let Some(proto_agent) = self.weak_proto_agent.upgrade() else {
            return;
        };
        let mut proto_agent = proto_agent.lock().unwrap();
        let mut proto_stream = proto_agent.mut_stream(self.id).unwrap();
        proto_stream.end_of_remote_candidates()
    }

    pub(crate) fn handle_transmit<'a>(
        &self,
        transmit: Transmit<'a>,
        waker: Waker,
    ) -> Option<Transmit<'a>> {
        if let Err(async_std::channel::TrySendError::Full(transmit)) =
            self.transmit_send.try_send(transmit.into_owned())
        {
            let mut inner = self.inner.lock().unwrap();
            inner.transmit_waker.push(waker);
            return Some(transmit);
        }
        None
    }

    pub(crate) fn handle_tcp_connect(
        weak_inner: Weak<Mutex<StreamInner>>,
        weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        stream_id: usize,
        component_id: usize,
        from: SocketAddr,
        to: SocketAddr,
        waker: Waker,
    ) {
        error!("making outbound tcp connection");
        async_std::task::spawn(async move {
            let stream = TcpStream::connect(to).await;
            error!("made outbound tcp connection");
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
                Err(e) => Err(StunError::IoError(e)),
            };
            let Some(proto_agent) = weak_proto_agent.upgrade() else {
                return;
            };

            let channel = {
                let mut proto_agent = proto_agent.lock().unwrap();
                let (agent, channel) = match channel {
                    Ok(channel) => {
                        let local_addr = channel.local_addr().unwrap();
                        let remote_addr = channel.remote_addr().unwrap();
                        (
                            Ok(StunAgent::builder(TransportType::Tcp, local_addr)
                                .remote_addr(remote_addr)
                                .build()),
                            Some(channel),
                        )
                    }
                    Err(e) => (Err(e), None),
                };

                let mut proto_stream = proto_agent.mut_stream(stream_id).unwrap();
                error!("handle_tcp_connect");
                proto_stream.handle_tcp_connect(component_id, from, to, agent);
                channel
            };

            waker.wake();

            if let Some(channel) = channel {
                let recv = channel.recv();
                let mut recv = core::pin::pin!(recv);
                let local_addr = channel.local_addr().unwrap();
                while let Some((data, from)) = recv.next().await {
                    Self::handle_incoming_data(
                        weak_inner.clone(),
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

    pub(crate) fn handle_gather_tcp_connect(
        weak_inner: Weak<Mutex<StreamInner>>,
        weak_proto_agent: Weak<Mutex<librice_proto::agent::Agent>>,
        weak_agent_inner: Weak<Mutex<AgentInner>>,
        stream_id: usize,
        component_id: usize,
        from: SocketAddr,
        to: SocketAddr,
        waker: Waker,
    ) {
        error!("making outbound tcp connection");
        async_std::task::spawn(async move {
            let stream = TcpStream::connect(to).await;
            error!("made outbound tcp connection");
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
                Err(e) => Err(StunError::IoError(e)),
            };
            let Some(proto_agent) = weak_proto_agent.upgrade() else {
                return;
            };

            let channel = {
                let mut proto_agent = proto_agent.lock().unwrap();
                let (agent, channel) = match channel {
                    Ok(channel) => {
                        let local_addr = channel.local_addr().unwrap();
                        let remote_addr = channel.remote_addr().unwrap();
                        (
                            Ok(StunAgent::builder(TransportType::Tcp, local_addr)
                                .remote_addr(remote_addr)
                                .build()),
                            Some(channel),
                        )
                    }
                    Err(e) => (Err(e), None),
                };

                let mut proto_stream = proto_agent.mut_stream(stream_id).unwrap();
                error!("handle_gather_tcp_connect");
                proto_stream.handle_gather_tcp_connect(component_id, from, to, agent);
                channel
            };
            if let Some(waker) = weak_inner
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .gather_waker
                .take()
            {
                waker.wake();
            }
            waker.wake();

            if let Some(channel) = channel {
                let recv = channel.recv();
                let mut recv = core::pin::pin!(recv);
                let local_addr = channel.local_addr().unwrap();
                error!("channel recv loop start");
                while let Some((data, from)) = recv.next().await {
                    Self::handle_incoming_data(
                        weak_inner.clone(),
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

    pub(crate) fn socket_for_pair(&self, pair: &CandidatePair) -> Option<StunChannel> {
        let inner = self.inner.lock().unwrap();
        inner
            .socket_for_5tuple(
                pair.local.transport_type,
                pair.local.base_address,
                pair.remote.address,
            )
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn gather_candidates() {
        init();
        let agent = Arc::new(Agent::default());
        let s = agent.add_stream();
        s.set_local_credentials(Credentials::new("luser".into(), "lpass".into()));
        s.set_remote_credentials(Credentials::new("ruser".into(), "rpass".into()));
        let _c = s.add_component().unwrap();
        async_std::task::block_on(async move {
            let mut gather = s.gather_candidates().await.unwrap();
            while let Some(_cand) = gather.next().await {}
            let local_cands = s.local_candidates();
            info!("gathered local candidates {:?}", local_cands);
            assert!(!local_cands.is_empty());
            assert!(matches!(
                s.gather_candidates().await,
                Err(AgentError::AlreadyInProgress)
            ));
        });
    }

    #[test]
    fn getters_setters() {
        init();
        let lcreds = Credentials::new("luser".into(), "lpass".into());
        let rcreds = Credentials::new("ruser".into(), "rpass".into());

        let agent = Agent::default();
        let stream = agent.add_stream();
        assert!(stream.component(0).is_none());
        assert!(stream.component(1).is_none());
        let comp = stream.add_component().unwrap();
        assert_eq!(comp.id(), stream.component(comp.id()).unwrap().id());

        stream.set_local_credentials(lcreds.clone());
        assert_eq!(stream.local_credentials().unwrap(), lcreds);
        stream.set_remote_credentials(rcreds.clone());
        assert_eq!(stream.remote_credentials().unwrap(), rcreds);
    }
}
