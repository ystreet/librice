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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};
use std::time::Instant;

use async_std::net::TcpStream;
use futures::StreamExt;
use librice_proto::gathering::{GatherRet, StunGatherer};
use librice_proto::stun::agent::{HandleStunReply, StunAgent, StunError, Transmit};
use librice_proto::stun::TransportType;

use crate::agent::{AgentError, AgentInner};
use crate::component::Component;
use crate::gathering::{iface_sockets, GatherSocket};
use crate::socket::{StunChannel, TcpChannel};
use librice_proto::conncheck::*;

use librice_proto::candidate::{Candidate, CandidatePair};
//use crate::turn::agent::TurnCredentials;

pub use librice_proto::conncheck::Credentials;

static STREAM_COUNT: AtomicUsize = AtomicUsize::new(0);

/// An ICE [`Stream`]
#[derive(Debug, Clone)]
pub struct Stream {
    id: usize,
    pub(crate) state: Arc<Mutex<StreamState>>,
    set: Arc<Mutex<ConnCheckListSet>>,
    pub(crate) checklist_id: usize,
    agent: Weak<Mutex<AgentInner>>,
    transmit_send: async_std::channel::Sender<Transmit>,
}

#[derive(Debug, Default)]
pub(crate) struct StreamState {
    components: Vec<Option<Component>>,
    local_credentials: Option<Credentials>,
    remote_credentials: Option<Credentials>,
    gather_state: GatherProgress,
    gatherers: Vec<Gatherer>,
    sockets: Vec<StunChannel>,
    transmit_waker: Vec<Waker>,
}

impl StreamState {
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
}

#[derive(Debug, Default, PartialEq, Eq)]
enum GatherProgress {
    #[default]
    New,
    InProgress,
    Completed,
}

#[derive(Debug)]
struct Gatherer {
    gatherer: StunGatherer,
}

/// A Future that completes the candidate gathering process.
#[derive(Debug)]
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct Gather {
    stream: Arc<Mutex<StreamState>>,
    timer: Option<Pin<Box<async_io::Timer>>>,
    weak_set: Weak<Mutex<ConnCheckListSet>>,
    checklist_id: usize,
    transmit_send: async_std::channel::Sender<Transmit>,
    pending_transmit_send: Option<Transmit>,
}

impl futures::stream::Stream for Gather {
    type Item = Candidate;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let now = Instant::now();
        let mut all_complete = true;
        let mut lowest_wait = None;
        let Some(set) = self.weak_set.clone().upgrade() else {
            return Poll::Ready(None);
        };
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
                return Poll::Pending;
            }
        }
        let weak_stream = Arc::downgrade(&self.stream);
        let mut stream = self.stream.lock().unwrap();
        stream.transmit_waker.push(cx.waker().clone());
        let mut pending_transmit_send = None;
        for gather in stream.gatherers.iter_mut() {
            match gather.gatherer.poll(now) {
                Ok(GatherRet::Complete) => (),
                Ok(GatherRet::NeedAgent(transport, _local_addr, server_addr)) => {
                    if transport == TransportType::Tcp {
                        let waker = cx.waker().clone();
                        let cid = gather.gatherer.component_id();
                        let weak_stream = weak_stream.clone();
                        async_std::task::spawn(async move {
                            let tcp_stream = TcpStream::connect(server_addr).await;
                            let channel = tcp_stream.as_ref().ok().map(|tcp_stream|
                                StunChannel::Tcp(TcpChannel::new(tcp_stream.clone())));
                            let agent = tcp_stream
                                .map(|tcp_stream| {
                                    StunAgent::builder(transport, tcp_stream.local_addr().unwrap())
                                        .remote_addr(server_addr)
                                        .build()
                                })
                                .map_err(librice_proto::stun::agent::StunError::IoError);
                            let Some(stream) = weak_stream.upgrade() else {
                                return;
                            };
                            let mut stream = stream.lock().unwrap();
                            let Some(gather) = stream
                                .gatherers
                                .iter_mut()
                                .find(|gather| gather.gatherer.component_id() == cid)
                            else {
                                return;
                            };
                            gather.gatherer.add_agent(transport, server_addr, agent);
                            if let Some(channel) = channel {
                                stream.sockets.push(channel);
                            }
                            waker.wake_by_ref();
                        });
                    }
                }
                Ok(GatherRet::NewCandidate(cand)) => {
                    drop(stream);
                    let mut set = set.lock().unwrap();
                    let checklist = set.list_mut(self.checklist_id).unwrap();
                    //let socket = self.socket_for_addr(cand.transport_type, cand.base_address).unwrap().clone();
                    checklist.add_local_candidate(cand.clone(), false);
                    return Poll::Ready(Some(cand));
                }
                Ok(GatherRet::SendData(transmit)) => {
                    all_complete = false;
                    if let Err(async_std::channel::TrySendError::Full(transmit)) =
                        transmit_send.try_send(transmit)
                    {
                        pending_transmit_send = Some(transmit);
                        all_complete = false;
                        break;
                    }
                }
                Ok(GatherRet::WaitUntil(wait_time)) => {
                    all_complete = false;
                    match lowest_wait {
                        Some(wait) => {
                            if wait_time < wait {
                                lowest_wait = Some(wait_time);
                            }
                        }
                        None => lowest_wait = Some(wait_time),
                    }
                }
                Err(e) => warn!("error produced while gathering: {e:?}"),
            }
        }

        if all_complete {
            stream.gather_state = GatherProgress::Completed;
            drop(stream);
            if let Some(set) = self.weak_set.upgrade() {
                let mut set = set.lock().unwrap();
                let checklist = set.list_mut(self.checklist_id).unwrap();
                checklist.end_of_local_candidates();
            }
            return Poll::Ready(None);
        } else {
            drop(stream);
        }

        if let Some(pending_transmit) = pending_transmit_send {
            self.pending_transmit_send = Some(pending_transmit);
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
                return Poll::Pending;
            }
            // timeout value passed, rerun our loop which will make more progress
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Stream {
    pub(crate) fn new(
        agent: Weak<Mutex<AgentInner>>,
        set: Arc<Mutex<ConnCheckListSet>>,
        checklist_id: usize,
    ) -> Self {
        let id = STREAM_COUNT.fetch_add(1, Ordering::SeqCst);
        let state = Arc::new(Mutex::new(StreamState::default()));
        let (transmit_send, mut transmit_recv) = async_std::channel::bounded::<Transmit>(16);
        let weak_state = Arc::downgrade(&state);
        async_std::task::spawn(async move {
            while let Some(transmit) = transmit_recv.next().await {
                let Some(stream) = weak_state.upgrade() else {
                    break;
                };
                let socket = {
                    let mut stream = stream.lock().unwrap();
                    while let Some(waker) = stream.transmit_waker.pop() {
                        waker.wake_by_ref();
                    }
                    stream
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
            id,
            set,
            checklist_id,
            state,
            agent,
            transmit_send,
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
        let mut state = self.state.lock().unwrap();
        let index = state
            .components
            .iter()
            .enumerate()
            .find(|c| c.1.is_none())
            .unwrap_or((state.components.len(), &None))
            .0;
        info!("stream {} adding component {}", self.id, index + 1);
        if state.components.get(index).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        while state.components.len() <= index {
            state.components.push(None);
        }
        let component = Component::new(index + 1);
        state.components[index] = Some(component.clone());
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.add_component(component.id());
        info!("Added component at index {}", index);
        Ok(component)
    }

    /// Remove a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, an error is returned
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
    /// assert!(stream.remove_component(component::RTP).is_ok());
    /// ```
    ///
    /// Removing a `Component` that was never added will return an error
    ///
    /// ```
    /// # use librice::agent::{Agent, AgentError};
    /// # use librice::component;
    /// # use librice::component::Component;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// assert!(matches!(stream.remove_component(component::RTP), Err(AgentError::ResourceNotFound)));
    /// ```
    // Should this really be public API?
    pub fn remove_component(&self, component_id: usize) -> Result<(), AgentError> {
        let mut state = self.state.lock().unwrap();
        if component_id < 1 {
            return Err(AgentError::ResourceNotFound);
        }
        let index = component_id - 1;
        let component = state
            .components
            .get(index)
            .ok_or(AgentError::ResourceNotFound)?
            .as_ref()
            .ok_or(AgentError::ResourceNotFound)?;
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.remove_component(component.id());
        state.components[index] = None;
        Ok(())
    }

    /// Retrieve a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, an error is returned
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
        let state = self.state.lock().unwrap();
        if index < 1 {
            return None;
        }
        state
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
    #[tracing::instrument(
        skip(self),
        fields(
            stream_id = self.id
        )
    )]
    pub fn set_local_credentials(&self, credentials: Credentials) {
        info!("setting");
        let mut state = self.state.lock().unwrap();
        state.local_credentials = Some(credentials.clone());
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.set_local_credentials(credentials);
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
        let state = self.state.lock().unwrap();
        state.local_credentials.clone()
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
    #[tracing::instrument(
        skip(self),
        fields(
            stream_id = self.id()
        )
    )]
    pub fn set_remote_credentials(&self, credentials: Credentials) {
        info!("setting");
        let mut state = self.state.lock().unwrap();
        state.remote_credentials = Some(credentials.clone());
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.set_remote_credentials(credentials)
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
        let state = self.state.lock().unwrap();
        state.remote_credentials.clone()
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
    /// stream.add_remote_candidate(&candidate).unwrap();
    /// ```
    #[tracing::instrument(
        skip(self, cand),
        fields(
            stream_id = self.id()
        )
    )]
    pub fn add_remote_candidate(&self, cand: &Candidate) -> Result<(), AgentError> {
        info!("adding remote candidate {:?}", cand);
        // TODO: error if component doesn't exist
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.add_remote_candidate(cand.clone());
        drop(set);
        if let Some(agent) = self.agent.upgrade() {
            let mut agent = agent.lock().unwrap();
            if let Some(waker) = agent.waker.take() {
                waker.wake();
            }
        }
        Ok(())
    }

    async fn handle_incoming_data(
        weak_state: Weak<Mutex<StreamState>>,
        weak_set: Weak<Mutex<ConnCheckListSet>>,
        weak_agent: Weak<Mutex<AgentInner>>,
        checklist_id: usize,
        component_id: usize,
        transmit: Transmit,
    ) {
        let Some(state) = weak_state.upgrade() else {
            return;
        };
        {
            let mut state = state.lock().unwrap();
            if state.gather_state == GatherProgress::InProgress {
                if let Some(gather) = state
                    .gatherers
                    .iter()
                    .find(|gather| gather.gatherer.component_id() == component_id)
                {
                    if let Ok(replies) = gather.gatherer.handle_data(&transmit.data, transmit.from)
                    {
                        for reply in replies {
                            // XXX: is this enough to successfully route to the gatherer over the
                            // connection check or component received handling?
                            if let HandleStunReply::Stun(_msg, _from) = reply {
                                while let Some(waker) = state.transmit_waker.pop() {
                                    waker.wake_by_ref();
                                }
                            }
                        }
                        return;
                    }
                }
            }
        }
        let Some(set) = weak_set.upgrade() else {
            return;
        };
        let mut wake_agent = false;
        {
            let mut set_inner = set.lock().unwrap();
            if let Ok(replies) = set_inner.incoming_data(checklist_id, &transmit) {
                for reply in replies {
                    match reply {
                        HandleRecvReply::Data(data, from) => {
                            drop(set_inner);
                            let Some(state) = weak_state.upgrade() else {
                                return;
                            };
                            let state = state.lock().unwrap();
                            let Some(Some(component)) = state
                                .components
                                .iter()
                                .find(|comp| comp.as_ref().map(|c| c.id) == Some(component_id))
                            else {
                                return;
                            };
                            component.handle_incoming_data(data, from);
                            set_inner = set.lock().unwrap();
                        }
                        HandleRecvReply::Handled => {
                            wake_agent = true;
                        }
                        HandleRecvReply::Ignored => (),
                    }
                }
            }
        }

        if wake_agent {
            if let Some(agent) = weak_agent.upgrade() {
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
    /// stream.gather_candidates().unwrap();
    /// ```
    pub fn gather_candidates(&self) -> Result<Gather, AgentError> {
        let stun_servers = {
            let agent = self.agent.upgrade().ok_or(AgentError::ResourceNotFound)?;
            let agent = agent.lock().unwrap();
            agent.stun_servers.clone()
        };

        let weak_state = Arc::downgrade(&self.state);
        let mut state = self.state.lock().unwrap();
        if state.gather_state != GatherProgress::New {
            return Err(AgentError::AlreadyInProgress);
        }
        let component_ids = state
            .components
            .iter()
            .filter_map(|c| c.clone())
            .map(|c| {
                c.set_state(ComponentState::Connecting);
                c.id
            })
            .collect::<Vec<_>>();
        let gatherers = component_ids
            .iter()
            .map(|&cid| {
                // FIXME: remove block_on()
                let sockets = async_std::task::block_on(async move {
                    iface_sockets()
                        .unwrap()
                        .filter_map(|s| async move { s.ok() })
                        .collect::<Vec<_>>()
                        .await
                });
                let proto_sockets = sockets
                    .iter()
                    .map(|s| (s.transport(), s.local_addr()))
                    .collect::<Vec<_>>();
                for socket in sockets {
                    let weak_state = weak_state.clone();
                    let weak_set = Arc::downgrade(&self.set);
                    let weak_agent = self.agent.clone();
                    let checklist_id = self.checklist_id;
                    let local_addr = socket.local_addr();
                    let transport = socket.transport();
                    match socket {
                        GatherSocket::Udp(udp) => {
                            state.sockets.push(StunChannel::Udp(udp.clone()));
                            async_std::task::spawn(async move {
                                let recv = udp.recv();
                                let mut recv = core::pin::pin!(recv);
                                while let Some((data, from)) = recv.next().await {
                                    Self::handle_incoming_data(
                                        weak_state.clone(),
                                        weak_set.clone(),
                                        weak_agent.clone(),
                                        checklist_id,
                                        cid,
                                        Transmit {
                                            transport,
                                            data,
                                            from,
                                            to: local_addr,
                                        },
                                    )
                                    .await
                                }
                            });
                        }
                        GatherSocket::Tcp(tcp) => {
                            async_std::task::spawn(async move {
                                while let Some(stream) = tcp.incoming().next().await {
                                    let Ok(stream) = stream else {
                                        continue;
                                    };
                                    let weak_set = weak_set.clone();
                                    let weak_state = weak_state.clone();
                                    let weak_agent = weak_agent.clone();
                                    async_std::task::spawn(async move {
                                        let Some(state) = weak_state.upgrade() else {
                                            return;
                                        };
                                        let channel = {
                                            let mut state = state.lock().unwrap();
                                            let channel = TcpChannel::new(stream);
                                            state.sockets.push(StunChannel::Tcp(channel.clone()));
                                            channel
                                        };

                                        let recv = channel.recv();
                                        let mut recv = core::pin::pin!(recv);
                                        while let Some((data, from)) = recv.next().await {
                                            Self::handle_incoming_data(
                                                weak_state.clone(),
                                                weak_set.clone(),
                                                weak_agent.clone(),
                                                checklist_id,
                                                cid,
                                                Transmit {
                                                    transport,
                                                    data,
                                                    from,
                                                    to: local_addr,
                                                },
                                            )
                                            .await
                                        }
                                    });
                                }
                            });
                        }
                    }
                }
                Gatherer {
                    gatherer: StunGatherer::new(cid, proto_sockets, stun_servers.clone()),
                }
            })
            .collect::<Vec<_>>();

        state.gather_state = GatherProgress::InProgress;
        state.gatherers = gatherers;
        Ok(Gather {
            stream: self.state.clone(),
            timer: None,
            weak_set: Arc::downgrade(&self.set),
            checklist_id: self.checklist_id,
            transmit_send: self.transmit_send.clone(),
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
                            checklist_id,
                            component_id,
                            Transmit {
                                data,
                                transport: TransportType::Udp,
                                from,
                                to: local_addr,
                            },
                        )
                        .await;
                    }
                });
            }
            TransportType::Tcp => {
                 match candidate.tcp_type {
                     Some(TcpType::Passive) => {
                         let stream = TcpListener::bind(candidate.base_address).await?;
                         async_std::task::spawn(async move {
                             while let Some(stream) =
                             Self::handle_incoming_data(weak_state, weak_set, checklist_id, component_id, transmit)
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
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.local_candidates()
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
    /// stream.add_remote_candidate(&candidate).unwrap();
    /// let remote_cands = stream.remote_candidates();
    /// assert_eq!(remote_cands.len(), 1);
    /// assert_eq!(remote_cands[0], candidate);
    /// ```
    pub fn remote_candidates(&self) -> Vec<Candidate> {
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.remote_candidates()
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
        let mut set = self.set.lock().unwrap();
        let checklist = set.list_mut(self.checklist_id).unwrap();
        checklist.end_of_remote_candidates();
    }

    pub(crate) fn handle_transmit(&self, transmit: Transmit, waker: Waker) -> Option<Transmit> {
        if let Err(async_std::channel::TrySendError::Full(transmit)) =
            self.transmit_send.try_send(transmit)
        {
            let mut state = self.state.lock().unwrap();
            state.transmit_waker.push(waker);
            return Some(transmit);
        }
        None
    }

    pub(crate) fn handle_tcp_connect(
        &self,
        component_id: usize,
        from: SocketAddr,
        to: SocketAddr,
        waker: Waker,
    ) {
        let weak_set = Arc::downgrade(&self.set);
        let weak_state = Arc::downgrade(&self.state);
        let checklist_id = self.checklist_id;
        async_std::task::spawn(async move {
            let stream = TcpStream::connect(to).await;
            let channel = match stream {
                Ok(stream) => {
                    let Some(state) = weak_state.upgrade() else {
                        return;
                    };
                    let mut state = state.lock().unwrap();
                    let channel = StunChannel::Tcp(TcpChannel::new(stream.clone()));
                    state.sockets.push(channel.clone());
                    Ok(channel)
                }
                Err(e) => Err(StunError::IoError(e)),
            };
            let Some(set) = weak_set.upgrade() else {
                return;
            };
            let mut set = set.lock().unwrap();
            let agent = channel.map(|channel| {
                let local_addr = channel.local_addr().unwrap();
                let remote_addr = channel.remote_addr().unwrap();
                StunAgent::builder(TransportType::Tcp, local_addr)
                    .remote_addr(remote_addr)
                    .build()
            });
            set.tcp_connect_reply(checklist_id, component_id, from, to, agent);
            waker.wake();
        });
    }

    pub(crate) fn socket_for_pair(&self, pair: &CandidatePair) -> Option<StunChannel> {
        let state = self.state.lock().unwrap();
        state
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
            let mut gather = s.gather_candidates().unwrap();
            while let Some(_cand) = gather.next().await {}
            let local_cands = s.local_candidates();
            info!("gathered local candidates {:?}", local_cands);
            assert!(!local_cands.is_empty());
            assert!(matches!(
                s.gather_candidates(),
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
        let comp = stream.add_component().unwrap();
        assert_eq!(comp.id(), stream.component(comp.id()).unwrap().id());

        stream.set_local_credentials(lcreds.clone());
        assert_eq!(stream.local_credentials().unwrap(), lcreds);
        stream.set_remote_credentials(rcreds.clone());
        assert_eq!(stream.remote_credentials().unwrap(), rcreds);
    }
}
