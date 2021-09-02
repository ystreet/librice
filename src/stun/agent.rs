// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN agent

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use std::time::Duration;

use std::collections::HashMap;

use futures::future::AbortHandle;
use futures::future::Either;
use futures::prelude::*;
use futures_timer::Delay;

use crate::agent::AgentError;

use crate::stun::message::*;

use crate::socket::SocketChannel;
use crate::utils::{ChannelBroadcast, DebugWrapper};

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub enum StunOrData
{
    Stun(Message, Vec<u8>, SocketAddr),
    Data(Vec<u8>, SocketAddr),
}

impl StunOrData
{
    pub fn stun(self) -> Option<(Message, Vec<u8>, SocketAddr)> {
        match self {
            StunOrData::Stun(msg, data, addr) => Some((msg, data, addr)),
            _ => None,
        }
    }
    pub fn data(self) -> Option<(Vec<u8>, SocketAddr)> {
        match self {
            StunOrData::Data(data, addr) => Some((data, addr)),
            _ => None,
        }
   }
}

/// Implementation of a STUN agent
#[derive(Debug, Clone)]
pub struct StunAgent {
    pub(crate) inner: DebugWrapper<Arc<StunAgentInner>>,
}

#[derive(Debug)]
pub(crate) struct StunAgentInner {
    id: usize,
    state: Mutex<StunAgentState>,
    pub(crate) channel: SocketChannel,
    broadcaster : Arc<ChannelBroadcast<StunOrData>>,
}

#[derive(Debug)]
struct StunAgentState {
    id: usize,
    receive_loop_started: bool,
    outstanding_requests: HashMap<u128, Message>,
    local_credentials: Option<MessageIntegrityCredentials>,
    remote_credentials: Option<MessageIntegrityCredentials>,
}

impl StunAgent {
    pub fn new(channel: SocketChannel) -> Self {
        let id = STUN_AGENT_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            inner: DebugWrapper::wrap(
                Arc::new(StunAgentInner {
                    id,
                    state: Mutex::new(StunAgentState::new(id)),
                    channel,
                    broadcaster: Arc::new(ChannelBroadcast::default()),
                }),
                "...",
            ),
        }
    }

    pub fn channel(&self) -> SocketChannel {
        self.inner.channel.clone()
    }

    fn maybe_store_message(state: &Mutex<StunAgentState>, msg: Message) {
        if msg.has_class(MessageClass::Request) {
            let mut state = state.lock().unwrap();
            trace!("{} storing request {}", state.id, msg);
            state.outstanding_requests.insert(msg.transaction_id(), msg);
        }
    }

    pub fn set_local_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.local_credentials = Some(credentials)
    }

    pub fn local_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.local_credentials.clone()
    }

    pub fn set_remote_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.remote_credentials = Some(credentials)
    }

    pub fn remote_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.remote_credentials.clone()
    }

    pub async fn send_to(&self, msg: Message, to: SocketAddr) -> Result<(), std::io::Error> {
        StunAgent::maybe_store_message(&self.inner.state, msg.clone());
        let buf = msg.to_bytes();
        self.inner.channel.send_to(&buf, to).await
    }

    pub async fn send(&self, msg: Message) -> Result<(), std::io::Error> {
        StunAgent::maybe_store_message(&self.inner.state, msg.clone());
        let buf = msg.to_bytes();
        self.inner.channel.send(&buf).await
    }

    fn receive_task_loop(inner_weak: Weak<StunAgentInner>, channel: SocketChannel) {
        // XXX: can we remove this demuxing task?
        // retrieve stream outside task to avoid a race
        let s = channel.receive_stream().unwrap();
        async_std::task::spawn({
            async move {
                futures::pin_mut!(s);
                while let Some((data, from)) = s.next().await {
                    let inner = match Weak::upgrade(&inner_weak) {
                        Some(inner) => inner,
                        None => {
                            info!("Receive task exit");
                            break;
                        }
                    };
                    match Message::from_bytes(&data) {
                        Ok(msg) => {
                            debug!("{} received from {:?} {}", inner.id, from, msg);
                            let handle = {
                                let mut state = inner.state.lock().unwrap();
                                state.handle_stun(msg.clone())
                            };
                            match handle {
                                HandleStunReply::Broadcast(msg) => {
                                    inner.broadcaster.broadcast(StunOrData::Stun(msg, data, from)).await;
                                }
                                HandleStunReply::Failure(err) => {
                                    warn!("{} Failed to handle {}. {:?}", inner.id, msg, err);
                                }
                                _ => {}
                            }
                        }
                        Err(_) => inner.broadcaster.broadcast(StunOrData::Data(data, from)).await,
                    }
                }
            }
        });
    }

    fn ensure_receive_task_loop(&self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            if !state.receive_loop_started {
                let inner_weak = Arc::downgrade(&self.inner);
                StunAgent::receive_task_loop(inner_weak, self.inner.channel.clone());
                state.receive_loop_started = true;
            }
        }
    }

    pub fn receive_stream_filter<F>(
        &self,
        filter: F,
    ) -> impl Stream<Item = StunOrData>
    where
        F: Fn(&StunOrData) -> bool + Send + Sync + 'static,
    {
        let ret = self.inner.broadcaster.channel_with_filter(filter);
        self.ensure_receive_task_loop();
        ret
    }

    pub fn receive_stream(&self) -> impl Stream<Item = StunOrData> {
        self.receive_stream_filter(|_| true)
    }

    async fn send_request(
        &self,
        msg: &Message,
        recv_abort_handle: AbortHandle,
        to: SocketAddr,
    ) -> Result<(), AgentError> {
        // FIXME: configurable timeout values: RFC 4389 Secion 7.2.1
        let timeouts: [u64; 7] = [0, 500, 1500, 3500, 7500, 15500, 31500];
        for timeout in timeouts.iter() {
            Delay::new(Duration::from_millis(*timeout)).await;
            info!("{} sending {} to {}", self.inner.id, msg, to);
            let buf = msg.to_bytes();
            self.inner.channel.send_to(&buf, to).await?;
        }

        // on failure, abort the receiver waiting
        recv_abort_handle.abort();
        Err(AgentError::TimedOut)
    }

    pub async fn stun_request_transaction(
        &self,
        msg: &Message,
        addr: SocketAddr,
    ) -> Result<(Message, Vec<u8>, SocketAddr), AgentError> {
        if !msg.has_class(MessageClass::Request) {
            return Err(AgentError::WrongImplementation);
        }
        Self::maybe_store_message(&self.inner.state, msg.clone());
        let tid = msg.transaction_id();
        let (recv_abort_handle, recv_registration) = futures::future::AbortHandle::new_pair();
        let (send_abortable, send_abort_handle) =
            futures::future::abortable(self.send_request(&msg, recv_abort_handle, addr));

        let mut receive_s =
            self.receive_stream_filter(move |stun_or_data| {
                match stun_or_data {
                    StunOrData::Stun(msg, _, _) => tid == msg.transaction_id(),
                    _ => false,
                }
            });
        let recv_abortable = futures::future::Abortable::new(
            receive_s.next().then(|msg| async move {
                send_abort_handle.abort();
                msg.and_then(|msg| msg.stun())
            }),
            recv_registration,
        );

        futures::pin_mut!(send_abortable);
        futures::pin_mut!(recv_abortable);

        // race the sending and receiving futures returning the first that succeeds
        match futures::future::try_select(send_abortable, recv_abortable).await {
            Ok(Either::Left((x, _))) => x.map(|_| (Message::new_error(msg), vec![], addr)),
            Ok(Either::Right((y, _))) => y.ok_or(AgentError::TimedOut),
            Err(_) => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum HandleStunReply {
    Broadcast(Message),
    Failure(AgentError),
    Ignore,
}
impl From<AgentError> for HandleStunReply {
    fn from(e: AgentError) -> Self {
        HandleStunReply::Failure(e)
    }
}

impl StunAgentState {
    fn new(id: usize) -> Self {
        Self {
            id,
            outstanding_requests: HashMap::new(),
            local_credentials: None,
            remote_credentials: None,
            receive_loop_started: false,
        }
    }

    fn handle_stun(&mut self, msg: Message) -> HandleStunReply {
        // TODO: validate message with credentials
        if msg.is_response() {
            if let Some(_orig_request) = self.outstanding_requests.remove(&msg.transaction_id()) {
                return HandleStunReply::Broadcast(msg);
            } else {
                debug!("{}, unmatched stun response, dropping {}", self.id, msg);
                // unmatched response -> drop
                return HandleStunReply::Ignore;
            }
        }
        HandleStunReply::Broadcast(msg)
    }
}
