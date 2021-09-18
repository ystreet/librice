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
use tracing_futures::Instrument;

use byteorder::{BigEndian, ByteOrder};

use crate::agent::AgentError;

use crate::stun::message::*;

use crate::socket::SocketChannel;
use crate::utils::{ChannelBroadcast, DebugWrapper};

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

#[derive(Debug, Clone)]
pub enum StunOrData {
    Stun(Message, Vec<u8>, SocketAddr),
    Data(Vec<u8>, SocketAddr),
}

impl StunOrData {
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
    pub(crate) id: usize,
    pub(crate) inner: DebugWrapper<Arc<StunAgentInner>>,
}

#[derive(Debug)]
pub(crate) struct StunAgentInner {
    id: usize,
    state: Mutex<StunAgentState>,
    pub(crate) channel: SocketChannel,
    broadcaster: Arc<ChannelBroadcast<StunOrData>>,
}

#[derive(Debug)]
struct StunAgentState {
    id: usize,
    receive_loop_started: bool,
    outstanding_requests: HashMap<TransactionId, Message>,
    local_credentials: Option<MessageIntegrityCredentials>,
    remote_credentials: Option<MessageIntegrityCredentials>,
}

impl StunAgent {
    pub fn new(channel: SocketChannel) -> Self {
        let id = STUN_AGENT_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
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

    fn receive_task_loop(
        inner_weak: Weak<StunAgentInner>,
        channel: SocketChannel,
        inner_id: usize,
    ) {
        // XXX: can we remove this demuxing task?
        // retrieve stream outside task to avoid a race
        let recv_stream = channel.receive_stream().unwrap();
        let message_based = channel.produces_complete_messages();
        let local_addr = channel.local_addr();
        async_std::task::spawn({
            let span = debug_span!("stun_recv_loop", stun.id = inner_id, ?local_addr);
            async move {
                let buf = Vec::with_capacity(2048);
                futures::pin_mut!(recv_stream);
                let s = stream::unfold((recv_stream, buf), |(mut recv_stream, mut buf)| async move {
                    let mut ret = None;
                    while let Some((data, from)) = recv_stream.next().await {
                        if message_based {
                            ret = Some(((data, from), (recv_stream, buf)));
                            break;
                        } else {
                            // we need to buffer up until we have enough data for each STUN
                            // message. This assumes that no other data is being sent over
                            // this socket
                            buf.extend_from_slice(&data);
                            if buf.len() < 20 {
                                trace!("not enough data, buf length {} too short (< 20)", buf.len());
                                continue;
                            } else {
                                let mlength = BigEndian::read_u16(&buf[2..]) as usize;
                                if mlength > MAX_STUN_MESSAGE_SIZE {
                                    warn!("stun message length ({}) is absurd > {}", mlength, MAX_STUN_MESSAGE_SIZE);
                                    break;
                                }
                                if mlength + 20 > buf.len() {
                                    trace!("not enough data, buf length {} less than advertised size {}", buf.len(), mlength + 20);
                                    continue;
                                }
                                let (data, _rest) = buf.split_at(mlength + 20);
                                let data = data.to_vec();
                                buf.drain(..mlength + 20);
                                ret = Some(((data, from), (recv_stream, buf)));
                                break;
                            }
                        }
                    }
                    ret
                });

                futures::pin_mut!(s);
                while let Some((data, from)) = s.next().await {
                    let inner = match Weak::upgrade(&inner_weak) {
                        Some(inner) => inner,
                        None => {
                            break;
                        }
                    };
                    match Message::from_bytes(&data) {
                        Ok(msg) => {
                            debug!("received from {:?} {}", from, msg);
                            let handle = {
                                let mut state = inner.state.lock().unwrap();
                                state.handle_stun(msg.clone())
                            };
                            match handle {
                                HandleStunReply::Broadcast(msg) => {
                                    inner
                                        .broadcaster
                                        .broadcast(StunOrData::Stun(msg, data, from))
                                        .await;
                                }
                                HandleStunReply::Failure(err) => {
                                    warn!("Failed to handle {}. {:?}", msg, err);
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            warn!("{:?}", e);
                            inner
                                .broadcaster
                                .broadcast(StunOrData::Data(data, from))
                                .await
                        }
                    }
                }
                debug!("task exit");
            }
            .instrument(span)
        });
    }

    fn ensure_receive_task_loop(&self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            if !state.receive_loop_started {
                let inner_weak = Arc::downgrade(&self.inner);
                StunAgent::receive_task_loop(inner_weak, self.inner.channel.clone(), self.inner.id);
                state.receive_loop_started = true;
            }
        }
    }

    pub fn receive_stream_filter<F>(&self, filter: F) -> impl Stream<Item = StunOrData>
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

    #[tracing::instrument(
        name = "stun_send_request",
        level = "debug",
        err,
        skip(self, msg, recv_abort_handle),
        fields(
            msg.transaction_id = %msg.transaction_id()
        )
    )]
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
            trace!("sending {}", msg);
            let buf = msg.to_bytes();
            self.inner.channel.send_to(&buf, to).await?;
        }

        // on failure, abort the receiver waiting
        recv_abort_handle.abort();
        Err(AgentError::TimedOut)
    }

    #[tracing::instrument(
        level = "debug",
        err,
        skip(self, msg, addr),
        fields(
            agent_id = %self.inner.id,
            transaction_id = %msg.transaction_id(),
            target_addr = ?addr,
            source_addr = ?self.inner.channel.local_addr()
        ),
    )]
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
            futures::future::abortable(self.send_request(msg, recv_abort_handle, addr));

        let mut receive_s = self.receive_stream_filter(move |stun_or_data| match stun_or_data {
            StunOrData::Stun(msg, _, _) => tid == msg.transaction_id(),
            _ => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::TcpChannel;
    use crate::stun::attribute::{SOFTWARE, Software};
    use async_std::task;
    use async_std::net::{TcpListener, TcpStream};

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn split_tcp_write_read() {
        init();
        task::block_on(async move {
            // ensure that if data comes in split, that the delineation between messages is
            // maintained.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr1 = listener.local_addr().unwrap();
            let mut incoming = listener.incoming();
            let mut tcp1 = TcpStream::connect(addr1).await.unwrap();
            let addr2 = tcp1.local_addr().unwrap();
            let tcp2 = incoming.next().await.unwrap().unwrap();
            let agent = StunAgent::new(SocketChannel::Tcp(TcpChannel::new(tcp2)));

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap()).unwrap();
            msg.add_fingerprint().unwrap();
            let mut bytes = msg.to_bytes();
            let mut msg = Message::new_request(32);
            let software_str2 = "AB";
            msg.add_attribute(Software::new(software_str2).unwrap()).unwrap();
            bytes.extend(msg.to_bytes());

            let mut receive_stream = agent.receive_stream();
            // split the write into 3 parts to ensure the reader buffers up correctly in all cases
            tcp1.write_all(&bytes[..19]).await.unwrap();
            // waits to ensure the tcp stack actually splits these reads
            task::sleep(Duration::from_millis (10)).await;
            tcp1.write_all(&bytes[19..30]).await.unwrap();
            task::sleep(Duration::from_millis (10)).await;
            tcp1.write_all(&bytes[30..40]).await.unwrap();
            task::sleep(Duration::from_millis (10)).await;
            tcp1.write_all(&bytes[40..60]).await.unwrap();
            task::sleep(Duration::from_millis (10)).await;
            tcp1.write_all(&bytes[60..]).await.unwrap();

            let stun_or_data = receive_stream.next().await.unwrap();
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _, _)));
            let (stun_msg, _data, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.get_attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str);

            let stun_or_data = receive_stream.next().await.unwrap();
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _, _)));
            let (stun_msg, _data, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.get_attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str2);
        });
    }
}
