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
use tracing_futures::Instrument;

use crate::agent::AgentError;

use crate::socket::*;
use crate::stun::message::*;

use crate::clock::{get_clock, Clock, ClockType};

use crate::utils::{ChannelBroadcast, DebugWrapper};

static STUN_AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Implementation of a STUN agent
#[derive(Debug, Clone)]
pub struct StunAgent {
    pub(crate) id: usize,
    clock: Arc<dyn Clock>,
    pub(crate) inner: DebugWrapper<Arc<StunAgentInner>>,
}

#[derive(Debug)]
pub(crate) struct StunAgentInner {
    id: usize,
    state: Mutex<StunAgentState>,
    pub(crate) channel: StunChannel,
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

pub(crate) struct StunAgentBuilder {
    channel: StunChannel,
    clock: Option<Arc<dyn Clock>>,
}

impl StunAgentBuilder {
    fn new(channel: StunChannel) -> Self {
        StunAgentBuilder {
            channel,
            clock: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn build(self) -> StunAgent {
        let id = STUN_AGENT_COUNT.fetch_add(1, Ordering::SeqCst);
        let clock = self
            .clock
            .unwrap_or_else(|| get_clock(ClockType::default()));
        StunAgent {
            id,
            clock,
            inner: DebugWrapper::wrap(
                Arc::new(StunAgentInner {
                    id,
                    state: Mutex::new(StunAgentState::new(id)),
                    channel: self.channel,
                    broadcaster: Arc::new(ChannelBroadcast::default()),
                }),
                "...",
            ),
        }
    }
}

impl StunAgent {
    pub fn new(channel: StunChannel) -> Self {
        Self::builder(channel).build()
    }

    pub(crate) fn builder(channel: StunChannel) -> StunAgentBuilder {
        StunAgentBuilder::new(channel)
    }

    pub fn channel(&self) -> StunChannel {
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
        debug!("channel {:?}", self.inner.channel);
        self.inner
            .channel
            .send(StunOrData::Stun(msg, vec![], to))
            .await
    }

    pub async fn send(&self, msg: Message) -> Result<(), std::io::Error> {
        let to = self.inner.channel.remote_addr()?;
        self.send_to(msg, to).await
    }

    fn receive_task_loop(inner_weak: Weak<StunAgentInner>, channel: StunChannel, inner_id: usize) {
        // XXX: can we remove this demuxing task?
        // retrieve stream outside task to avoid a race
        let recv_stream = channel.receive_stream();
        let local_addr = channel.local_addr();
        debug!(
            "starting stun_recv_loop stun.id={} local_addr={:?}",
            inner_id, local_addr
        );
        async_std::task::spawn({
            let span = debug_span!("stun_recv_loop", stun.id = inner_id, ?local_addr);
            async move {
                futures::pin_mut!(recv_stream);

                debug!("started");
                while let Some(stun_or_data) = recv_stream.next().await {
                    debug!("got {:?}", stun_or_data);
                    let inner = match Weak::upgrade(&inner_weak) {
                        Some(inner) => inner,
                        None => {
                            break;
                        }
                    };
                    match stun_or_data {
                        StunOrData::Stun(msg, data, from) => {
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
                        StunOrData::Data(data, from) => {
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
        msg: Message,
        recv_abort_handle: AbortHandle,
        to: SocketAddr,
    ) -> Result<(), AgentError> {
        // FIXME: configurable timeout values: RFC 4389 Secion 7.2.1
        let timeouts: [u64; 7] = [0, 500, 1500, 3500, 7500, 15500, 31500];
        for timeout in timeouts.iter() {
            self.clock
                .delay(Duration::from_millis(*timeout))
                .await
                .wait()
                .await;
            trace!("sending {}", msg);
            self.inner
                .channel
                .send(StunOrData::Stun(msg.clone(), vec![], to))
                .await?;
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
            futures::future::abortable(self.send_request(msg.clone(), recv_abort_handle, addr));

        let mut receive_s = self.receive_stream_filter(move |stun_or_data| match stun_or_data {
            StunOrData::Stun(msg, _, from) => tid == msg.transaction_id() && from == &addr,
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
pub(crate) mod tests {
    use super::*;
    use crate::socket::{StunOnlyTcpChannel, UdpConnectionChannel};
    use crate::stun::attribute::{Software, SOFTWARE};
    use async_std::net::{TcpListener, TcpStream};
    use async_std::task;

    fn init() {
        crate::tests::test_init_log();
    }

    fn recv_data(channel: StunChannel) -> impl Future<Output = StunOrData> {
        let result = Arc::new(Mutex::new(None));
        // retrieve the recv channel before starting the task otherwise, there is a race starting
        // the task against the a sender in the current thread.
        let recv = channel.receive_stream();
        let f = task::spawn({
            let result = result.clone();
            async move {
                futures::pin_mut!(recv);
                let val = recv.next().await.unwrap();
                let mut result = result.lock().unwrap();
                result.replace(val);
            }
        });
        async move {
            f.await;
            result.lock().unwrap().take().unwrap()
        }
    }

    async fn send_and_receive(send_socket: StunChannel, recv_socket: StunChannel) {
        // this won't work unless the sockets are pointing at each other
        assert_eq!(
            send_socket.local_addr().unwrap(),
            recv_socket.remote_addr().unwrap()
        );
        assert_eq!(
            recv_socket.local_addr().unwrap(),
            send_socket.remote_addr().unwrap()
        );
        let from = send_socket.local_addr().unwrap();
        let to = send_socket.remote_addr().unwrap();

        // send data and assert that it is received
        let recv = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket
            .send(StunOrData::Data(data.clone(), to))
            .await
            .unwrap();
        let result = recv.await.data().unwrap();
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
    }

    #[test]
    fn udp_connection_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            send_and_receive(socket_channel1, socket_channel2).await;
        });
    }

    async fn send_and_double_receive(send_socket: StunChannel, recv_socket: StunChannel) {
        // this won't work unless the sockets are pointing at each other
        assert_eq!(
            send_socket.local_addr().unwrap(),
            recv_socket.remote_addr().unwrap()
        );
        assert_eq!(
            recv_socket.local_addr().unwrap(),
            send_socket.remote_addr().unwrap()
        );
        let from = send_socket.local_addr().unwrap();
        let to = send_socket.remote_addr().unwrap();

        // send data and assert that it is received on both receive channels
        let recv1 = recv_data(recv_socket.clone());
        let recv2 = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket
            .send(StunOrData::Data(data.clone(), to))
            .await
            .unwrap();
        let result = recv1.await.data().unwrap();
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
        let result = recv2.await.data().unwrap();
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
    }

    #[test]
    fn send_multi_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(socket_channel1, socket_channel2).await;
        });
    }

    #[test]
    fn send_multi_recv_with_drop() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(socket_channel1.clone(), socket_channel2.clone()).await;

            // previous receivers should have been dropped as not connected anymore
            // XXX: doesn't currently test the actual drop just that nothing errors
            send_and_receive(socket_channel1, socket_channel2).await;
        });
    }

    #[test]
    fn send_udp_request_unanswered() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();
            let clock = Arc::new(crate::clock::tests::TestClock::default());

            let agent = StunAgent::builder(StunChannel::Udp(UdpConnectionChannel::new(udp1, from)))
                .clock(clock.clone())
                .build();

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap())
                .unwrap();
            msg.add_fingerprint().unwrap();

            let f = task::spawn(async move { agent.stun_request_transaction(&msg, to).await });

            // advance through all the waits to get to the timeout return value
            for _ in 0..6 {
                clock.advance().await;
            }
            assert!(matches!(f.await, Err(AgentError::TimedOut)));
        });
    }

    #[test]
    fn tcp_connection_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_addr = listener.local_addr().unwrap();
            let mut incoming = listener.incoming();
            let tcp2 = incoming.next();
            let tcp1 = task::spawn(async move { TcpStream::connect(local_addr).await });
            let _tcp2 = tcp2.await.unwrap().unwrap();
            let _tcp1 = tcp1.await.unwrap();

            // TODO: need the correct rfc framing to send data
            //let socket_channel1 = StunChannel::Tcp(TcpChannel::new(tcp1));
            //let socket_channel2 = StunChannel::Tcp(TcpChannel::new(tcp2));

            //send_and_receive(socket_channel1, socket_channel2).await;
        });
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
            info!("connected");
            let agent = StunAgent::new(StunChannel::Tcp(StunOnlyTcpChannel::new(tcp2)));

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap())
                .unwrap();
            msg.add_fingerprint().unwrap();
            let mut bytes = msg.to_bytes();
            let mut msg = Message::new_request(32);
            let software_str2 = "AB";
            msg.add_attribute(Software::new(software_str2).unwrap())
                .unwrap();
            bytes.extend(msg.to_bytes());

            let mut receive_stream = agent.receive_stream();
            // split the write into 3 parts to ensure the reader buffers up correctly in all cases
            tcp1.write_all(&bytes[..19]).await.unwrap();
            // waits to ensure the tcp stack actually splits these reads
            task::sleep(Duration::from_millis(10)).await;
            tcp1.write_all(&bytes[19..30]).await.unwrap();
            task::sleep(Duration::from_millis(10)).await;
            tcp1.write_all(&bytes[30..40]).await.unwrap();
            task::sleep(Duration::from_millis(10)).await;
            tcp1.write_all(&bytes[40..60]).await.unwrap();
            task::sleep(Duration::from_millis(10)).await;
            tcp1.write_all(&bytes[60..]).await.unwrap();
            info!("written");

            let stun_or_data = receive_stream.next().await.unwrap();
            info!("received1");
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _, _)));
            let (stun_msg, _data, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.get_attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str);

            let stun_or_data = receive_stream.next().await.unwrap();
            info!("received2");
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _, _)));
            let (stun_msg, _data, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.get_attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str2);
        });
    }
}
