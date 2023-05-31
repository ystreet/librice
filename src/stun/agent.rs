// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN agent

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use std::time::Duration;

use std::collections::{HashMap, HashSet};

use async_std::net::TcpStream;
use futures::future::AbortHandle;
use futures::future::Either;
use futures::prelude::*;
use tracing_futures::Instrument;

use crate::stun::attribute::*;
use crate::stun::message::*;
use crate::stun::socket::*;

use crate::clock::{self, get_clock, Clock, ClockType};

use crate::utils::{ChannelBroadcast, DebugWrapper};

use super::TransportType;

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
    #[allow(dead_code)]
    id: usize,
    receive_loop_started: bool,
    validated_peers: HashSet<SocketAddr>,
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

    pub fn channel(&self) -> &StunChannel {
        &self.inner.channel
    }

    fn maybe_store_message(state: &Mutex<StunAgentState>, msg: Message) {
        if msg.has_class(MessageClass::Request) {
            let mut state = state.lock().unwrap();
            trace!("storing request {}", msg.transaction_id());
            state.outstanding_requests.insert(msg.transaction_id(), msg);
        }
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            stun.id = ?self.id
        )
    )]
    pub fn set_local_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.local_credentials = Some(credentials)
    }

    pub fn local_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.local_credentials.clone()
    }

    #[tracing::instrument(
        level = "debug",
        skip(self),
        fields(
            stun.id = ?self.id
        )
    )]
    pub fn set_remote_credentials(&self, credentials: MessageIntegrityCredentials) {
        let mut state = self.inner.state.lock().unwrap();
        state.remote_credentials = Some(credentials)
    }

    pub fn remote_credentials(&self) -> Option<MessageIntegrityCredentials> {
        let state = self.inner.state.lock().unwrap();
        state.remote_credentials.clone()
    }

    pub async fn send_data_to(&self, bytes: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        self.inner.channel.send(DataFraming::from(bytes, to)).await
    }

    #[tracing::instrument(
        name = "send_to",
        skip(self, msg, to),
        fields(
            stun.id = self.id,
            msg.transaction = %msg.transaction_id(),
            to
        )
    )]
    pub async fn send_to(&self, msg: Message, to: SocketAddr) -> Result<(), std::io::Error> {
        StunAgent::maybe_store_message(&self.inner.state, msg.clone());
        self.send_data_to(&msg.to_bytes(), to).await
    }

    pub async fn send(&self, msg: Message) -> Result<(), std::io::Error> {
        let to = self.inner.channel.remote_addr()?;
        self.send_to(msg, to).await
    }

    fn receive_task_loop(inner_weak: Weak<StunAgentInner>, channel: &StunChannel, inner_id: usize) {
        // XXX: can we remove this demuxing task?
        // retrieve stream outside task to avoid a race
        let recv_stream = channel.receive_stream();
        let local_addr = channel.local_addr();
        let remote_addr = channel.remote_addr().ok();
        debug!(
            "starting stun_recv_loop stun.id={inner_id} local_addr={local_addr:?} {}",
            channel.transport()
        );
        async_std::task::spawn({
            let span = debug_span!(
                "stun_recv_loop",
                stun.id = inner_id,
                ?local_addr,
                ?remote_addr
            );
            async move {
                futures::pin_mut!(recv_stream);

                debug!("started");
                while let Some(data_address) = recv_stream.next().await {
                    trace!(
                        "got {} bytes from {:?}",
                        data_address.data.len(),
                        data_address.address
                    );
                    let inner = match Weak::upgrade(&inner_weak) {
                        Some(inner) => inner,
                        None => {
                            warn!("stun agent has disappeared, exiting receive loop");
                            break;
                        }
                    };
                    match Message::from_bytes(&data_address.data) {
                        Ok(stun_msg) => {
                            debug!("received from {:?} {}", data_address.address, stun_msg);
                            let handle = {
                                let mut state = inner.state.lock().unwrap();
                                state.handle_stun(stun_msg, &data_address.data, data_address.address)
                            };
                            match handle {
                                HandleStunReply::Broadcast(stun_msg) => {
                                    inner
                                        .broadcaster
                                        .broadcast(StunOrData::Stun(stun_msg, data_address.address))
                                        .await;
                                }
                                HandleStunReply::Failure(err) => {
                                    warn!("Failed to handle message. {:?}", err);
                                    break;
                                }
                                _ => {}
                            }
                        }
                        Err(_) => {
                            let peer_validated = {
                                let state = inner.state.lock().unwrap();
                                state.validated_peers.get(&data_address.address).is_some()
                            };
                            if peer_validated {
                                inner
                                    .broadcaster
                                    .broadcast(StunOrData::Data(
                                        data_address.data,
                                        data_address.address,
                                    ))
                                    .await
                            } else if matches!(inner.channel, StunChannel::Tcp(_)) {
                                // close the tcp channel
                                warn!("stun message not the first message sent over TCP channel, closing");
                                if let Err(e) = inner.channel.close().await {
                                    warn!("error closing channel {:?}", e);
                                }
                                break;
                            } else {
                                trace!("dropping unvalidated data from peer");
                            }
                        }
                    }
                }
                debug!("task exit");
            }
            .instrument(span.or_current())
        });
    }

    fn ensure_receive_task_loop(&self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            if !state.receive_loop_started {
                let inner_weak = Arc::downgrade(&self.inner);
                StunAgent::receive_task_loop(inner_weak, &self.inner.channel, self.inner.id);
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
    pub fn stun_request_transaction(
        &self,
        msg: &Message,
        addr: SocketAddr,
    ) -> Result<StunRequestBuilder, StunError> {
        StunRequestBuilder::new(self.clone(), msg.clone(), addr)
    }

    pub(crate) fn tcp_connect_stun_request_transaction(
        clock: Arc<dyn Clock>,
        msg: &Message,
        addr: SocketAddr,
        create_agent_tx: async_channel::Sender<StunAgent>,
        create_agent_rx: async_channel::Receiver<StunAgent>,
    ) -> Result<StunRequestBuilder, StunError> {
        StunRequestBuilder::new_tcp(clock, msg.clone(), addr, create_agent_tx, create_agent_rx)
    }
}

pub struct StunRequestBuilder {
    agent: StunRequestAgent,
    clock: Arc<dyn Clock>,
    msg: Message,
    to: SocketAddr,
    create_agent_tx: Option<async_channel::Sender<StunAgent>>,
    create_agent_rx: Option<async_channel::Receiver<StunAgent>>,
}

impl StunRequestBuilder {
    fn new(agent: StunAgent, msg: Message, addr: SocketAddr) -> Result<Self, StunError> {
        if !msg.has_class(MessageClass::Request) {
            return Err(StunError::WrongImplementation);
        }
        Ok(Self {
            agent: StunRequestAgent::Agent(agent.clone()),
            clock: agent.clock.clone(),
            msg,
            to: addr,
            create_agent_tx: None,
            create_agent_rx: None,
        })
    }

    fn new_tcp(
        clock: Arc<dyn Clock>,
        msg: Message,
        addr: SocketAddr,
        create_agent_tx: async_channel::Sender<StunAgent>,
        create_agent_rx: async_channel::Receiver<StunAgent>,
    ) -> Result<Self, StunError> {
        if !msg.has_class(MessageClass::Request) {
            return Err(StunError::WrongImplementation);
        }
        Ok(Self {
            agent: StunRequestAgent::TcpRemote(addr),
            clock,
            msg,
            to: addr,
            create_agent_tx: Some(create_agent_tx),
            create_agent_rx: Some(create_agent_rx),
        })
    }

    pub fn build(self) -> Result<StunRequest, StunError> {
        let transaction_id = self.msg.transaction_id();
        let transport = match self.agent {
            StunRequestAgent::Agent(ref agent) => agent.channel().transport(),
            StunRequestAgent::TcpRemote(_) => TransportType::Tcp,
        };
        let timeouts_ms = if transport == TransportType::Tcp {
            vec![39500]
        } else {
            vec![500, 1000, 2000, 4000, 8000, 16000]
        };
        let (tx, rx) = if let (Some(tx), Some(rx)) = (self.create_agent_tx, self.create_agent_rx) {
            (tx, rx)
        } else {
            async_channel::bounded(1)
        };
        Ok(StunRequest(Arc::new(StunRequestState {
            agent: self.agent,
            clock: self.clock,
            msg: self.msg,
            to: self.to,
            inner: Mutex::new(StunRequestInner {
                transaction_id,
                send_abort: None,
                recv_abort: None,
            }),
            timeouts_ms,
            create_agent_tx: tx,
            create_agent_rx: rx,
        })))
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct StunRequestInner {
    transaction_id: TransactionId,
    #[derivative(Debug = "ignore")]
    send_abort: Option<AbortHandle>,
    #[derivative(Debug = "ignore")]
    recv_abort: Option<AbortHandle>,
}

impl StunRequestInner {
    #[tracing::instrument(
        name = "stun_request_cancel_retransmissions",
        level = "debug",
        skip(self),
        fields(
            msg.transaction_id = %self.transaction_id
        )
    )]
    fn cancel_retransmissions(&mut self) {
        if let Some(send_abort) = self.send_abort.take() {
            trace!("aborting sending stun request");
            send_abort.abort();
        }
    }
}

#[derive(Debug)]
enum StunRequestAgent {
    Agent(StunAgent),
    TcpRemote(SocketAddr),
}

#[derive(Debug)]
pub struct StunRequestState {
    agent: StunRequestAgent,
    clock: Arc<dyn Clock>,
    msg: Message,
    to: SocketAddr,
    inner: Mutex<StunRequestInner>,
    timeouts_ms: Vec<u64>,
    create_agent_tx: async_channel::Sender<StunAgent>,
    create_agent_rx: async_channel::Receiver<StunAgent>,
}

#[derive(Debug, Clone)]
pub struct StunRequest(Arc<StunRequestState>);

impl Deref for StunRequest {
    type Target = StunRequestState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StunRequest {
    pub fn request(&self) -> &Message {
        &self.msg
    }

    pub fn peer_address(&self) -> SocketAddr {
        self.to
    }

    pub fn cancel_retransmissions(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cancel_retransmissions();
    }

    #[tracing::instrument(
        name = "stun_request_cancel",
        level = "debug",
        skip(self),
        fields(
            msg.transaction_id = %self.msg.transaction_id()
        )
    )]
    pub fn cancel(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cancel_retransmissions();
        if let Some(recv_abort) = inner.recv_abort.take() {
            trace!("aborting recv stun request");
            recv_abort.abort();
        }
    }

    pub(crate) async fn create_agent(&self) -> Result<StunAgent, StunError> {
        let agent = match self.agent {
            StunRequestAgent::Agent(ref agent) => Ok(agent.clone()),
            StunRequestAgent::TcpRemote(remote_addr) => {
                let stream = TcpStream::connect(remote_addr)
                    .await
                    .map_err(StunError::IoError)?;
                Ok(StunAgent::new(StunChannel::Tcp(TcpChannel::new(stream))))
            }
        };
        if let Ok(agent) = agent {
            let mut rx = self.create_agent_rx.clone();
            if self.create_agent_tx.send(agent.clone()).await.is_err() {
                return Err(StunError::ResourceNotFound);
            }
            rx.next().await.ok_or(StunError::ResourceNotFound)
        } else {
            agent
        }
    }

    #[tracing::instrument(name = "stun_send_request", level = "debug", err, skip(self, agent))]
    async fn send_request(self, agent: StunAgent) -> Result<(), StunError> {
        for timeout in self.timeouts_ms.iter() {
            trace!(
                "sending from {:?}, request {}",
                agent.inner.channel.local_addr(),
                self.msg
            );
            agent.send_to(self.msg.clone(), self.to).await?;
            agent
                .clock
                .delay(Duration::from_millis(*timeout))
                .await
                .wait()
                .await;
        }

        Err(StunError::TimedOut)
    }

    #[tracing::instrument(
        name = "stun_request_perform",
        err,
        skip(self)
        fields(
            msg.transaction_id = %self.msg.transaction_id(),
            to = ?self.to,
        )
    )]
    pub async fn perform(&self) -> Result<(Message, SocketAddr), StunError> {
        let tid = self.msg.transaction_id();
        let (req_tx, mut req_rx) = async_channel::bounded(1);
        let (reply_tx, mut reply_rx) = async_channel::bounded(1);
        let (send_abortable, send_abort_handle) = futures::future::abortable(async move {
            // agent creation (e.g. tcp stream) is included in the timeout values
            let agent = self.create_agent().await?;
            req_tx
                .send(agent.clone())
                .await
                .map_err(|_| StunError::Aborted)?;
            reply_rx.next().await.ok_or(StunError::Aborted)?;
            self.clone().send_request(agent).await
        });

        let to = self.to;
        let (recv_abortable, recv_abort_handle) = {
            let send_abort_handle = send_abort_handle.clone();
            futures::future::abortable(clock::timeout(
                self.clock.clone(),
                Duration::from_secs(40),
                async move {
                    if let Some(agent) = req_rx.next().await {
                        let mut receive_s =
                            agent.receive_stream_filter(move |stun_or_data| match stun_or_data {
                                StunOrData::Stun(msg, from) => {
                                    tid == msg.transaction_id() && *from == to
                                }
                                _ => false,
                            });
                        reply_tx
                            .send(agent)
                            .await
                            .map_err(|_e| StunError::Aborted)?;
                        receive_s
                            .next()
                            .then(|msg| async move {
                                send_abort_handle.abort();
                                msg.and_then(|msg| msg.stun())
                                    .ok_or(StunError::ResourceNotFound)
                            })
                            .await
                    } else {
                        send_abort_handle.abort();
                        debug!("Stun Agent sender closed");
                        Err(StunError::ResourceNotFound)
                    }
                },
            ))
        };

        {
            let mut inner = self.inner.lock().unwrap();
            inner.send_abort = Some(send_abort_handle);
            inner.recv_abort = Some(recv_abort_handle);
        }

        futures::pin_mut!(send_abortable);
        futures::pin_mut!(recv_abortable);

        // race the sending and receiving futures returning the first that succeeds
        let ret = match futures::future::try_select(send_abortable, recv_abortable).await {
            Ok(Either::Left((x, _))) => x.map(|_| (Message::new_error(&self.msg), self.to)),
            Ok(Either::Right((y, _))) => y.map_err(|_| StunError::TimedOut)?,
            Err(Either::Left((_send_aborted, recv_abortable))) => {
                // if both have been aborted, then we return aborted, otherwise, we continue
                // waiting for a response until timeout
                recv_abortable
                    .await
                    .map_err(|_| StunError::Aborted)?
                    .unwrap_or(Err(StunError::TimedOut))
            }
            _ => unreachable!(),
        };
        if let Ok(ret) = &ret {
            debug!("response from {:?} {}", ret.1, ret.0);
        }
        ret
    }
}

#[derive(Debug, Clone)]
pub enum StunOrData {
    Stun(Message, SocketAddr),
    Data(Vec<u8>, SocketAddr),
}

impl StunOrData {
    pub fn stun(self) -> Option<(Message, SocketAddr)> {
        match self {
            StunOrData::Stun(msg, addr) => Some((msg, addr)),
            _ => None,
        }
    }
    pub fn data(self) -> Option<(Vec<u8>, SocketAddr)> {
        match self {
            StunOrData::Data(data, addr) => Some((data, addr)),
            _ => None,
        }
    }
    pub fn addr(&self) -> SocketAddr {
        match self {
            StunOrData::Stun(_msg, addr) => *addr,
            StunOrData::Data(_data, addr) => *addr,
        }
    }
}

#[derive(Debug)]
enum HandleStunReply {
    Broadcast(Message),
    Failure(StunError),
    Ignore,
}
impl From<StunError> for HandleStunReply {
    fn from(e: StunError) -> Self {
        HandleStunReply::Failure(e)
    }
}

#[derive(Debug)]
pub enum StunError {
    Failed,
    WrongImplementation,
    AlreadyExists,
    ResourceNotFound,
    TimedOut,
    IntegrityCheckFailed,
    ParseError(StunParseError),
    IoError(std::io::Error),
    Aborted,
}

impl std::error::Error for StunError {}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for StunError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<StunParseError> for StunError {
    fn from(e: StunParseError) -> Self {
        match e {
            StunParseError::WrongImplementation => StunError::WrongImplementation,
            _ => StunError::ParseError(e),
        }
    }
}

impl StunAgentState {
    fn new(id: usize) -> Self {
        Self {
            id,
            outstanding_requests: HashMap::new(),
            receive_loop_started: false,
            validated_peers: HashSet::new(),
            local_credentials: None,
            remote_credentials: None,
        }
    }

    fn validated_peer(&mut self, addr: SocketAddr) {
        if self.validated_peers.get(&addr).is_none() {
            debug!("validated peer {:?}", addr);
            self.validated_peers.insert(addr);
        }
    }

    fn handle_stun(&mut self, msg: Message, orig_data: &[u8], from: SocketAddr) -> HandleStunReply {
        if msg.is_response() {
            if let Some(orig_request) = self.take_outstanding_request(&msg.transaction_id()) {
                // only validate response if the original request had credentials
                if orig_request
                    .attribute::<MessageIntegrity>(MESSAGE_INTEGRITY)
                    .is_some()
                {
                    if let Some(remote_creds) = &self.remote_credentials {
                        match msg.validate_integrity(orig_data, remote_creds) {
                            Ok(_) => {
                                self.validated_peer(from);
                                HandleStunReply::Broadcast(msg)
                            }
                            Err(e) => {
                                debug!("message failed integrity check: {:?}", e);
                                HandleStunReply::Ignore
                            }
                        }
                    } else {
                        debug!("no remote credentials, ignoring");
                        HandleStunReply::Ignore
                    }
                } else {
                    // original message didn't have integrity, reply doesn't need to either
                    self.validated_peer(from);
                    HandleStunReply::Broadcast(msg)
                }
            } else {
                debug!("unmatched stun response, dropping {}", msg);
                // unmatched response -> drop
                HandleStunReply::Ignore
            }
        } else {
            self.validated_peer(from);
            HandleStunReply::Broadcast(msg)
        }
    }

    #[tracing::instrument(skip(self, transaction_id),
        fields(transaction_id = %transaction_id))]
    fn take_outstanding_request(&mut self, transaction_id: &TransactionId) -> Option<Message> {
        if let Some(msg) = self.outstanding_requests.remove(transaction_id) {
            trace!("removing request");
            Some(msg)
        } else {
            trace!("no outstanding request");
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::stun::attribute::{Software, SOFTWARE};
    use crate::stun::socket::tests::*;
    use crate::stun::socket::{TcpChannel, UdpConnectionChannel};
    use async_std::net::{TcpListener, TcpStream};
    use async_std::task;
    use byteorder::{BigEndian, ByteOrder};
    use std::net::{IpAddr, Ipv4Addr};

    fn init() {
        crate::tests::test_init_log();
    }

    fn recv_data(channel: &StunChannel) -> impl Future<Output = DataAddress> {
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

    async fn send_and_receive(send_socket: &StunChannel, recv_socket: &StunChannel) {
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
            .send(DataFraming::from(&data, to))
            .await
            .unwrap();
        let result = recv.await;
        assert_eq!(result.data, data);
        assert_eq!(result.address, from);
    }

    #[test]
    fn udp_connection_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::stun::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::stun::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            send_and_receive(&socket_channel1, &socket_channel2).await;
        });
    }

    async fn send_and_double_receive(send_socket: &StunChannel, recv_socket: &StunChannel) {
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
        let recv1 = recv_data(recv_socket);
        let recv2 = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket
            .send(DataRefAddress::from(&data, to))
            .await
            .unwrap();
        let result = recv1.await;
        assert_eq!(result.data, data);
        assert_eq!(result.address, from);
        let result = recv2.await;
        assert_eq!(result.data, data);
        assert_eq!(result.address, from);
    }

    #[test]
    fn send_multi_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::stun::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::stun::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(&socket_channel1, &socket_channel2).await;
        });
    }

    #[test]
    fn send_multi_recv_with_drop() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::stun::socket::tests::setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = crate::stun::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = StunChannel::Udp(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = StunChannel::Udp(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(&socket_channel1, &socket_channel2).await;

            // previous receivers should have been dropped as not connected anymore
            // XXX: doesn't currently test the actual drop just that nothing errors
            send_and_receive(&socket_channel1, &socket_channel2).await;
        });
    }

    #[test]
    fn send_udp_request_unanswered() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::stun::socket::tests::setup_udp_channel().await;
            let udp2 = crate::stun::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();
            let clock = Arc::new(crate::clock::tests::TestClock::default());

            let agent = StunAgent::builder(StunChannel::Udp(UdpConnectionChannel::new(udp1, to)))
                .clock(clock.clone())
                .build();

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap())
                .unwrap();
            msg.add_fingerprint().unwrap();

            let start = clock.now();
            let f = task::spawn(async move {
                agent
                    .stun_request_transaction(&msg, to)
                    .unwrap()
                    .build()
                    .unwrap()
                    .perform()
                    .await
            });

            // ensure that the request is waiting on at least something
            clock.advance().await;

            // advance past any timeouts
            clock.set_time(start + Duration::from_secs(120)).await;

            assert!(matches!(f.await, Err(StunError::TimedOut)));
        });
    }

    #[test]
    fn send_udp_request_unanswered_cancelled() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = crate::stun::socket::tests::setup_udp_channel().await;
            let udp2 = crate::stun::socket::tests::setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();
            let clock = Arc::new(crate::clock::tests::TestClock::default());

            let agent = StunAgent::builder(StunChannel::Udp(UdpConnectionChannel::new(udp1, to)))
                .clock(clock.clone())
                .build();

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap())
                .unwrap();
            msg.add_fingerprint().unwrap();

            let transaction = agent
                .stun_request_transaction(&msg, to)
                .unwrap()
                .build()
                .unwrap();
            let f = task::spawn({
                let transaction = transaction.clone();
                async move { transaction.perform().await }
            });

            // first retrieve both waits so that we don't race setting up a new sender delay wait
            // with retrieving the receive timeout wait
            let sender_delay = clock.next_entry().await;
            let receiver_timeout = clock.next_entry().await;
            transaction.cancel_retransmissions();
            // advance through the sender wait, there should be no more sender-initiated waits after this
            sender_delay.advance().await;
            // advance to the receiver timeout
            receiver_timeout.advance().await;
            assert!(matches!(f.await, Err(StunError::TimedOut)));
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
            let tcp2 = tcp2.await.unwrap().unwrap();
            let tcp1 = tcp1.await.unwrap();

            let socket_channel1 = StunChannel::Tcp(TcpChannel::new(tcp1));
            let socket_channel2 = StunChannel::Tcp(TcpChannel::new(tcp2));

            send_and_receive(&socket_channel1, &socket_channel2).await;
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
            let agent = StunAgent::new(StunChannel::Tcp(TcpChannel::new(tcp2)));

            let software_str = "ab";
            let mut msg = Message::new_request(48);
            msg.add_attribute(Software::new(software_str).unwrap())
                .unwrap();
            msg.add_fingerprint().unwrap();
            let mut bytes = vec![0; 2];
            let msg_bytes = msg.to_bytes();
            let msg_bytes_len = msg_bytes.len() as u16;
            bytes.extend(msg_bytes);
            BigEndian::write_u16(&mut bytes, msg_bytes_len);
            let mut msg = Message::new_request(32);
            let software_str2 = "AB";
            msg.add_attribute(Software::new(software_str2).unwrap())
                .unwrap();
            let curr_idx = bytes.len();
            bytes.extend([0; 2]);
            let msg_bytes = msg.to_bytes();
            let msg_bytes_len = msg_bytes.len() as u16;
            bytes.extend(msg_bytes);
            BigEndian::write_u16(&mut bytes[curr_idx..], msg_bytes_len);

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
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _)));
            let (stun_msg, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str);

            let stun_or_data = receive_stream.next().await.unwrap();
            info!("received2");
            assert!(matches!(stun_or_data, StunOrData::Stun(_, _)));
            let (stun_msg, from) = stun_or_data.stun().unwrap();
            assert_eq!(from, addr2);
            let attr: Software = stun_msg.attribute(SOFTWARE).unwrap();
            assert_eq!(attr.software(), software_str2);
        });
    }

    pub async fn async_stund(
        channel: AsyncChannel,
        start_notify: async_channel::Sender<()>,
    ) -> Result<(), std::io::Error> {
        let stun_agent = StunAgent::new(StunChannel::AsyncChannel(channel));
        stund::handle_stun(stun_agent, start_notify).await
    }

    mod stund {
        use crate::agent::*;
        use crate::stun::agent::*;
        use std::net::SocketAddr;

        fn warn_on_err<T, E>(res: Result<T, E>, default: T) -> T
        where
            E: std::fmt::Display,
        {
            match res {
                Ok(v) => v,
                Err(e) => {
                    warn!("{}", e);
                    default
                }
            }
        }

        pub(crate) fn handle_binding_request(
            msg: &Message,
            from: SocketAddr,
        ) -> Result<Message, AgentError> {
            if let Some(error_msg) = Message::check_attribute_types(msg, &[FINGERPRINT], &[]) {
                return Ok(error_msg);
            }

            let mut response = Message::new_success(msg);
            response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
            response.add_fingerprint()?;
            Ok(response)
        }

        pub async fn handle_stun(
            stun_agent: StunAgent,
            start_notify: async_channel::Sender<()>,
        ) -> std::io::Result<()> {
            let mut receive_stream = stun_agent.receive_stream();
            start_notify.send(()).await.unwrap();

            let channel = stun_agent.channel();
            let addr = channel.local_addr()?;

            debug!("starting stun server at {}", addr);
            while let Some(stun_or_data) = receive_stream.next().await {
                match stun_or_data {
                    StunOrData::Data(data, from) => {
                        info!("received from {} data: {:?}", from, data)
                    }
                    StunOrData::Stun(msg, from) => {
                        info!("received from {}: {}", from, msg);
                        if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                            match handle_binding_request(&msg, from) {
                                Ok(response) => {
                                    info!("sending response to {}: {}", from, response);
                                    /* XXX: probably want a explicity vfunc/check for this rather than relying on
                                     * th error */
                                    match channel.remote_addr() {
                                        Ok(_) => warn_on_err(stun_agent.send(response).await, ()),
                                        Err(_) => warn_on_err(
                                            stun_agent.send_to(response, from).await,
                                            (),
                                        ),
                                    }
                                }
                                Err(err) => warn!("error: {}", err),
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    }

    async fn async_find_public_ip(send_agent: &StunAgent, stund_addr: SocketAddr) -> SocketAddr {
        let mut msg = Message::new_request(BINDING);
        msg.add_fingerprint().unwrap();
        let (response, _from) = send_agent
            .stun_request_transaction(&msg, stund_addr)
            .unwrap()
            .build()
            .unwrap()
            .perform()
            .await
            .unwrap();
        response
            .attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS)
            .unwrap()
            .addr(response.transaction_id())
    }

    async fn async_prime_stun(
        send_agent: &StunAgent,
        remote_addr: SocketAddr,
        receive_agent: &StunAgent,
    ) {
        let mut recv_stream = receive_agent.receive_stream();
        let receive_agent = receive_agent.clone();
        let (tx, mut rx) = async_channel::bounded(1);
        let recv_data = task::spawn(async move {
            tx.send(()).await.unwrap();
            if let Some(stun_or_data) = recv_stream.next().await {
                let (msg, from) = stun_or_data.stun().unwrap();
                if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                    let response = stund::handle_binding_request(&msg, from).unwrap();
                    receive_agent.send_to(response.clone(), from).await.unwrap();
                }
            }
        });
        rx.next().await.unwrap();

        let mut msg = Message::new_request(BINDING);
        msg.add_fingerprint().unwrap();
        let (_response, _from) = send_agent
            .stun_request_transaction(&msg, remote_addr)
            .unwrap()
            .build()
            .unwrap()
            .perform()
            .await
            .unwrap();
        recv_data.await;
    }

    #[test]
    fn async_router_double_nat_stund() {
        init();
        task::block_on(async move {
            let public_router = async_public_router();
            let nat1_router = async_nat_router(public_router.clone());
            let local_host = nat1_router.add_host();
            let local = local_host.new_channel(None);
            let local_agent = StunAgent::new(StunChannel::AsyncChannel(local.clone()));
            let nat2_router = {
                let start_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 20, 4));
                let end_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 20, 40));
                ChannelRouter::builder()
                    .allocate_range(start_ip, end_ip)
                    .gateway(public_router.clone())
                    .build()
            };
            let remote_host = nat2_router.add_host();
            let remote = remote_host.new_channel(None);
            let remote_agent = StunAgent::new(StunChannel::AsyncChannel(remote.clone()));
            let stund_host = public_router.add_host();
            let stund_channel = stund_host.new_channel(None);
            let stund_addr = stund_channel.local_addr().unwrap();
            let (tx, mut rx) = async_channel::bounded(1);
            let stund_join =
                task::spawn(async move { async_stund(stund_channel, tx.clone()).await });
            rx.next().await.unwrap();

            let local_public_addr = async_find_public_ip(&local_agent, stund_addr).await;
            info!("found local public ip addr {local_public_addr:?}");

            let remote_public_addr = async_find_public_ip(&remote_agent, stund_addr).await;
            info!("found remote public ip addr {remote_public_addr:?}");

            // prime remote stun agent with a stun message to allow further data
            async_prime_stun(&local_agent, remote_public_addr, &remote_agent).await;
            info!("remote stun agent has validated local peer");

            // prime local stun agent with a stun message to allow further data
            async_prime_stun(&remote_agent, local_public_addr, &local_agent).await;
            info!("local stun agent has validated remote peer");

            // actually send the data
            send_to_address_and_receive(
                StunChannel::AsyncChannel(local.clone()),
                remote_public_addr,
                StunChannel::AsyncChannel(remote.clone()),
                false,
            )
            .await;
            send_to_address_and_receive(
                StunChannel::AsyncChannel(remote),
                local_public_addr,
                StunChannel::AsyncChannel(local),
                false,
            )
            .await;
            stund_join.cancel().await;
        });
    }
}
