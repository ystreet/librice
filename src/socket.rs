// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_std::net::{TcpStream, UdpSocket};

use futures::prelude::*;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};

use crate::stun::message::Message;
use crate::utils::{ChannelBroadcast, DebugWrapper};

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

#[derive(Debug, Clone)]
pub enum StunChannel {
    UdpAny(UdpSocketChannel),
    Udp(UdpConnectionChannel),
    Tcp(StunOnlyTcpChannel),
    #[cfg(test)]
    AsyncChannel(tests::AsyncChannel),
}

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
    pub fn addr(&self) -> SocketAddr {
        match self {
            StunOrData::Stun(_msg, _data, addr) => *addr,
            StunOrData::Data(_data, addr) => *addr,
        }
    }
}

pub trait SocketAddresses {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error>;
    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error>;
}

#[derive(Debug, Clone)]
pub struct UdpSocketChannel {
    socket: DebugWrapper<Arc<UdpSocket>>,
    pub(crate) sender_broadcast: Arc<ChannelBroadcast<(Vec<u8>, SocketAddr)>>,
    inner: DebugWrapper<Arc<Mutex<UdpSocketChannelInner>>>,
}

#[derive(Debug)]
struct UdpSocketChannelInner {
    receive_loop: Option<async_std::task::JoinHandle<()>>,
}

impl UdpSocketChannelInner {}

impl UdpSocketChannel {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: DebugWrapper::wrap(Arc::new(socket), "..."),
            sender_broadcast: Arc::new(ChannelBroadcast::default()),
            inner: DebugWrapper::wrap(
                Arc::new(Mutex::new(UdpSocketChannelInner { receive_loop: None })),
                "...",
            ),
        }
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        (*self.socket).clone()
    }

    #[tracing::instrument(
        name = "udp_receive_loop",
        level = "debug",
        skip(socket, broadcaster)
        fields(
            local_addr = ?socket.local_addr(),
        )
    )]
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        broadcaster: Arc<ChannelBroadcast<(Vec<u8>, SocketAddr)>>,
    ) {
        // stream that continuosly reads from a udp socket
        let stream = futures::stream::unfold(socket, |socket| async move {
            let mut data = vec![0; 1500];
            socket.recv_from(&mut data).await.ok().map(|(len, from)| {
                data.truncate(len);
                ((data, from), socket)
            })
        });
        futures::pin_mut!(stream);

        debug!("loop starting");
        // send data to the receive channels
        while let Some(res) = stream.next().await {
            trace!("have {:?}", res);
            broadcaster.broadcast(res).await;
        }
        trace!("loop exited");
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        debug!("socket channel send_to {:?}, {:?}", data, to);
        self.socket.send_to(data, to).await?;
        Ok(())
    }

    pub(crate) fn ensure_receive_loop(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.receive_loop.is_none() {
            inner.receive_loop = Some(async_std::task::spawn({
                let socket = (*self.socket).clone();
                let broadcaster = self.sender_broadcast.clone();
                async move { UdpSocketChannel::receive_loop(socket, broadcaster).await }
            }));
        }
    }
}

impl SocketAddresses for UdpSocketChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Connection-less UDP socket doesn't have a remote address",
        ))
    }
}

#[derive(Debug)]
pub(crate) struct UdpMessage<'a> {
    pub(crate) addr: SocketAddr,
    pub(crate) data: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct MutUdpMessage<'a> {
    pub(crate) addr: SocketAddr,
    pub(crate) data: &'a mut [u8],
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, UdpMessage<'msg>> for UdpSocketChannel {
    async fn send<'udp>(&self, msg: UdpMessage<'udp>) -> Result<(), std::io::Error> {
        debug!("socket channel send {:?}", msg);
        self.send_to(msg.data, msg.addr).await
    }
}

#[async_trait]
impl<'msg> SocketMessageRecv<MutUdpMessage<'msg>, usize> for UdpSocketChannel {
    async fn max_recv_size(&self) -> Result<usize, std::io::Error> {
        Ok(65535)
    }

    async fn recv<'udp>(&self, msg: &'udp mut MutUdpMessage) -> Result<usize, std::io::Error> {
        let (length, from) = self.socket.recv_from(&mut msg.data).await?;
        msg.addr = from;
        Ok(length)
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, StunOrData> for UdpSocketChannel {
    async fn send<'udp>(&self, msg: StunOrData) -> Result<(), std::io::Error> {
        debug!("socket channel send {:?}", msg);
        match msg {
            StunOrData::Data(_data, _to) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot send data over a connectionless stun-only UDP socket",
            )),
            StunOrData::Stun(msg, _data, addr) => {
                let msg = UdpMessage {
                    addr,
                    data: &msg.to_bytes(),
                };
                self.send(msg).await
            }
        }
    }
}

impl ReceiveStream<StunOrData> for UdpSocketChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = StunOrData> + Send>> {
        let channel = self.sender_broadcast.channel();
        self.ensure_receive_loop();
        Box::pin(channel.filter_map(|(data, from)| async move {
            match Message::from_bytes(&data) {
                Ok(msg) => Some(StunOrData::Stun(msg, data, from)),
                // can we potentially get out-of-bounds data before things are set up?
                Err(_) => Some(StunOrData::Data(data, from)),
            }
        }))
    }
}

impl ReceiveStream<(Vec<u8>, SocketAddr)> for UdpSocketChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = (Vec<u8>, SocketAddr)> + Send>> {
        let channel = self.sender_broadcast.channel();
        self.ensure_receive_loop();
        debug!("retrieve socket channel stream {:?}", self.local_addr());
        Box::pin(channel)
    }
}

#[derive(Debug, Clone)]
pub struct TcpChannel {
    channel: TcpStream,
    sender_broadcast: Arc<ChannelBroadcast<Vec<u8>>>,
    inner: Arc<Mutex<TcpChannelInner>>,
    write_lock: Arc<async_std::sync::Mutex<()>>,
}

#[derive(Debug)]
struct TcpChannelInner {
    receive_loop: Option<async_std::task::JoinHandle<()>>,
}

impl TcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            channel: stream,
            sender_broadcast: Arc::new(ChannelBroadcast::default()),
            inner: Arc::new(Mutex::new(TcpChannelInner { receive_loop: None })),
            write_lock: Arc::new(async_std::sync::Mutex::new(())),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.local_addr()
    }

    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.peer_addr()
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        let mut written = 0;
        let mut channel = self.channel.clone();
        let _write_lock = self.write_lock.lock().await;
        while written < data.len() {
            written += channel.write(&data[written..]).await?;
        }
        Ok(())
    }

    fn ensure_receive_loop(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.receive_loop.is_none() {
            inner.receive_loop = Some(async_std::task::spawn({
                let socket = self.channel.clone();
                let broadcaster = self.sender_broadcast.clone();
                async move { TcpChannel::receive_loop(socket, broadcaster).await }
            }));
        }
    }

    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        self.ensure_receive_loop();
        self.sender_broadcast.channel()
    }

    #[tracing::instrument(
        name = "tcp_receive_loop",
        level = "debug",
        skip(stream, broadcaster)
        fields(
            local_addr = ?stream.local_addr(),
            remote_addr = ?stream.peer_addr(),
        )
    )]
    async fn receive_loop(stream: TcpStream, broadcaster: Arc<ChannelBroadcast<Vec<u8>>>) {
        futures::pin_mut!(stream);
        let mut scratch = vec![0; 2048];

        trace!("loop starting");
        // send data to the receive channels
        while let Some(size) = stream.read(&mut scratch).await.ok() {
            if size == 0 {
                // connection was closed
                break;
            }
            broadcaster.broadcast(scratch[..size].to_vec()).await;
            scratch.iter_mut().map(|v| *v = 0).count();
        }
        trace!("loop exited");
    }
}

impl SocketAddresses for TcpChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.peer_addr()
    }
}

#[async_trait]
pub trait SocketMessageSend<T, 'a>
where
    T: Send + std::fmt::Debug + 'a,
{
    async fn send<'b>(&self, msg: T) -> Result<(), std::io::Error>
    where
        T: 'b;
}

#[async_trait]
pub(crate) trait SocketMessageRecv<T, R>
where
    T: Send + std::fmt::Debug,
    R: Send + std::fmt::Debug,
{
    async fn max_recv_size(&self) -> Result<usize, std::io::Error>;
    async fn recv<'b>(&self, msg: &'b mut T) -> Result<R, std::io::Error>
    where
        T: 'b;
}

pub(crate) trait ReceiveStream<T> {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = T> + Send>>;
}

impl StunChannel {}

impl SocketAddresses for StunChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            StunChannel::UdpAny(c) => c.local_addr(),
            StunChannel::Udp(c) => c.local_addr(),
            StunChannel::Tcp(c) => c.local_addr(),
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.local_addr(),
        }
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            StunChannel::UdpAny(_) => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "connection-less udp doesn't have a remote addr",
            )),
            StunChannel::Udp(c) => c.remote_addr(),
            StunChannel::Tcp(c) => c.remote_addr(),
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.remote_addr(),
        }
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, StunOrData> for StunChannel {
    async fn send<'stun>(&self, msg: StunOrData) -> Result<(), std::io::Error> {
        match self {
            StunChannel::UdpAny(c) => c.send(msg).await,
            StunChannel::Udp(c) => c.send(msg).await,
            StunChannel::Tcp(c) => match msg {
                StunOrData::Stun(msg, _data, _to) => c.send(msg).await,
                StunOrData::Data(_data, _to) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot send data over a Stun-only TCP connection",
                )),
            },
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.send(msg).await,
        }
    }
}

impl ReceiveStream<StunOrData> for StunChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = StunOrData> + Send>> {
        debug!("stun channel receive stream for {:?}", self);
        match self {
            StunChannel::UdpAny(c) => c.receive_stream(),
            StunChannel::Udp(c) => c.receive_stream(),
            StunChannel::Tcp(c) => c.receive_stream(),
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.receive_stream(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpConnectionChannel {
    channel: UdpSocketChannel,
    to: SocketAddr,
}

impl UdpConnectionChannel {
    pub fn new(channel: UdpSocketChannel, to: SocketAddr) -> Self {
        Self { channel, to }
    }
}

impl SocketAddresses for UdpConnectionChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.to)
    }
}

impl ReceiveStream<StunOrData> for UdpConnectionChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = StunOrData> + Send>> {
        let channel = self.channel.clone();
        let to = self.to;
        trace!(
            "retrieving receive_stream for connection channel from {:?}, to {:?}",
            channel.local_addr(),
            to
        );
        Box::pin(
            channel
                .receive_stream()
                .filter_map(move |(data, from)| async move {
                    if from == to {
                        trace!("passing through message {:?} {:?}", from, data);
                        Some(match Message::from_bytes(&data) {
                            Ok(msg) => StunOrData::Stun(msg, data, from),
                            Err(_) => StunOrData::Data(data, from),
                        })
                    } else {
                        trace!("filtered message out {:?} {:?}", from, to);
                        None
                    }
                }),
        )
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, StunOrData> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: StunOrData) -> Result<(), std::io::Error> {
        let bytes = match msg {
            StunOrData::Stun(msg, _data, _addr) => msg.to_bytes(),
            StunOrData::Data(data, _addr) => data,
        };
        let msg = UdpMessage {
            data: &bytes,
            addr: self.to,
        };
        debug!("socket connection send {:?}", msg);
        self.channel.send(msg).await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, &'msg [u8]> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: &'udp [u8]) -> Result<(), std::io::Error> {
        let msg = UdpMessage {
            data: msg,
            addr: self.to,
        };
        self.channel.send(msg).await
    }
}

/*
#[async_trait]
impl<'msg> SocketMessageRecv<'msg> for UdpConnectionChannel
{
    type Message = &'msg [u8];

    async fn max_recv_size(&self) -> Result<usize, std::io::Error> {
        Ok(65535)
    }

    async fn recv (&self, msg: &'async_trait mut Self::Message) -> Result<usize, std::io::Error> {
        let (length, from) = self.socket.recv_from(&mut msg.data).await?;
        msg.addr = from;
        Ok(length)
    }
}
*/
#[derive(Debug, Clone)]
pub struct StunOnlyTcpChannel {
    stream: DebugWrapper<TcpStream>,
    running_buffer: Arc<Mutex<Option<TcpBuffer>>>,
}

impl StunOnlyTcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: DebugWrapper::wrap(stream, "..."),
            running_buffer: Arc::new(Mutex::new(Some(TcpBuffer::new(MAX_STUN_MESSAGE_SIZE)))),
        }
    }

    #[tracing::instrument(
        name = "tcp_recv",
        err,
        skip(stream, running),
        fields(
            remote.addr = ?stream.peer_addr()
        )
    )]
    async fn inner_recv(
        stream: &mut TcpStream,
        running: Arc<Mutex<Option<TcpBuffer>>>,
    ) -> Result<StunOrData, std::io::Error> {
        let from = stream.peer_addr()?;
        let mut buf = running.lock().unwrap().take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Unsupported: multiple calls to recv()",
            )
        })?;

        // If only stun is being sent over this connection, then we can figure out lengths
        // ourselves but do need to buffer incoming data as required
        while let Some(size) = stream.read(buf.ref_mut()).await.ok() {
            trace!("recved {} bytes", size);
            buf.read_size(size);
            if size == 0 {
                info!("connection closed");
                *running.lock().unwrap() = Some(buf);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "TCP connection closed",
                ));
            }
            trace!("buf {:?}", buf);
            // we need to buffer up until we have enough data for each STUN
            // message. This assumes that no other data is being sent over
            // this socket
            if buf.len() < 20 {
                trace!(
                    "not enough data, buf length {} too short (< 20), reading again",
                    buf.len()
                );
                continue;
            } else {
                let mlength = BigEndian::read_u16(&buf.buf[2..]) as usize;
                if mlength > MAX_STUN_MESSAGE_SIZE {
                    warn!(
                        "stun message length ({}) is absurd > {}, aborting read",
                        mlength, MAX_STUN_MESSAGE_SIZE
                    );
                    buf.take(buf.len());
                    break;
                }
                if mlength + 20 > buf.len() {
                    trace!(
                        "not enough data, buf length {} less than advertised size {}, reading again",
                        buf.len(),
                        mlength + 20
                    );
                    continue;
                }
                let bytes = buf.take(mlength + 20);
                trace!("have full message bytes {:?}", bytes);
                match Message::from_bytes(&bytes) {
                    Ok(msg) => {
                        trace!("have message bytes {}", msg);
                        *running.lock().unwrap() = Some(buf);
                        return Ok(StunOrData::Stun(msg, bytes.to_vec(), from));
                    }
                    Err(e) => debug!("failed to parse STUN message: {:?}", e),
                }
            }
        }
        debug!("no more data");
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "No more data",
        ))
    }
}

impl SocketAddresses for StunOnlyTcpChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.peer_addr()
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, Message> for StunOnlyTcpChannel {
    async fn send<'udp>(&self, msg: Message) -> Result<(), std::io::Error> {
        let mut stream = self.stream.clone();
        stream.write_all(&msg.to_bytes()).await
    }
}

#[derive(Debug)]
struct TcpBuffer {
    buf: DebugWrapper<Vec<u8>>,
    offset: usize,
}

impl TcpBuffer {
    fn new(size: usize) -> Self {
        Self {
            buf: DebugWrapper::wrap(vec![0; size], "..."),
            offset: 0,
        }
    }

    fn take(&mut self, offset: usize) -> Vec<u8> {
        if offset > self.buf.len() {
            return vec![];
        }
        let (data, _rest) = self.buf.split_at(offset);
        let data = data.to_vec();
        self.buf.drain(..offset);
        self.offset -= offset;
        self.buf.extend(&vec![0; offset]);
        data
    }

    fn ref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..]
    }

    fn read_size(&mut self, size: usize) {
        self.offset += size;
    }

    fn len(&self) -> usize {
        self.offset
    }
}

#[async_trait]
impl SocketMessageRecv<(), StunOrData> for StunOnlyTcpChannel {
    async fn max_recv_size(&self) -> Result<usize, std::io::Error> {
        Ok(1)
    }

    async fn recv<'b>(&self, _msg: &'b mut ()) -> Result<StunOrData, std::io::Error> {
        let mut stream = self.stream.clone();
        let running = self.running_buffer.clone();
        StunOnlyTcpChannel::inner_recv(&mut stream, running).await
    }
}

impl ReceiveStream<StunOrData> for StunOnlyTcpChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = StunOrData> + Send>> {
        let stream = self.stream.clone();
        let running = self.running_buffer.clone();
        // replace self.running_buffer when done? drop handler?
        warn!("tcp receive stream");
        Box::pin(stream::unfold(
            (stream, running),
            |(mut stream, running)| async move {
                StunOnlyTcpChannel::inner_recv(&mut stream, running.clone())
                    .await
                    .ok()
                    .map(|v| (v, (stream, running)))
            },
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::agent::AgentError;
    use async_std::task;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[derive(Debug, Clone)]
    pub struct ChannelRouter {
        inner: Arc<Mutex<ChannelRouterInner>>,
    }

    #[derive(Debug)]
    struct ChannelRouterInner {
        channels: std::collections::HashMap<SocketAddr, Arc<ChannelBroadcast<StunOrData>>>,
        last_generated_port: u16,
    }

    impl Default for ChannelRouter {
        fn default() -> Self {
            Self {
                inner: Arc::new(Mutex::new(ChannelRouterInner {
                    channels: Default::default(),
                    last_generated_port: 0,
                })),
            }
        }
    }

    impl ChannelRouter {
        fn add_channel(&self, addr: SocketAddr) {
            let mut inner = self.inner.lock().unwrap();
            debug!("adding channel {}", addr);
            match inner.channels.get(&addr) {
                Some(_) => unreachable!(),
                None => {
                    let recv = Arc::new(ChannelBroadcast::default());
                    inner.channels.insert(addr, recv);
                }
            }
        }

        fn receiver(&self, addr: SocketAddr) -> impl Stream<Item = StunOrData> {
            let mut inner = self.inner.lock().unwrap();
            match inner.channels.get(&addr) {
                Some(recv) => recv.clone(),
                None => {
                    let recv = Arc::new(ChannelBroadcast::default());
                    debug!("adding channel {}", addr);
                    inner.channels.insert(addr, recv.clone());
                    recv
                }
            }
            .channel()
        }

        async fn send(&self, msg: StunOrData, from: SocketAddr) -> Result<(), AgentError> {
            let (msg, to) = match msg {
                StunOrData::Stun(msg, _, to) => {
                    let bytes = msg.to_bytes();
                    (StunOrData::Stun(msg, bytes, from), to)
                }
                StunOrData::Data(data, to) => (StunOrData::Data(data, from), to),
            };
            let broadcast = {
                let inner = self.inner.lock().unwrap();
                error!("send channels {:?}", inner.channels);
                inner
                    .channels
                    .get(&to)
                    .ok_or(AgentError::ResourceNotFound)?
                    .clone()
            };
            broadcast.broadcast(msg).await;
            Ok(())
        }

        pub fn remove_addr(&self, addr: SocketAddr) {
            let mut inner = self.inner.lock().unwrap();
            debug!("removing channel {}", addr);
            inner.channels.remove(&addr);
        }

        pub fn generate_addr(&self) -> SocketAddr {
            let mut inner = self.inner.lock().unwrap();
            inner.last_generated_port += 1;
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                inner.last_generated_port,
            )
        }
    }

    #[derive(Debug, Clone)]
    pub struct AsyncChannel {
        router: ChannelRouter,
        addr: SocketAddr,
        peer_addr: Option<SocketAddr>,
    }

    impl AsyncChannel {
        pub fn new(router: ChannelRouter, addr: SocketAddr, peer_addr: Option<SocketAddr>) -> Self {
            let ret = Self {
                router: router.clone(),
                addr,
                peer_addr,
            };
            router.add_channel(addr);
            ret
        }
    }

    impl SocketAddresses for AsyncChannel {
        fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
            Ok(self.addr)
        }

        fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
            self.peer_addr.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "Implementation not available")
            })
        }
    }

    #[async_trait]
    impl<'msg> SocketMessageSend<'msg, StunOrData> for AsyncChannel {
        async fn send<'udp>(&self, msg: StunOrData) -> Result<(), std::io::Error> {
            if let Some(peer_addr) = self.peer_addr {
                if msg.addr() != peer_addr {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Implementation not available",
                    ));
                }
            }

            self.router.send(msg, self.addr).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Channel failed to send",
                )
            })?;
            Ok(())
        }
    }

    impl ReceiveStream<StunOrData> for AsyncChannel {
        fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = StunOrData> + Send>> {
            Box::pin(self.router.receiver(self.addr))
        }
    }

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn channel_addr_matches_socket() {
        init();
        task::block_on(async move {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let s1 = UdpSocket::bind(addr).await.unwrap();
            let from = s1.local_addr().unwrap();
            let channel = UdpSocketChannel::new(s1);
            assert_eq!(from, channel.local_addr().unwrap());
        })
    }

    pub(crate) async fn setup_udp_channel() -> UdpSocketChannel {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        UdpSocketChannel::new(socket)
    }

    fn recv_data(channel: UdpSocketChannel) -> impl Future<Output = (Vec<u8>, SocketAddr)> {
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

    async fn send_to_and_receive(send_socket: UdpSocketChannel, recv_socket: UdpSocketChannel) {
        let from = send_socket.local_addr().unwrap();
        let to = recv_socket.local_addr().unwrap();

        // send data and assert that it is received
        let recv = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket.send_to(&data.clone(), to).await.unwrap();
        let result = recv.await;
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
    }

    #[test]
    fn udp_channel_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let udp2 = setup_udp_channel().await;

            send_to_and_receive(udp1, udp2).await;
        });
    }
}
