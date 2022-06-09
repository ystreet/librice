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
use tracing_futures::Instrument;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};

use crate::stun::message::{Message, MessageType};
use crate::utils::{ChannelBroadcast, DebugWrapper};

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

#[derive(Debug, Clone)]
pub enum StunChannel {
    UdpAny(UdpSocketChannel),
    Udp(UdpConnectionChannel),
    Tcp(TcpChannel),
    #[cfg(test)]
    AsyncChannel(tests::AsyncChannel),
}

#[derive(Debug, Clone)]
pub struct DataAddress {
    pub data: Vec<u8>,
    pub address: SocketAddr,
}

impl DataAddress {
    fn new(data: Vec<u8>, address: SocketAddr) -> Self {
        Self { data, address }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DataRefAddress<'data> {
    pub(crate) data: &'data [u8],
    pub(crate) address: SocketAddr,
}

impl<'data> DataRefAddress<'data> {
    pub(crate) fn from(data: &[u8], address: SocketAddr) -> DataRefAddress {
        DataRefAddress { data, address }
    }
}

pub trait SocketAddresses {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error>;
    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error>;
}

#[derive(Debug, Clone)]
pub struct UdpSocketChannel {
    socket: DebugWrapper<Arc<UdpSocket>>,
    pub(crate) sender_broadcast: Arc<ChannelBroadcast<DataAddress>>,
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
    async fn receive_loop(socket: Arc<UdpSocket>, broadcaster: Arc<ChannelBroadcast<DataAddress>>) {
        // stream that continuosly reads from a udp socket
        let stream = futures::stream::unfold(socket, |socket| async move {
            let mut data = vec![0; 1500];
            socket.recv_from(&mut data).await.ok().map(|(len, from)| {
                data.truncate(len);
                (DataAddress::new(data, from), socket)
            })
        });
        futures::pin_mut!(stream);

        debug!("loop starting");
        // send data to the receive channels
        while let Some(res) = stream.next().await {
            //trace!("have {:?}", res);
            broadcaster.broadcast(res).await;
        }
        debug!("loop exited");
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        trace!("socket channel send_to {:?} bytes to {:?}", data.len(), to);
        self.socket.send_to(data, to).await?;
        Ok(())
    }

    pub(crate) fn ensure_receive_loop(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.receive_loop.is_none() {
            let span = debug_span!("udp_recv_loop");
            inner.receive_loop = Some(async_std::task::spawn({
                let socket = (*self.socket).clone();
                let broadcaster = self.sender_broadcast.clone();
                async move { UdpSocketChannel::receive_loop(socket, broadcaster).await }
                    .instrument(span.or_current())
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
pub(crate) struct MutUdpMessage<'a> {
    pub(crate) addr: SocketAddr,
    pub(crate) data: &'a mut [u8],
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataRefAddress<'msg>> for UdpSocketChannel {
    async fn send<'udp>(&self, msg: DataRefAddress<'udp>) -> Result<(), std::io::Error> {
        trace!(
            "socket channel send {:?} bytes to {:?}",
            msg.data.len(),
            msg.address
        );
        self.send_to(msg.data, msg.address).await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataFraming<'msg>> for UdpSocketChannel {
    async fn send<'udp>(&self, msg: DataFraming<'udp>) -> Result<(), std::io::Error> {
        trace!(
            "socket channel send {:?} bytes to {:?}",
            msg.data.len(),
            msg.address
        );
        self.send_to(msg.data, msg.address).await
    }
}

#[async_trait]
impl<'msg> SocketMessageRecv<MutUdpMessage<'msg>, usize> for UdpSocketChannel {
    async fn max_recv_size(&self) -> Result<usize, std::io::Error> {
        Ok(65535)
    }

    async fn recv<'udp>(&self, msg: &'udp mut MutUdpMessage) -> Result<usize, std::io::Error> {
        let (length, from) = self.socket.recv_from(msg.data).await?;
        msg.addr = from;
        Ok(length)
    }
}

impl ReceiveStream<DataAddress> for UdpSocketChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = DataAddress> + Send>> {
        let channel = self.sender_broadcast.channel();
        self.ensure_receive_loop();
        Box::pin(channel)
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
impl<'msg> SocketMessageSend<'msg, DataRefAddress<'msg>> for StunChannel {
    async fn send<'stun>(&self, msg: DataRefAddress<'stun>) -> Result<(), std::io::Error> {
        match self {
            StunChannel::UdpAny(c) => c.send(msg).await,
            StunChannel::Udp(c) => c.send(msg).await,
            StunChannel::Tcp(c) => c.send(msg).await,
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.send(msg).await,
        }
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataFraming<'msg>> for StunChannel {
    async fn send<'data>(&self, msg: DataFraming<'data>) -> Result<(), std::io::Error> {
        match self {
            StunChannel::UdpAny(c) => c.send(msg).await,
            StunChannel::Udp(c) => c.send(msg).await,
            StunChannel::Tcp(c) => c.send(msg).await,
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.send(msg).await,
        }
    }
}

impl ReceiveStream<DataAddress> for StunChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = DataAddress> + Send>> {
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

impl ReceiveStream<DataAddress> for UdpConnectionChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = DataAddress> + Send>> {
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
                .filter_map(move |data_address| async move {
                    if data_address.address == to {
                        trace!(
                            "passing through message of {} bytes from {:?}",
                            data_address.data.len(),
                            data_address.address
                        );
                        Some(data_address)
                    } else {
                        trace!(
                            "filtered message out as {:?} != {:?}",
                            data_address.address,
                            to
                        );
                        None
                    }
                }),
        )
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataRefAddress<'msg>> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: DataRefAddress<'udp>) -> Result<(), std::io::Error> {
        if msg.address != self.to {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Address to send to is different from connected address",
            ));
        }
        debug!(
            "socket connection send {} bytes to {:?}",
            msg.data.len(),
            msg.address
        );
        self.channel.send(msg).await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataFraming<'msg>> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: DataFraming<'udp>) -> Result<(), std::io::Error> {
        self.send(DataRefAddress::from(msg.data, self.to)).await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, &'msg [u8]> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: &'udp [u8]) -> Result<(), std::io::Error> {
        let msg = DataRefAddress {
            data: msg,
            address: self.to,
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
pub struct TcpChannel {
    stream: DebugWrapper<TcpStream>,
    running_buffer: Arc<Mutex<Option<TcpBuffer>>>,
}

impl TcpChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: DebugWrapper::wrap(stream, "..."),
            running_buffer: Arc::new(Mutex::new(Some(TcpBuffer::new(MAX_STUN_MESSAGE_SIZE)))),
        }
    }

    #[tracing::instrument(
        name = "tcp_single_recv",
        skip(stream, running),
        fields(
            remote.addr = ?stream.peer_addr()
        )
    )]
    async fn inner_recv(
        stream: &mut TcpStream,
        running: Arc<Mutex<Option<TcpBuffer>>>,
    ) -> Result<DataAddress, std::io::Error> {
        let from = stream.peer_addr()?;
        let mut buf = running.lock().unwrap().take().ok_or_else(|| {
            warn!("Unsupported: multiple calls to recv()");
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Unsupported: multiple calls to recv()",
            )
        })?;

        while let Ok(size) = stream.read(buf.ref_mut()).await {
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
            //trace!("buf {:?}", buf.peek());
            let data_length = if buf.len() >= 2 {
                (BigEndian::read_u16(&buf.buf[..2]) as usize) + 2
            } else {
                usize::MAX
            };

            let mut may_be_stun = false;
            let mlength = {
                let mut ret = usize::MAX;
                if buf.len() >= 20 {
                    let tid = BigEndian::read_u128(&buf.buf[4..]);
                    let cookie = (tid >> 96) as u32;
                    let data = buf.peek();

                    // first two bits are always 0 for stun and the cookie value must match
                    if MessageType::from_bytes(data).is_ok()
                        && cookie == crate::stun::message::MAGIC_COOKIE
                    {
                        // XXX: use fingerprint if it exists
                        ret = (BigEndian::read_u16(&data[2..4]) as usize) + 20;
                        may_be_stun = true;
                    }
                }
                ret
            };

            let min_length = data_length.min(mlength);
            if min_length > buf.len() {
                debug!(
                    "not enough data, buf length {} less than smallest advertised size {}, reading again",
                    buf.len(),
                    min_length
                );
                continue;
            }

            if may_be_stun {
                match Message::from_bytes(&buf.buf[..mlength]) {
                    Ok(msg) => {
                        trace!("detected a stun message {}", msg);
                        let bytes = buf.take(mlength);
                        *running.lock().unwrap() = Some(buf);
                        return Ok(DataAddress::new(bytes.to_vec(), from));
                    }
                    Err(e) => debug!("failed to parse STUN message: {:?}", e),
                }
            } else if data_length <= buf.len() {
                buf.take(2);
                let bytes = buf.take(data_length - 2);
                return Ok(DataAddress::new(bytes.to_vec(), from));
            }
        }
        debug!("no more data");
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "No more data",
        ))
    }
}

impl SocketAddresses for TcpChannel {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.peer_addr()
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataRefAddress<'msg>> for TcpChannel {
    async fn send<'udp>(&self, msg: DataRefAddress<'udp>) -> Result<(), std::io::Error> {
        if msg.address != self.remote_addr()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Address to send to is different from connected address",
            ));
        }
        let mut stream = self.stream.clone();
        stream.write_all(msg.data).await
    }
}

// Framing as specified in RFC4571 (when used with TCP)
//
// 16-bit length in network order (big-endian) followed by the data. The value of length does not
// include the length field.
#[derive(Debug)]
pub(crate) struct DataFraming<'data> {
    data: &'data [u8],
    address: SocketAddr,
}

impl<'data> DataFraming<'data> {
    pub(crate) fn from(data: &[u8], address: SocketAddr) -> DataFraming {
        DataFraming { data, address }
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, DataFraming<'msg>> for TcpChannel {
    async fn send<'udp>(&self, msg: DataFraming<'udp>) -> Result<(), std::io::Error> {
        if msg.address != self.remote_addr()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Address to send to is different from connected address",
            ));
        }

        if msg.data.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data length too large for transport",
            ));
        }

        let mut stream = self.stream.clone();
        let mut len_bytes = [0; 2];
        BigEndian::write_u16(&mut len_bytes, msg.data.len() as u16);
        // XXX: may need to check this will not be interpreted as STUN and reject the send
        stream.write_all(&len_bytes).await?;
        stream.write_all(msg.data).await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, &'msg [u8]> for TcpChannel {
    async fn send<'rtp>(&self, msg: &'rtp [u8]) -> Result<(), std::io::Error> {
        let framed = DataFraming::from(msg, self.remote_addr()?);
        self.send(framed).await
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

    fn peek(&self) -> &[u8] {
        &*self.buf
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
impl SocketMessageRecv<(), DataAddress> for TcpChannel {
    async fn max_recv_size(&self) -> Result<usize, std::io::Error> {
        Ok(1)
    }

    async fn recv<'b>(&self, _msg: &'b mut ()) -> Result<DataAddress, std::io::Error> {
        let mut stream = self.stream.clone();
        let running = self.running_buffer.clone();
        TcpChannel::inner_recv(&mut stream, running).await
    }
}

impl ReceiveStream<DataAddress> for TcpChannel {
    fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = DataAddress> + Send>> {
        let stream = self.stream.clone();
        let running = self.running_buffer.clone();
        // replace self.running_buffer when done? drop handler?
        let span = debug_span!("tcp_recv");
        Box::pin(
            stream::unfold((stream, running), |(mut stream, running)| async move {
                TcpChannel::inner_recv(&mut stream, running.clone())
                    .await
                    .ok()
                    .map(|v| (v, (stream, running)))
            })
            .instrument(span.or_current()),
        )
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
        channels: std::collections::HashMap<SocketAddr, Arc<ChannelBroadcast<DataAddress>>>,
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

        fn receiver(&self, addr: SocketAddr) -> impl Stream<Item = DataAddress> {
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

        async fn send(&self, msg: DataAddress, from: SocketAddr) -> Result<(), AgentError> {
            let broadcast = {
                let inner = self.inner.lock().unwrap();
                //trace!("send channels {:?}", inner.channels);
                inner
                    .channels
                    .get(&msg.address)
                    .ok_or(AgentError::ResourceNotFound)?
                    .clone()
            };
            let msg = DataAddress::new(msg.data, from);
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
    impl<'msg> SocketMessageSend<'msg, DataRefAddress<'msg>> for AsyncChannel {
        async fn send<'udp>(&self, msg: DataRefAddress<'udp>) -> Result<(), std::io::Error> {
            if let Some(peer_addr) = self.peer_addr {
                if msg.address != peer_addr {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Implementation not available",
                    ));
                }
            }
            let msg = DataAddress::new(msg.data.to_vec(), msg.address);

            self.router.send(msg, self.addr).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Channel failed to send",
                )
            })?;
            Ok(())
        }
    }

    #[async_trait]
    impl<'msg> SocketMessageSend<'msg, DataFraming<'msg>> for AsyncChannel {
        async fn send<'udp>(&self, msg: DataFraming<'udp>) -> Result<(), std::io::Error> {
            self.send(DataRefAddress::from(msg.data, msg.address)).await
        }
    }

    impl ReceiveStream<DataAddress> for AsyncChannel {
        fn receive_stream(&self) -> Pin<Box<dyn Stream<Item = DataAddress> + Send>> {
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

    fn recv_data(channel: UdpSocketChannel) -> impl Future<Output = DataAddress> {
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
        assert_eq!(result.data, data);
        assert_eq!(result.address, from);
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
