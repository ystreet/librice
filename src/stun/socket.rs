// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_std::net::{TcpStream, UdpSocket};

use futures::prelude::*;
use tracing_futures::Instrument;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};

use crate::utils::{ChannelBroadcast, DebugWrapper};

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

#[derive(Debug)]
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
    closed: bool,
}

impl UdpSocketChannelInner {}

impl UdpSocketChannel {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: DebugWrapper::wrap(Arc::new(socket), "..."),
            sender_broadcast: Arc::new(ChannelBroadcast::default()),
            inner: DebugWrapper::wrap(
                Arc::new(Mutex::new(UdpSocketChannelInner {
                    receive_loop: None,
                    closed: false,
                })),
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
        {
            let inner = self.inner.lock().unwrap();
            if inner.closed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Connection closed",
                ));
            }
        }
        trace!("socket channel send_to {:?} bytes to {:?}", data.len(), to);
        self.socket.send_to(data, to).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        let join_handle = {
            let mut inner = self.inner.lock().unwrap();
            inner.closed = true;
            inner.receive_loop.take()
        };
        if let Some(join_handle) = join_handle {
            join_handle.cancel().await;
        }
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

impl StunChannel {
    pub async fn close(&self) -> Result<(), std::io::Error> {
        match self {
            StunChannel::UdpAny(c) => c.close().await,
            StunChannel::Udp(c) => c.close().await,
            StunChannel::Tcp(c) => c.close().await,
            #[cfg(test)]
            StunChannel::AsyncChannel(c) => c.close().await,
        }
    }
}

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

#[derive(Debug)]
pub struct UdpConnectionChannel {
    channel: UdpSocketChannel,
    to: SocketAddr,
    closed: AtomicBool,
}

impl UdpConnectionChannel {
    pub fn new(channel: UdpSocketChannel, to: SocketAddr) -> Self {
        Self {
            channel,
            to,
            closed: AtomicBool::new(false),
        }
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
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
        let to = self.to;
        trace!(
            "retrieving receive_stream for connection channel from {:?}, to {:?}",
            self.channel.local_addr(),
            to
        );
        Box::pin(
            self.channel
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
        if self.closed.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Connection closed",
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
        if self.closed.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Connection closed",
            ));
        }
        self.channel
            .send(DataRefAddress::from(msg.data, self.to))
            .await
    }
}

#[async_trait]
impl<'msg> SocketMessageSend<'msg, &'msg [u8]> for UdpConnectionChannel {
    async fn send<'udp>(&self, msg: &'udp [u8]) -> Result<(), std::io::Error> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Connection closed",
            ));
        }
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
            // need at least 2 bytes to read the length header
            if buf.len() < 2 {
                continue;
            }
            let data_length = (BigEndian::read_u16(&buf.buf[..2]) as usize) + 2;
            if buf.len() < data_length {
                trace!(
                    "not enough data, buf length {} data specifies length {}",
                    buf.len(),
                    data_length
                );
                continue;
            }

            if data_length <= buf.len() {
                let bytes = buf.take(data_length);
                *running.lock().unwrap() = Some(buf);
                return Ok(DataAddress::new(bytes[2..].to_vec(), from));
            }
        }
        debug!("no more data");
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "No more data",
        ))
    }

    pub async fn close(&self) -> Result<(), std::io::Error> {
        self.stream.shutdown(std::net::Shutdown::Both)
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
        self.send(DataFraming::from(msg.data, msg.address)).await
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Weak;

    pub struct ChannelRouterBuilder {
        start_ip: IpAddr,
        end_ip: IpAddr,
        gateway: Option<ChannelRouter>,
    }

    impl ChannelRouterBuilder {
        pub fn allocate_range(mut self, start: IpAddr, end: IpAddr) -> Self {
            self.start_ip = start;
            self.end_ip = end;
            self
        }

        pub fn gateway(mut self, gateway: ChannelRouter) -> Self {
            self.gateway = Some(gateway);
            self
        }

        pub fn build(self) -> ChannelRouter {
            let broadcast = Arc::new(ChannelBroadcast::default());
            let mut receiver: async_channel::Receiver<(DataAddress, SocketAddr)> =
                broadcast.channel();
            let inner = Arc::new(Mutex::new(ChannelRouterInner {
                hosts: Default::default(),
                routers: Default::default(),
                last_generated_ip: self.start_ip,
                last_generated_port: 0,
                addr_map: Default::default(),
            }));
            let weak_inner = Arc::downgrade(&inner);
            let our_ip = self.start_ip;
            let public_ip = if let Some(ref gw) = self.gateway {
                let ip = gw.generate_ip();
                gw.add_router(ip, broadcast);
                Some(ip)
            } else {
                None
            };
            let _task_handle = task::spawn({
                let public_ip = public_ip;
                let our_ip = our_ip;
                let span = tracing::debug_span!("ChannelRouter::recv", public_ip = ?public_ip, our_ip = ?our_ip);
                async move {
                    while let Some((msg, from)) = receiver.next().await {
                        trace!("got {msg:?} from {from:?}");
                        let (host, router, ia) = {
                            let inner = match weak_inner.upgrade() {
                                Some(inner) => inner,
                                None => break,
                            };
                            let inner = inner.lock().unwrap();
                            let internal_address = inner
                                .addr_map
                                .iter()
                                .find(|(_key, &value)| value == msg.address.port())
                                .map(|(key, _value)| key);
                            trace!(
                                "external_address: {:?} -> internal_address: {internal_address:?}",
                                msg.address
                            );
                            // map from public to private
                            if let Some(addr) = internal_address {
                                //trace!("hosts: {:?}", inner.hosts);
                                //trace!("routers: {:?}", inner.routers);
                                (
                                    inner.hosts.get(&addr.ip()).cloned(),
                                    inner.routers.get(&addr.ip()).cloned(),
                                    *addr,
                                )
                            } else {
                                trace!("Could not find nat mapping for {:?}", msg.address);
                                continue;
                            }
                        };
                        let msg = DataAddress {
                            data: msg.data,
                            address: ia,
                        };
                        if let Some(host) = host {
                            if let Err(e) = host.handle_incoming(msg, from).await {
                                warn!("Failed to send to {ia:?}: {e:?}");
                            }
                            continue;
                        }
                        if let Some(router) = router {
                            router.broadcast((msg, from)).await;
                            continue;
                        }
                        trace!("no host found for {ia:?}");
                    }
                }
                .instrument(span)
            });
            ChannelRouter {
                inner,
                our_ip,
                start_ip: self.start_ip,
                end_ip: self.end_ip,
                public_ip,
                gateway: self.gateway.map(|router| Arc::downgrade(&router.inner)),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ChannelRouter {
        inner: Arc<Mutex<ChannelRouterInner>>,
        our_ip: IpAddr,
        start_ip: IpAddr,
        end_ip: IpAddr,
        gateway: Option<Weak<Mutex<ChannelRouterInner>>>,
        public_ip: Option<IpAddr>,
    }

    #[derive(Debug)]
    struct ChannelRouterInner {
        hosts: std::collections::HashMap<IpAddr, ChannelHost>,
        routers:
            std::collections::HashMap<IpAddr, Arc<ChannelBroadcast<(DataAddress, SocketAddr)>>>,
        last_generated_ip: IpAddr,
        last_generated_port: u16,
        addr_map: std::collections::HashMap<SocketAddr, u16>,
    }

    impl ChannelRouterInner {
        fn generate_port(&mut self) -> u16 {
            self.last_generated_port += 1;
            self.last_generated_port
        }
    }

    impl Default for ChannelRouter {
        fn default() -> Self {
            Self::builder().build()
        }
    }

    impl ChannelRouter {
        pub fn builder() -> ChannelRouterBuilder {
            ChannelRouterBuilder {
                start_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                end_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)),
                gateway: None,
            }
        }

        fn add_router(
            &self,
            address: IpAddr,
            router_broadcast: Arc<ChannelBroadcast<(DataAddress, SocketAddr)>>,
        ) {
            let mut inner = self.inner.lock().unwrap();
            inner.routers.insert(address, router_broadcast);
        }

        pub fn add_host(&self) -> ChannelHost {
            let host = ChannelHost::builder().router(self.clone()).build();
            let ip = host.our_ip;
            debug!("adding host with ip: {ip:?}");
            let mut inner = self.inner.lock().unwrap();
            inner.hosts.insert(ip, host.clone());
            host
        }

        fn ip_octets_inc<T: std::ops::Add + std::ops::AddAssign + PartialEq + Copy>(
            octets: &mut [T],
            min: T,
            max: T,
            add: T,
        ) {
            let mut i = (octets.len() as isize) - 1;
            while i >= 0 {
                if octets[i as usize] == max {
                    octets[i as usize] = min;
                } else {
                    octets[i as usize] += add;
                    break;
                }
                i += 1;
            }
        }

        fn generate_ip(&self) -> IpAddr {
            let mut inner = self.inner.lock().unwrap();
            inner.last_generated_ip = match inner.last_generated_ip {
                IpAddr::V4(ipv4) => {
                    let mut octets = ipv4.octets();
                    Self::ip_octets_inc(&mut octets, std::u8::MIN, std::u8::MAX, 1);
                    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
                }
                IpAddr::V6(ipv6) => {
                    let mut segments = ipv6.segments();
                    Self::ip_octets_inc(&mut segments, std::u16::MIN, std::u16::MAX, 1);
                    IpAddr::V6(Ipv6Addr::new(
                        segments[0],
                        segments[1],
                        segments[2],
                        segments[3],
                        segments[4],
                        segments[5],
                        segments[6],
                        segments[7],
                    ))
                }
            };
            inner.last_generated_ip
        }

        #[tracing::instrument(
            name = "ChannelRouter::send",
            skip(self),
            fields(
                public_ip = ?self.public_ip,
                our_ip = ?self.our_ip,
            ),
            err
        )]
        async fn send(&self, msg: DataAddress, from: SocketAddr) -> Result<(), AgentError> {
            trace!("router send");
            if msg.address.ip() >= self.start_ip && msg.address.ip() <= self.end_ip {
                let (host, router) = {
                    let inner = self.inner.lock().unwrap();
                    //trace!("trying to send to {:?}", msg.address.ip());
                    //trace!("hosts {:?}", inner.hosts);
                    let host = inner.hosts.get(&msg.address.ip()).cloned();
                    let router = inner.routers.get(&msg.address.ip()).cloned();
                    (host, router)
                };
                //trace!("found host {host:?}");
                if let Some(host) = host {
                    return host.handle_incoming(msg, from).await;
                }
                if let Some(router) = router {
                    router.broadcast((msg, from)).await;
                    return Ok(());
                }
            }
            if let Some(ref gw) = self.gateway {
                let nat_addr = {
                    let mut inner = self.inner.lock().unwrap();
                    let nat_port = inner.addr_map.get(&from);
                    let nat_port = if let Some(nat_port) = nat_port {
                        *nat_port
                    } else {
                        let nat_port = inner.generate_port();
                        inner.addr_map.insert(from, nat_port);
                        nat_port
                    };
                    SocketAddr::new(self.public_ip.unwrap(), nat_port)
                };
                trace!(
                    "NAT translated send address {:?} to external {nat_addr:?}",
                    from
                );
                let gw = match gw.upgrade() {
                    Some(gw) => gw,
                    None => return Err(AgentError::ResourceNotFound),
                };
                let (host, router) = {
                    let gw = gw.lock().unwrap();
                    let host = gw.hosts.get(&msg.address.ip()).cloned();
                    let router = gw.routers.get(&msg.address.ip()).cloned();
                    (host, router)
                };
                //trace!("found host {host:?}");
                if let Some(host) = host {
                    return host.handle_incoming(msg, nat_addr).await;
                }
                if let Some(router) = router {
                    router.broadcast((msg, nat_addr)).await;
                    return Ok(());
                }
            }
            trace!("no gateway?");
            Err(AgentError::ResourceNotFound)
        }
    }

    pub struct ChannelHostBuilder {
        router: Option<ChannelRouter>,
    }

    impl ChannelHostBuilder {
        pub fn router(mut self, router: ChannelRouter) -> Self {
            self.router = Some(router);
            self
        }

        pub fn build(self) -> ChannelHost {
            let our_ip = self
                .router
                .clone()
                .map(|router| router.generate_ip())
                .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            ChannelHost {
                router: self.router,
                our_ip,
                inner: Arc::new(Mutex::new(ChannelHostInner {
                    channels: Default::default(),
                    last_generated_port: 0,
                })),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ChannelHost {
        router: Option<ChannelRouter>,
        our_ip: IpAddr,
        inner: Arc<Mutex<ChannelHostInner>>,
    }

    #[derive(Debug)]
    struct ChannelHostInner {
        channels: std::collections::HashMap<SocketAddr, Arc<ChannelBroadcast<DataAddress>>>,
        last_generated_port: u16,
    }

    impl ChannelHost {
        pub fn builder() -> ChannelHostBuilder {
            ChannelHostBuilder { router: None }
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
            if msg.address.ip() == from.ip() {
                self.handle_incoming(msg, from).await
            } else {
                self.router.clone().unwrap().send(msg, from).await
            }
        }

        async fn handle_incoming(
            &self,
            msg: DataAddress,
            from: SocketAddr,
        ) -> Result<(), AgentError> {
            let broadcast = {
                let inner = self.inner.lock().unwrap();
                //trace!("trying to send to {:?}", msg.address);
                //trace!("channels {:?}", inner.channels);
                inner
                    .channels
                    .get(&msg.address)
                    .ok_or(AgentError::ResourceNotFound)?
                    .clone()
            };
            //trace!("have channel {broadcast:?}");
            let msg = DataAddress::new(msg.data, from);
            broadcast.broadcast(msg).await;
            Ok(())
        }

        fn generate_addr(&self) -> SocketAddr {
            let mut inner = self.inner.lock().unwrap();
            inner.last_generated_port += 1;
            SocketAddr::new(self.our_ip, inner.last_generated_port)
        }

        pub fn new_channel(&self, peer_addr: Option<SocketAddr>) -> AsyncChannel {
            let addr = self.generate_addr();
            let ret = AsyncChannel {
                host: self.clone(),
                addr,
                peer_addr,
            };
            let mut inner = self.inner.lock().unwrap();
            match inner.channels.get(&addr) {
                Some(_) => unreachable!(),
                None => {
                    let recv = Arc::new(ChannelBroadcast::default());
                    debug!("adding channel {}", addr);
                    inner.channels.insert(addr, recv);
                }
            };

            ret
        }
    }

    #[derive(Debug, Clone)]
    pub struct AsyncChannel {
        host: ChannelHost,
        addr: SocketAddr,
        peer_addr: Option<SocketAddr>,
    }

    impl AsyncChannel {
        pub async fn close(&self) -> Result<(), std::io::Error> {
            Ok(())
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
            let to = msg.address;
            let msg = DataAddress::new(msg.data.to_vec(), msg.address);

            self.host.send(msg, self.addr).await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("Channel {:?} failed to send to {to:?}: {e:?}", self.addr),
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
            Box::pin(self.host.receiver(self.addr))
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

    fn recv_data(channel: StunChannel) -> impl Future<Output = DataAddress> {
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

    pub(crate) async fn send_to_address_and_receive(
        send_socket: StunChannel,
        to: SocketAddr,
        recv_socket: StunChannel,
        check_from: bool,
    ) -> DataAddress {
        let from = send_socket.local_addr().unwrap();

        // send data and assert that it is received
        let recv = recv_data(recv_socket);
        let data = vec![4; 4];
        let da = DataRefAddress::from(&data, to);
        send_socket.send(da).await.unwrap();
        let result = recv.await;
        assert_eq!(result.data, data);
        if check_from {
            assert_eq!(result.address, from);
        }
        result
    }

    async fn send_to_and_receive(send_socket: StunChannel, recv_socket: StunChannel) {
        let to = recv_socket.local_addr().unwrap();
        send_to_address_and_receive(send_socket, to, recv_socket, true).await;
    }

    #[test]
    fn udp_channel_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let udp2 = setup_udp_channel().await;

            send_to_and_receive(StunChannel::UdpAny(udp1), StunChannel::UdpAny(udp2)).await;
        });
    }

    #[test]
    fn async_channel_host_local_send_recv() {
        init();
        task::block_on(async move {
            let host = ChannelHost::builder().build();
            let local = host.new_channel(None);
            let remote = host.new_channel(None);
            send_to_and_receive(
                StunChannel::AsyncChannel(local),
                StunChannel::AsyncChannel(remote),
            )
            .await;
        });
    }

    #[test]
    fn async_channel_host_send_recv() {
        init();
        task::block_on(async move {
            let router = ChannelRouter::builder().build();
            let local_host = router.add_host();
            let local = local_host.new_channel(None);
            let remote_host = router.add_host();
            let remote = remote_host.new_channel(None);
            send_to_and_receive(
                StunChannel::AsyncChannel(local),
                StunChannel::AsyncChannel(remote),
            )
            .await;
        });
    }

    #[test]
    fn async_router_ip_range() {
        init();
        task::block_on(async move {
            let start_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 4));
            let end_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 40));
            let router = ChannelRouter::builder()
                .allocate_range(start_ip, end_ip)
                .build();
            assert!(router.start_ip == start_ip);
            assert!(router.end_ip == end_ip);
            assert!(router.our_ip >= router.start_ip);
            assert!(router.our_ip <= router.end_ip);
            let host = router.add_host();
            assert!(host.our_ip >= router.start_ip);
            assert!(host.our_ip <= router.end_ip);
        });
    }

    pub(crate) fn async_public_router() -> ChannelRouter {
        let start_ip = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 1));
        let end_ip = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 254));
        ChannelRouter::builder()
            .allocate_range(start_ip, end_ip)
            .build()
    }

    pub(crate) fn async_nat_router(public_router: ChannelRouter) -> ChannelRouter {
        let start_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 4));
        let end_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 40));
        ChannelRouter::builder()
            .allocate_range(start_ip, end_ip)
            .gateway(public_router)
            .build()
    }

    #[test]
    fn async_router_nat_send_receive() {
        init();
        task::block_on(async move {
            let public_router = async_public_router();
            let nat_router = async_nat_router(public_router.clone());
            assert!(nat_router.public_ip.is_some());
            let private_host = nat_router.add_host();
            let local = private_host.new_channel(None);
            let remote_host = public_router.add_host();
            let remote = remote_host.new_channel(None);
            let to = remote.local_addr().unwrap();
            let recved = send_to_address_and_receive(
                StunChannel::AsyncChannel(local.clone()),
                to,
                StunChannel::AsyncChannel(remote.clone()),
                false,
            )
            .await;
            send_to_address_and_receive(
                StunChannel::AsyncChannel(remote),
                recved.address,
                StunChannel::AsyncChannel(local),
                true,
            )
            .await;
        });
    }
}
