// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;

use crate::candidate::TransportType;
use crate::utils::{ChannelBroadcast, DebugWrapper};
use futures::StreamExt;
#[cfg(not(test))]
use futures::{future::Either, stream::Empty};

#[derive(Debug, Clone)]
pub enum SocketChannel {
    Udp(UdpSocketChannel),
    UdpConnection(UdpConnectionChannel),
    Tcp(TcpChannel),
    #[cfg(test)]
    AsyncChannel(tests::AsyncChannel),
}

impl SocketChannel {
    pub fn receive_stream(
        &self,
    ) -> Result<impl Stream<Item = (Vec<u8>, SocketAddr)>, std::io::Error> {
        // so this is weird for a number of reasons:
        // - Either's are for working around the different opaque types returning an impl Stream
        // - We need to provide a type (cause the Either doesn't have one) for the the AsyncChannel
        //   case when #[cfg(not(test))]
        #[cfg(not(test))]
        #[allow(unused_assignments)]
        let mut ret: Option<Either<_, Either<_, Empty<_>>>> = None;
        #[cfg(test)]
        #[allow(unused_assignments)]
        let mut ret = None;
        ret = match self {
            SocketChannel::Udp(c) => Some(c.receive_stream().left_stream().left_stream()),
            SocketChannel::UdpConnection(c) => {
                let remote_addr = c.remote_addr()?;
                Some(
                    c.receive_stream()
                        .map(move |data| (data, remote_addr))
                        .left_stream()
                        .right_stream(),
                )
            }
            SocketChannel::Tcp(c) => {
                let remote_addr = c.remote_addr()?;
                Some(
                    c.receive_stream()
                        .map(move |data| (data, remote_addr))
                        .right_stream()
                        .left_stream(),
                )
            }
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => {
                Some(c.receive_stream().right_stream().right_stream())
            }
        };
        ret.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Implementation not available")
        })
    }

    #[tracing::instrument(
        level = "debug",
        err,
        skip(self, data),
        fields(
            data.size = data.len()
        )
    )]
    pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        match self {
            SocketChannel::UdpConnection(c) => c.send(data).await,
            SocketChannel::Tcp(c) => c.send(data).await,
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => c.send(data).await,
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Implementation not available",
            )),
        }
    }

    #[tracing::instrument(
        level = "debug",
        err,
        skip(self, data),
        fields(
            data.size = data.len()
        )
    )]
    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        match self {
            SocketChannel::Udp(c) => c.send_to(data, to).await,
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => c.send_to(data, to).await,
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Implementation not available",
            )),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            SocketChannel::Udp(c) => c.local_addr(),
            SocketChannel::UdpConnection(c) => c.local_addr(),
            SocketChannel::Tcp(c) => c.local_addr(),
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => c.local_addr(),
        }
    }

    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            SocketChannel::UdpConnection(c) => c.remote_addr(),
            SocketChannel::Tcp(c) => c.remote_addr(),
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => c.remote_addr(),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Implementation not available",
            )),
        }
    }

    pub(crate) fn produces_complete_messages(&self) -> bool {
        match self {
            SocketChannel::Udp(_) => true,
            SocketChannel::UdpConnection(_) => true,
            SocketChannel::Tcp(_) => false,
            #[cfg(test)]
            SocketChannel::AsyncChannel(c) => c.produces_complete_messages(),
        }
    }

    pub fn transport_type(&self) -> TransportType {
        match self {
            SocketChannel::Udp(_) => TransportType::Udp,
            SocketChannel::UdpConnection(_) => TransportType::Udp,
            SocketChannel::Tcp(_) => TransportType::Tcp,
            #[cfg(test)]
            SocketChannel::AsyncChannel(_) => TransportType::AsyncChannel,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpSocketChannel {
    socket: DebugWrapper<Arc<UdpSocket>>,
    sender_broadcast: Arc<ChannelBroadcast<(Vec<u8>, SocketAddr)>>,
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

    pub fn receive_channel(&self) -> async_channel::Receiver<(Vec<u8>, SocketAddr)> {
        self.sender_broadcast.channel()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        (*self.socket).clone()
    }

    fn socket_receive_stream(socket: Arc<UdpSocket>) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
        // stream that continuosly reads from a udp socket
        futures::stream::unfold(socket, |socket| async move {
            let mut data = vec![0; 1500];
            socket.recv_from(&mut data).await.ok().map(|(len, from)| {
                data.truncate(len);
                //trace!("got {} bytes from {:?}", data.len(), from);
                ((data, from), socket)
            })
        })
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
        let stream = UdpSocketChannel::socket_receive_stream(socket);
        futures::pin_mut!(stream);

        debug!("loop starting");
        // send data to the receive channels
        while let Some(res) = stream.next().await {
            broadcaster.broadcast(res).await;
        }
        trace!("loop exited");
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        self.socket.send_to(data, &to).await?;
        Ok(())
    }

    pub fn receive_stream(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
        {
            let mut inner = self.inner.lock().unwrap();
            //let (send, recv) = futures::channel::oneshot::channel();
            if inner.receive_loop.is_none() {
                inner.receive_loop = Some(async_std::task::spawn({
                    let socket = (*self.socket).clone();
                    let broadcaster = self.sender_broadcast.clone();
                    async move { UdpSocketChannel::receive_loop(socket, broadcaster).await }
                }));
            }
        }
        self.sender_broadcast.channel()
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

    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        let channel = self.channel.clone();
        let to = self.to;
        channel
            .receive_stream()
            .filter_map(move |(data, from)| async move {
                if from == to {
                    Some(data)
                } else {
                    None
                }
            })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.channel.local_addr()
    }

    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.to)
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.channel.socket()
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        self.channel.send_to(data, self.to).await
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

    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.receive_loop.is_none() {
                inner.receive_loop = Some(async_std::task::spawn({
                    let socket = self.channel.clone();
                    let broadcaster = self.sender_broadcast.clone();
                    async move { TcpChannel::receive_loop(socket, broadcaster).await }
                }));
            }
        }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::agent::AgentError;
    use async_std::net::TcpListener;
    use async_std::task;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[derive(Debug, Clone)]
    pub struct ChannelRouter {
        inner: Arc<Mutex<ChannelRouterInner>>,
    }

    #[derive(Debug)]
    struct ChannelRouterInner {
        channels:
            std::collections::HashMap<SocketAddr, Arc<ChannelBroadcast<(Vec<u8>, SocketAddr)>>>,
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

        fn receiver(&self, addr: SocketAddr) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
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

        async fn send(
            &self,
            data: &[u8],
            to: SocketAddr,
            from: SocketAddr,
        ) -> Result<(), AgentError> {
            let broadcast = {
                let inner = self.inner.lock().unwrap();
                error!("send channels {:?}", inner.channels);
                inner
                    .channels
                    .get(&to)
                    .ok_or(AgentError::ResourceNotFound)?
                    .clone()
            };
            broadcast.broadcast((data.to_vec(), from)).await;
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

        pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
            Ok(self.addr)
        }

        pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
            self.peer_addr.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "Implementation not available")
            })
        }

        pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
            if let Some(peer_addr) = self.peer_addr {
                if to != peer_addr {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Implementation not available",
                    ));
                }
            }

            self.router.send(data, to, self.addr).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Channel failed to send",
                )
            })?;
            Ok(())
        }

        pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
            let peer_addr = self.peer_addr.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "Implementation not available")
            })?;

            self.router
                .send(data, peer_addr, self.addr)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "Channel failed to send",
                    )
                })?;
            Ok(())
        }

        pub fn receive_stream(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
            error!("receive stream for {}", self.addr);
            self.router.receiver(self.addr)
        }

        pub fn produces_complete_messages(&self )-> bool {
            true
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

    async fn setup_udp_channel() -> UdpSocketChannel {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        UdpSocketChannel::new(socket)
    }

    fn recv_data(channel: SocketChannel) -> impl Future<Output = (Vec<u8>, SocketAddr)> {
        let result = Arc::new(Mutex::new(None));
        // retrieve the recv channel before starting the task otherwise, there is a race starting
        // the task against the a sender in the current thread.
        let recv = channel.receive_stream().unwrap();
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

    async fn send_to_and_receive(send_socket: SocketChannel, recv_socket: SocketChannel) {
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
            let udp1 = SocketChannel::Udp(setup_udp_channel().await);
            let udp2 = SocketChannel::Udp(setup_udp_channel().await);

            send_to_and_receive(udp1, udp2).await;
        });
    }

    async fn send_and_receive(send_socket: SocketChannel, recv_socket: SocketChannel) {
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

        // send data and assert that it is received
        let recv = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket.send(&data.clone()).await.unwrap();
        let result = recv.await;
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
    }

    #[test]
    fn udp_connection_send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = SocketChannel::UdpConnection(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 =
                SocketChannel::UdpConnection(UdpConnectionChannel::new(udp2, from));

            send_and_receive(socket_channel1, socket_channel2).await;
        });
    }

    async fn send_and_double_receive(send_socket: SocketChannel, recv_socket: SocketChannel) {
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

        // send data and assert that it is received on both receive channels
        let recv1 = recv_data(recv_socket.clone());
        let recv2 = recv_data(recv_socket);
        let data = vec![4; 4];
        send_socket.send(&data.clone()).await.unwrap();
        let result = recv1.await;
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
        let result = recv2.await;
        assert_eq!(result.0, data);
        assert_eq!(result.1, from);
    }

    #[test]
    fn send_multi_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = SocketChannel::UdpConnection(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 =
                SocketChannel::UdpConnection(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(socket_channel1, socket_channel2).await;
        });
    }

    #[test]
    fn send_multi_recv_with_drop() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = SocketChannel::UdpConnection(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 =
                SocketChannel::UdpConnection(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            send_and_double_receive(socket_channel1.clone(), socket_channel2.clone()).await;

            // previous receivers should have been dropped as not connected anymore
            // XXX: doesn't currently test the actual drop just that nothing errors
            send_and_receive(socket_channel1, socket_channel2).await;
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

            let socket_channel1 = SocketChannel::Tcp(TcpChannel::new(tcp1));
            let socket_channel2 = SocketChannel::Tcp(TcpChannel::new(tcp2));

            send_and_receive(socket_channel1, socket_channel2).await;
        });
    }
}
