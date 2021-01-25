// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_std::net::UdpSocket;
use async_std::prelude::*;

use crate::utils::ChannelBroadcast;

#[derive(Debug)]
pub enum SocketChannel {
    Udp(UdpConnectionChannel),
}

impl SocketChannel {
    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        match self {
            SocketChannel::Udp(c) => c.receive_stream(),
        }
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        match self {
            SocketChannel::Udp(c) => c.send(data).await,
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            SocketChannel::Udp(c) => c.local_addr(),
        }
    }

    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            SocketChannel::Udp(c) => c.remote_addr(),
        }
    }
}

#[derive(Debug)]
pub struct UdpSocketChannel {
    socket: Arc<UdpSocket>,
    sender_broadcast: Arc<ChannelBroadcast<(Vec<u8>, SocketAddr)>>,
    inner: Mutex<UdpSocketChannelInner>,
}

#[derive(Debug)]
struct UdpSocketChannelInner {
    receive_loop_started: bool,
}

impl UdpSocketChannelInner {}

impl UdpSocketChannel {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            sender_broadcast: Arc::new(ChannelBroadcast::default()),
            inner: Mutex::new(UdpSocketChannelInner {
                receive_loop_started: false,
            }),
        }
    }

    pub fn receive_channel(&self) -> async_channel::Receiver<(Vec<u8>, SocketAddr)> {
        self.sender_broadcast.channel()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    fn socket_receive_stream(socket: Arc<UdpSocket>) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
        // stream that continuosly reads from a udp socket
        info!("starting udp receive stream for {:?}", socket.local_addr());
        futures::stream::unfold(socket, |socket| async move {
            let mut data = vec![0; 1500];
            socket.recv_from(&mut data).await.ok().map(|(len, from)| {
                data.truncate(len);
                //trace!("got {} bytes from {:?}", data.len(), from);
                ((data, from), socket)
            })
        })
    }

    async fn receive_loop(
        socket: Arc<UdpSocket>,
        broadcaster: &ChannelBroadcast<(Vec<u8>, SocketAddr)>,
    ) {
        let stream = UdpSocketChannel::socket_receive_stream(socket);
        futures::pin_mut!(stream);

        // send data to the receive channels
        while let Some(res) = stream.next().await {
            broadcaster.broadcast(res).await;
        }
        trace!("UdpSocket receive loop exited");
    }

    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        self.socket.send_to(data, &to).await?;
        Ok(())
    }

    pub fn receive_stream(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
        {
            let mut inner = self.inner.lock().unwrap();
            //let (send, recv) = futures::channel::oneshot::channel();
            if !inner.receive_loop_started {
                async_std::task::spawn({
                    let socket = self.socket.clone();
                    let broadcaser = self.sender_broadcast.clone();
                    async move { UdpSocketChannel::receive_loop(socket, &broadcaser).await }
                });
                inner.receive_loop_started = true;
            }
        }
        self.sender_broadcast.channel()
    }
}

#[derive(Debug)]
pub struct UdpConnectionChannel {
    channel: Arc<UdpSocketChannel>,
    to: SocketAddr,
}

impl UdpConnectionChannel {
    pub fn new(channel: Arc<UdpSocketChannel>, to: SocketAddr) -> Self {
        Self { channel, to }
    }

    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        let channel = self.channel.clone();
        let to = self.to;
        channel.receive_stream().filter_map(
            move |(data, from)| {
                if from == to {
                    Some(data)
                } else {
                    None
                }
            },
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
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

    async fn setup_udp_channel() -> Arc<UdpSocketChannel> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        Arc::new(UdpSocketChannel::new(socket))
    }

    fn recv_data(channel: Arc<UdpConnectionChannel>) -> impl Future<Output = Vec<u8>> {
        let result = Arc::new(Mutex::new(None));
        // retrieve the recv channel before starting the task otherwise, there is a race starting
        // the task against the a sender in the current thread.
        let mut recv = channel.receive_stream();
        let f = task::spawn({
            let result = result.clone();
            async move {
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

    #[test]
    fn send_recv() {
        init();
        task::block_on(async move {
            // set up sockets
            let udp1 = setup_udp_channel().await;
            let from = udp1.local_addr().unwrap();
            let udp2 = setup_udp_channel().await;
            let to = udp2.local_addr().unwrap();

            let socket_channel1 = Arc::new(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = Arc::new(UdpConnectionChannel::new(udp2, from));
            // send data and assert that it is received
            let recv = recv_data(socket_channel2);
            let data = vec![4; 4];
            socket_channel1.send(&data.clone()).await.unwrap();
            let result = recv.await;
            assert_eq!(data, result);
        });
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

            let socket_channel1 = Arc::new(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = Arc::new(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            let recv1 = recv_data(socket_channel2.clone());
            let recv2 = recv_data(socket_channel2);
            let data = vec![4; 4];
            socket_channel1.send(&data.clone()).await.unwrap();
            let result = recv1.await;
            assert_eq!(data, result);
            let result = recv2.await;
            assert_eq!(data, result);
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

            let socket_channel1 = Arc::new(UdpConnectionChannel::new(udp1, to));
            let socket_channel2 = Arc::new(UdpConnectionChannel::new(udp2, from));

            // send data and assert that it is received on both receive channels
            let recv1 = recv_data(socket_channel2.clone());
            let recv2 = recv_data(socket_channel2.clone());
            let data = vec![4; 4];
            socket_channel1.send(&data.clone()).await.unwrap();
            let result = recv1.await;
            assert_eq!(data, result);
            let result = recv2.await;
            assert_eq!(data, result);

            // previous receivers should have been dropped as not connected anymore
            // XXX: doesn't currently test the actual drop just that nothing errors
            let recv1 = recv_data(socket_channel2);
            socket_channel1.send(&data.clone()).await.unwrap();
            let result = recv1.await;
            assert_eq!(data, result);
        });
    }
}
