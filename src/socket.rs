// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;

use async_std::net::UdpSocket;
use async_std::prelude::*;

use async_channel;

use futures;

#[derive(Debug)]
pub enum SocketChannel {
    Udp(UdpSocketChannel)
}

impl SocketChannel {
    pub fn receive_channel(&self) -> async_channel::Receiver<(Vec<u8>, SocketAddr)> {
        match self {
            SocketChannel::Udp(c) => c.receive_channel(),
        }
    }

    pub fn send_channel(&self) -> async_channel::Sender<(Vec<u8>, SocketAddr)> {
        match self {
            SocketChannel::Udp(c) => c.send_channel(),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            SocketChannel::Udp(c) => c.local_addr(),
        }
    }
}

#[derive(Debug)]
pub struct UdpSocketChannel {
    socket: Arc<UdpSocket>,
    udp_send_send_channel: async_channel::Sender<(Vec<u8>, SocketAddr)>,
    udp_send_receive_channel: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
    udp_receive_send_channel: async_channel::Sender<(Vec<u8>, SocketAddr)>,
    udp_receive_receive_channel: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
}

impl UdpSocketChannel {
    pub fn new(socket: UdpSocket) -> Self {
        let (udp_recv_s, udp_recv_r) = async_channel::bounded(16);
        let (udp_send_s, udp_send_r) = async_channel::bounded(16);

        Self {
            socket: Arc::new(socket),
            udp_send_send_channel: udp_send_s,
            udp_send_receive_channel: udp_send_r,
            udp_receive_send_channel: udp_recv_s,
            udp_receive_receive_channel: udp_recv_r,
        }
    }

    pub fn receive_channel(&self) -> async_channel::Receiver<(Vec<u8>, SocketAddr)> {
        self.udp_receive_receive_channel.clone()
    }

    pub fn send_channel(&self) -> async_channel::Sender<(Vec<u8>, SocketAddr)> {
        self.udp_send_send_channel.clone()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    pub async fn receive_loop(&self) -> std::io::Result<()> {
        // stream that continuosly reads from a udp socket
        let stream = futures::stream::unfold(self.socket.clone(), |socket| async move {
            let data: std::io::Result<(Vec<u8>, SocketAddr)> = {
                let mut data = vec![0; 1500];
                match socket.recv_from(&mut data).await {
                    Ok((len, from)) => {
                        data.truncate(len);
                        Ok((data, from))
                    },
                    Err(e) => Err(e),
                }
            };
            Some((data, socket))
        });
        futures::pin_mut!(stream);

        // send data to the receive channel
        while let Some(res) = stream.next().await {
            let res = res?;
            trace!("received from {:?} {:?}", res.1, res.0);
            self.udp_receive_send_channel
                .send((res.0, res.1))
                .await
                .map_err(|_| {
                     std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "receive channel closed")
                })?;
        }
        Ok(())
    }

    pub async fn send_loop(&self) -> std::io::Result<()> {
        // receive from the send channel and send on the socket
        while let Ok((buf, to)) = self.udp_send_receive_channel
            .recv()
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "send channel closed"))
        {
            trace!("sending to {:?} {:?}", to, buf);
            self.socket
                .send_to(&buf, &to)
                .await?;
        }
        Ok(())
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
    fn send_recv() {
        task::block_on(async move {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let s1 = UdpSocket::bind(addr.clone()).await.unwrap();
            let from = s1.local_addr().unwrap();
            let socket_channel1 = UdpSocketChannel::new(s1);
            let s2 = UdpSocket::bind(addr.clone()).await.unwrap();
            let to = s2.local_addr().unwrap();
            let socket_channel2 = UdpSocketChannel::new(s2);

        });
    }
}
