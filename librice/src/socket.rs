// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Socket helpers for handling UDP and TCP transports

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures::prelude::*;

use tracing::{debug_span, info, trace, warn};
use tracing_futures::Instrument;

use crate::runtime::{
    AsyncTcpStream, AsyncTcpStreamRead, AsyncTcpStreamReadExt, AsyncTcpStreamWriteExt,
    AsyncUdpSocket, AsyncUdpSocketExt, Runtime,
};
use crate::utils::DebugWrapper;

use rice_c::candidate::TransportType;

pub(crate) struct Transmit<T: AsRef<[u8]> + std::fmt::Debug> {
    pub transport: TransportType,
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: T,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Transmit<T> {
    pub fn new(data: T, transport: TransportType, from: SocketAddr, to: SocketAddr) -> Self {
        Self {
            data,
            transport,
            from,
            to,
        }
    }
}

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

/// A combined socket interface for both UDP and TCP
#[derive(Debug, Clone)]
pub enum StunChannel {
    /// A UDP socket.
    Udp(UdpSocketChannel),
    /// A TCP socket.
    Tcp(TcpChannel),
}

/// Data and address
#[derive(Debug, Clone)]
struct DataAddress {
    /// The data
    pub data: Vec<u8>,
    /// An address
    pub address: SocketAddr,
}

impl DataAddress {
    fn new(data: Vec<u8>, address: SocketAddr) -> Self {
        Self { data, address }
    }
}

impl StunChannel {
    /// Close the socket
    pub async fn close(&mut self) -> Result<(), std::io::Error> {
        match self {
            StunChannel::Udp(c) => c.close(),
            StunChannel::Tcp(c) => c.close().await,
        }
    }

    /// The transport of this socket
    pub fn transport(&self) -> TransportType {
        match self {
            StunChannel::Udp(_) => TransportType::Udp,
            StunChannel::Tcp(_) => TransportType::Tcp,
        }
    }

    /// Send data to a specified address
    pub async fn send_to(&mut self, data: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        match self {
            StunChannel::Udp(udp) => udp.send_to(data, to).await,
            StunChannel::Tcp(tcp) => tcp.send_to(data, to).await,
        }
    }

    /// Return a stream of received data.
    ///
    /// WARNING: Any data received will only be dispatched to a single returned stream
    pub fn recv(&mut self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> + '_ {
        match self {
            StunChannel::Udp(udp) => udp.recv().left_stream(),
            StunChannel::Tcp(tcp) => tcp.recv().right_stream(),
        }
    }

    /// The local address of the socket (where available)
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            StunChannel::Udp(c) => c.local_addr(),
            StunChannel::Tcp(c) => c.local_addr(),
        }
    }

    /// The remote address of the socket (where available)
    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            StunChannel::Udp(_) => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "connection-less udp doesn't have a remote addr",
            )),
            StunChannel::Tcp(c) => c.remote_addr(),
        }
    }
}

/// A UDP socket
#[derive(Debug, Clone)]
pub struct UdpSocketChannel {
    socket: Arc<dyn AsyncUdpSocket>,
    inner: DebugWrapper<Arc<Mutex<UdpSocketChannelInner>>>,
}

#[derive(Debug)]
struct UdpSocketChannelInner {
    closed: bool,
}

impl UdpSocketChannel {
    /// Create a new UDP socket
    pub fn new(socket: Arc<dyn AsyncUdpSocket>) -> Self {
        Self {
            socket,
            inner: DebugWrapper::wrap(
                Arc::new(Mutex::new(UdpSocketChannelInner { closed: false })),
                "...",
            ),
        }
    }

    /// Send a piece of data to a particular address
    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<()> {
        {
            let inner = self.inner.lock().unwrap();
            if inner.closed {
                return Err(std::io::Error::other("Connection closed"));
            }
        }
        trace!(
            "udp socket send_to {:?} bytes from {:?} to {:?}",
            data.len(),
            self.local_addr(),
            to
        );
        self.socket.send_to(data, to).await?;
        Ok(())
    }

    /// Close the socket for any further processing.
    pub fn close(&self) -> Result<(), std::io::Error> {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.closed = true;
        };
        Ok(())
    }

    /// A channel for receiving data sent to this socket.
    ///
    /// WARNING: If multiple streams are retrieved, it is  undefined which returned stream will
    /// received a piece of data.
    pub fn recv(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> + '_ {
        stream::unfold(self.clone(), |this| async move {
            let mut buf = vec![0; 1024];
            let (size, from) = this.socket.recv_from(&mut buf).await.unwrap();
            let ret = buf.split_at(size).0.to_vec();
            Some(((ret, from), this))
        })
    }

    /// The local address of the socket
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }
}

/// A TCP socket
#[derive(Debug, Clone)]
pub struct TcpChannel {
    read_channel: Arc<Mutex<Option<futures::channel::mpsc::Receiver<DataAddress>>>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    sender_channel: futures::channel::mpsc::Sender<TcpData>,
}

#[derive(Debug)]
enum TcpData {
    Data(Vec<u8>),
    Shutdown,
}

impl TcpChannel {
    /// Create a TCP socket from an existing TcpStream
    pub fn new(runtime: Arc<dyn Runtime>, stream: Box<dyn AsyncTcpStream>) -> Self {
        let local_addr = stream.local_addr().unwrap();
        let remote_addr = stream.remote_addr().unwrap();
        let (send_tx, send_rx) = futures::channel::mpsc::channel::<TcpData>(1);
        let (mut read, mut write) = stream.split();
        runtime.spawn(Box::pin({
            async move {
                let mut send_rx = core::pin::pin!(send_rx);
                //let mut write = core::pin::pin!(write);
                while let Some(data) = send_rx.next().await {
                    match data {
                        TcpData::Data(data) => {
                            if let Err(e) = write.write_all(&data).await {
                                warn!("tcp write produced error {e:?}");
                                break;
                            }
                        }
                        TcpData::Shutdown => {
                            if let Err(e) = write.shutdown(std::net::Shutdown::Both).await {
                                warn!("tcp shutdown produced error {e:?}");
                            }
                            break;
                        }
                    }
                }
            }
        }));
        let (mut recv_tx, recv_rx) = futures::channel::mpsc::channel::<DataAddress>(1);
        runtime.spawn(Box::pin(async move {
            while let Ok(data_addr) = Self::inner_recv(&mut read).await {
                if recv_tx.send(data_addr).await.is_err() {
                    break;
                }
            }
        }));
        Self {
            local_addr,
            remote_addr,
            read_channel: Arc::new(Mutex::new(Some(recv_rx))),
            sender_channel: send_tx,
        }
    }

    #[tracing::instrument(
        name = "tcp_single_recv",
        skip(stream),
        fields(
            remote.addr = ?stream.remote_addr()
        )
    )]
    async fn inner_recv(
        stream: &mut Box<dyn AsyncTcpStreamRead>,
    ) -> Result<DataAddress, std::io::Error> {
        let from = stream.remote_addr()?;

        let mut data = vec![0; MAX_STUN_MESSAGE_SIZE];

        match stream.read(&mut data).await {
            Ok(size) => {
                trace!("recved {} bytes", size);
                if size == 0 {
                    info!("connection closed");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TCP connection closed",
                    ));
                }
                trace!("return {} bytes", size);
                return Ok(DataAddress::new(data[..size].to_vec(), from));
            }
            Err(e) => return Err(e),
        }
    }

    /// Close the socket
    pub async fn close(&mut self) -> Result<(), std::io::Error> {
        self.sender_channel
            .send(TcpData::Shutdown)
            .await
            .map_err(|e| {
                if e.is_disconnected() {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Disconnected")
                } else {
                    unreachable!();
                }
            })
    }

    /// Send data to the specified address
    pub async fn send_to(&mut self, data: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        if to != self.remote_addr()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Address to send to is different from connected address",
            ));
        }

        if data.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data length too large for transport",
            ));
        }

        self.sender_channel
            .send(TcpData::Data(data.to_vec()))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
    }

    /// Return a stream of received data blocks
    pub fn recv(&mut self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> + '_ {
        let span = debug_span!("tcp_recv");
        let chan = self
            .read_channel
            .lock()
            .unwrap()
            .take()
            .expect("Receiver already taken!");
        chan.map(|v| (v.data, v.address))
            .instrument(span.or_current())
        // TODO: replace self.running_buffer when done? drop handler?
        /*stream::unfold(&mut self.read_stream, |mut stream| async move {
            TcpChannel::inner_recv(&mut stream)
                .await
                .ok()
                .map(|v| ((v.data, v.address), stream))
        })
        .instrument(span.or_current())*/
    }

    /// The local address of the socket
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.local_addr)
    }

    /// The remoted address of the connected socket
    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.remote_addr)
    }
}
