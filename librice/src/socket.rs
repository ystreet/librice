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

use async_std::net::{TcpStream, UdpSocket};

use futures::prelude::*;

use byteorder::{BigEndian, ByteOrder};
use tracing_futures::Instrument;

use crate::utils::DebugWrapper;

use librice_proto::candidate::TransportType;

const MAX_STUN_MESSAGE_SIZE: usize = 1500 * 2;

/// A combined socket for both UDP and TCP
#[derive(Debug, Clone)]
pub enum StunChannel {
    Udp(UdpSocketChannel),
    Tcp(TcpChannel),
}

/// Data and address
#[derive(Debug, Clone)]
pub struct DataAddress {
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
    pub async fn close(&self) -> Result<(), std::io::Error> {
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
    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        match self {
            StunChannel::Udp(udp) => udp.send_to(data, to).await,
            StunChannel::Tcp(tcp) => tcp.send_to(data, to).await,
        }
    }

    /// Return a stream of received data.
    ///
    /// WARNING: Any data received will only be dispatched to a single returned stream
    pub fn recv(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> + '_ {
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
    socket: DebugWrapper<Arc<UdpSocket>>,
    inner: DebugWrapper<Arc<Mutex<UdpSocketChannelInner>>>,
}

#[derive(Debug)]
struct UdpSocketChannelInner {
    closed: bool,
}

impl UdpSocketChannel {
    /// Create a new UDP socket
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: DebugWrapper::wrap(Arc::new(socket), "..."),
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Connection closed",
                ));
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
    stream: DebugWrapper<TcpStream>,
    running_buffer: Arc<Mutex<Option<TcpBuffer>>>,
    sender_channel: async_std::channel::Sender<Vec<u8>>,
    sender_task: Arc<async_std::sync::Mutex<Option<async_std::task::JoinHandle<()>>>>,
}

impl TcpChannel {
    /// Create a TCP socket from an existing TcpStream
    pub fn new(stream: TcpStream) -> Self {
        let (tx, mut rx) = async_std::channel::bounded::<Vec<u8>>(1);
        let sender_task = async_std::task::spawn({
            let mut stream = stream.clone();
            async move {
                while let Some(data) = rx.next().await {
                    let mut header_len = [0, 0];
                    BigEndian::write_u16(&mut header_len, data.len() as u16);
                    if let Err(e) = stream.write_all(&header_len).await {
                        warn!("tcp write produced error {:?}", e);
                        break;
                    }
                    if let Err(e) = stream.write_all(&data).await {
                        warn!("tcp write produced error {:?}", e);
                        break;
                    }
                }
            }
        });
        Self {
            stream: DebugWrapper::wrap(stream, "..."),
            running_buffer: Arc::new(Mutex::new(Some(TcpBuffer::new(MAX_STUN_MESSAGE_SIZE)))),
            sender_channel: tx,
            sender_task: Arc::new(async_std::sync::Mutex::new(Some(sender_task))),
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

        if buf.len() > 2 {
            let data_length = (BigEndian::read_u16(&buf.buf[..2]) as usize) + 2;
            trace!(
                "check for enough data in existing buffer of length {}, data length {data_length}",
                buf.len()
            );
            if data_length <= buf.len() {
                let bytes = buf.take(data_length);
                *running.lock().unwrap() = Some(buf);
                trace!("return {} bytes", data_length - 2);
                return Ok(DataAddress::new(bytes[2..].to_vec(), from));
            }
        }

        trace!("start reading from tcp buffer");
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
                trace!("return {} bytes", data_length - 2);
                return Ok(DataAddress::new(bytes[2..].to_vec(), from));
            }
        }
        debug!("no more data");
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "No more data",
        ))
    }

    /// Close the socket
    pub async fn close(&self) -> Result<(), std::io::Error> {
        if let Some(task_handle) = self.sender_task.lock().await.take() {
            task_handle.cancel().await;
        }
        self.stream.shutdown(std::net::Shutdown::Both)
    }

    /// Send data to the specified address
    pub async fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
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
            .send(data.to_vec())
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))
    }

    /// Return a stream of received data blocks
    pub fn recv(&self) -> impl Stream<Item = (Vec<u8>, SocketAddr)> {
        let stream = self.stream.clone();
        let running = self.running_buffer.clone();
        // TODO: replace self.running_buffer when done? drop handler?
        let span = debug_span!("tcp_recv");
        stream::unfold((stream, running), |(mut stream, running)| async move {
            TcpChannel::inner_recv(&mut stream, running.clone())
                .await
                .ok()
                .map(|v| ((v.data, v.address), (stream, running)))
        })
        .instrument(span.or_current())
    }

    /// The local address of the socket
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.local_addr()
    }

    /// The remoted address of the connected socket
    pub fn remote_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.stream.peer_addr()
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
