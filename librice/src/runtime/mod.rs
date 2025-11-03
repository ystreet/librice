// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Async runtime abstraction

use core::future::Future;

use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Abstracts I/O and timer operations for runtime independence.
pub trait Runtime: Send + Sync + core::fmt::Debug + 'static {
    /// Drive a `Future` to completion in the background.
    #[track_caller]
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
    /// Construct a timer that will expire at `i`.
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>>;
    /// Convert socket into the socket type used by this runtime.
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn AsyncUdpSocket>>;
    /// Construct a new TCP listener.
    #[allow(clippy::type_complexity)]
    fn new_tcp_listener(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn AsyncTcpListener>>> + Send>>;
    /// Connect to a TCP server.
    #[allow(clippy::type_complexity)]
    fn tcp_connect(
        &self,
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncTcpStream>>> + Send>>;
}

/// Abstract implementation of an async timer for runtime independence.
pub trait AsyncTimer: Send + Debug + 'static {
    /// Update the timer to expire at `i`.
    fn reset(self: Pin<&mut Self>, i: Instant);
    /// Check whether the timer has expired, or register to be woken up at the configured instant.
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()>;
}

/// Abstract implementation of an async UDP socket for runtime independence.
pub trait AsyncUdpSocket: Send + Sync + Debug + 'static {
    /// Return the local bound address of a socket.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Receive a UDP datagram, or register to be woken up.
    fn poll_recv(
        &self,
        cx: &mut Context,
        dest: &mut [u8],
    ) -> Poll<std::io::Result<(usize, SocketAddr)>>;
    /// Send a UDP datagram, or register to be woken up.
    fn poll_send(
        &self,
        cx: &mut Context,
        src: &[u8],
        to: SocketAddr,
    ) -> Poll<std::io::Result<usize>>;
}

/// Helper trait implementing for `AsyncUdpSocket`.
pub trait AsyncUdpSocketExt: AsyncUdpSocket {
    /// Send a datagram to a particular peer.
    fn send_to(
        &self,
        data: &[u8],
        to: SocketAddr,
    ) -> impl Future<Output = std::io::Result<usize>> + Send;
    /// Receive a datagram received on a socket.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = std::io::Result<(usize, SocketAddr)>> + Send;
}

impl<T: AsyncUdpSocket + ?Sized> AsyncUdpSocketExt for T {
    async fn send_to(&self, data: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_send(cx, data, to)).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        core::future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }
}

/// Abstract implementation of an async UDP socket for runtime independence.
pub trait AsyncTcpListener: Send + Sync + Debug + 'static {
    /// Return the local bound address of a socket.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Receive a UDP datagram, or register to be woken up.
    fn poll_next(&self, cx: &mut Context) -> Poll<std::io::Result<Box<dyn AsyncTcpStream>>>;
}

/// Extension trait for listening for TCP connections.
pub trait AsyncTcpListenerExt {
    /// Accept an incoming TCP connection.
    fn accept(&self) -> impl Future<Output = std::io::Result<Box<dyn AsyncTcpStream>>> + Send;
}

impl<T: AsyncTcpListener + ?Sized> AsyncTcpListenerExt for T {
    async fn accept(&self) -> std::io::Result<Box<dyn AsyncTcpStream>> {
        core::future::poll_fn(|cx| self.poll_next(cx)).await
    }
}

/// Abstract implementation of an async TCP listener for runtime independence.
pub trait AsyncTcpStream: Send + Sync + Debug {
    /// Return the local bound address of a socket.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Return the local bound address of a socket.
    fn remote_addr(&self) -> std::io::Result<SocketAddr>;
    /// Split into read and write halves.
    fn split(self: Box<Self>) -> (Box<dyn AsyncTcpStreamRead>, Box<dyn AsyncTcpStreamWrite>);
}

/// Trait for reading from a Tcp connection.
pub trait AsyncTcpStreamRead: Send + Sync + Debug {
    /// Return the local bound address of a socket.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Return the local bound address of a socket.
    fn remote_addr(&self) -> std::io::Result<SocketAddr>;
    /// Poll for the progress of reading from a Tcp connection.
    fn poll_read(&mut self, cx: &mut Context, buf: &mut [u8]) -> Poll<std::io::Result<usize>>;
}

/// Extension trait for reading from a TCP stream.
pub trait AsyncTcpStreamReadExt: AsyncTcpStreamRead {
    /// Read from a TCP stream.
    fn read(&mut self, dest: &mut [u8]) -> impl Future<Output = std::io::Result<usize>> + Send;
}

impl<T: AsyncTcpStreamRead + ?Sized> AsyncTcpStreamReadExt for T {
    async fn read(&mut self, dest: &mut [u8]) -> std::io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_read(cx, dest)).await
    }
}

/// Trait for writing to a Tcp connection.
pub trait AsyncTcpStreamWrite: Send + Sync + Debug {
    /// Return the local bound address of a socket.
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    /// Return the local bound address of a socket.
    fn remote_addr(&self) -> std::io::Result<SocketAddr>;
    /// Poll for writing data to the Tcp connection.
    fn poll_write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>>;
    /// Poll for flush completion.
    fn poll_flush(&mut self, cx: &mut Context) -> Poll<std::io::Result<()>>;
    /// Poll for shutdown completion.
    fn poll_shutdown(
        &mut self,
        cx: &mut Context,
        how: std::net::Shutdown,
    ) -> Poll<std::io::Result<()>>;
}

/// Automatically implemented extension trait for writing to a Tcp connection.
pub trait AsyncTcpStreamWriteExt: AsyncTcpStreamWrite {
    /// Write the buffer into the Tcp connection.  Returns the number of bytes written.
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = std::io::Result<usize>> + Send;
    /// Write all the bytes to the Tcp connection or produce an error.
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = std::io::Result<()>> {
        async move {
            let mut idx = 0;
            loop {
                if idx >= buf.len() {
                    return Ok(());
                }
                match self.write(&buf[idx..]).await {
                    Ok(len) => idx += len,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => return Err(e),
                }
            }
        }
    }
    /// Flush the Tcp connection.
    fn flush(&mut self) -> impl Future<Output = std::io::Result<()>>;
    /// Close the Tcp connection
    fn shutdown(&mut self, how: std::net::Shutdown) -> impl Future<Output = std::io::Result<()>>;
}

impl<T: AsyncTcpStreamWrite + ?Sized> AsyncTcpStreamWriteExt for T {
    async fn flush(&mut self) -> std::io::Result<()> {
        core::future::poll_fn(|cx| self.poll_flush(cx)).await
    }
    async fn shutdown(&mut self, how: std::net::Shutdown) -> std::io::Result<()> {
        core::future::poll_fn(|cx| self.poll_shutdown(cx, how)).await
    }
    async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        core::future::poll_fn(|cx| self.poll_write(cx, buf)).await
    }
}

/// Automatically select the appropriate runtime from those enabled at compile time.
#[allow(clippy::needless_return)]
pub fn default_runtime() -> Option<Arc<dyn Runtime>> {
    #[cfg(feature = "runtime-tokio")]
    if ::tokio::runtime::Handle::try_current().is_ok() {
        return Some(Arc::new(TokioRuntime));
    }

    #[cfg(feature = "runtime-smol")]
    {
        return Some(Arc::new(SmolRuntime));
    }

    #[cfg(not(feature = "runtime-smol"))]
    None
}

#[cfg(feature = "runtime-smol")]
mod smol;
#[cfg(feature = "runtime-smol")]
pub use smol::SmolRuntime;
#[cfg(feature = "runtime-tokio")]
mod tokio;
#[cfg(feature = "runtime-tokio")]
pub use tokio::TokioRuntime;
