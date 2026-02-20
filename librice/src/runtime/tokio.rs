// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};

use tokio::time::sleep_until;

use crate::runtime::{AsyncTcpStream, AsyncTcpStreamRead, AsyncTcpStreamWrite, Runtime};

/// An async implementation for use with Tokio.
#[derive(Debug)]
pub struct TokioRuntime {
    handle: tokio::runtime::Handle,
}

impl TokioRuntime {
    /// Construct a new Tokio runtime with the provide tokio runtime `Handle`.
    pub fn new(handle: tokio::runtime::Handle) -> Self {
        Self { handle }
    }
}

impl Runtime for TokioRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.handle.spawn(future);
    }
    fn new_timer(&self, i: std::time::Instant) -> std::pin::Pin<Box<dyn super::AsyncTimer>> {
        let _guard = self.handle.enter();
        Box::pin(sleep_until(i.into()))
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<std::sync::Arc<dyn super::AsyncUdpSocket>> {
        let _guard = self.handle.enter();
        socket.set_nonblocking(true)?;
        Ok(Arc::new(TokioUdpSocket {
            io: tokio::net::UdpSocket::from_std(socket)?,
        }))
    }
    fn tcp_connect(
        &self,
        peer: std::net::SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncTcpStream>>> + Send>> {
        Box::pin(async move {
            tokio::net::TcpStream::connect(peer)
                .await
                .map(|s| Box::new(s) as _)
        })
    }
    fn new_tcp_listener(
        &self,
        addr: std::net::SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn super::AsyncTcpListener>>> + Send>>
    {
        Box::pin(async move {
            tokio::net::TcpListener::bind(addr)
                .await
                .map(|s| Arc::new(s) as _)
        })
    }
}

#[derive(Debug)]
struct TokioUdpSocket {
    io: tokio::net::UdpSocket,
}

impl super::AsyncUdpSocket for TokioUdpSocket {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        dest: &mut [u8],
    ) -> std::task::Poll<std::io::Result<(usize, std::net::SocketAddr)>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_recv_from(dest) {
                Ok(ret) => return Poll::Ready(Ok(ret)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        src: &[u8],
        to: std::net::SocketAddr,
    ) -> Poll<std::io::Result<usize>> {
        loop {
            ready!(self.io.poll_send_ready(cx))?;
            match self.io.try_send_to(src, to) {
                Ok(ret) => return Poll::Ready(Ok(ret)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl super::AsyncTcpStream for tokio::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::TcpStream::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::TcpStream::peer_addr(self)
    }
    fn split(self: Box<Self>) -> (Box<dyn AsyncTcpStreamRead>, Box<dyn AsyncTcpStreamWrite>) {
        let (read, write) = tokio::net::TcpStream::into_split(*self);
        (Box::new(read), Box::new(write))
    }
}

impl super::AsyncTcpStreamRead for tokio::net::tcp::OwnedReadHalf {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::tcp::OwnedReadHalf::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::tcp::OwnedReadHalf::peer_addr(self)
    }
    fn poll_read(
        &mut self,
        cx: &mut std::task::Context,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        tokio::io::AsyncRead::poll_read(Pin::new(&mut *self), cx, &mut buf)
            .map_ok(|_| buf.filled().len())
    }
}

impl super::AsyncTcpStreamWrite for tokio::net::tcp::OwnedWriteHalf {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::tcp::OwnedWriteHalf::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::tcp::OwnedWriteHalf::peer_addr(self)
    }
    fn poll_write(
        &mut self,
        cx: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut *self), cx, buf)
    }
    fn poll_flush(&mut self, cx: &mut std::task::Context) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut *self), cx)
    }
    fn poll_shutdown(
        &mut self,
        cx: &mut std::task::Context,
        _how: std::net::Shutdown,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut *self), cx)
    }
}

impl super::AsyncTcpListener for tokio::net::TcpListener {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        tokio::net::TcpListener::local_addr(self)
    }
    fn poll_next(
        &self,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<Box<dyn AsyncTcpStream>>> {
        tokio::net::TcpListener::poll_accept(self, cx).map_ok(|(s, _addr)| Box::new(s) as _)
    }
}

impl super::AsyncTimer for tokio::time::Sleep {
    fn reset(self: std::pin::Pin<&mut Self>, i: std::time::Instant) {
        Self::reset(self, i.into())
    }
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context) -> std::task::Poll<()> {
        Future::poll(self, cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_spawn() {
        let runtime = crate::tests::tokio_multi_runtime();
        let runtime = TokioRuntime::new(runtime.handle().clone());
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        runtime.spawn(Box::pin(async move {
            send.send(42).unwrap();
        }));
        assert_eq!(recv.recv().unwrap(), 42);
    }

    #[test]
    fn tokio_spawn_from_non_tokio_thread() {
        let runtime = crate::tests::tokio_multi_runtime();
        let runtime = TokioRuntime::new(runtime.handle().clone());
        std::thread::scope(move |scope| {
            scope
                .spawn(move || {
                    let (send, recv) = std::sync::mpsc::sync_channel(1);
                    runtime.spawn(Box::pin(async move {
                        send.send(42).unwrap();
                    }));
                    assert_eq!(recv.recv().unwrap(), 42);
                })
                .join()
        })
        .unwrap();
    }

    #[test]
    fn tokio_sleep() {
        let tokio_runtime = crate::tests::tokio_multi_runtime();
        let runtime = TokioRuntime::new(tokio_runtime.handle().clone());
        tokio_runtime.block_on(async move {
            let now = std::time::Instant::now();
            let duration = core::time::Duration::from_secs(1);
            let mut timer = runtime.new_timer(now + duration);
            core::future::poll_fn(|cx| timer.as_mut().poll(cx)).await;
            assert!(std::time::Instant::now() >= now + duration);
        });
    }

    #[test]
    fn tokio_sleep_from_non_tokio_thread() {
        let tokio_runtime = crate::tests::tokio_multi_runtime();
        let runtime = TokioRuntime::new(tokio_runtime.handle().clone());
        std::thread::scope(move |scope| {
            scope
                .spawn(move || {
                    let now = std::time::Instant::now();
                    let duration = core::time::Duration::from_secs(1);
                    let mut timer = runtime.new_timer(now + duration);
                    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
                    assert!(matches!(
                        timer.as_mut().poll(&mut cx),
                        std::task::Poll::Pending
                    ));
                })
                .join()
        })
        .unwrap();
    }

    #[test]
    fn tokio_udp_from_non_tokio_thread() {
        let tokio_runtime = crate::tests::tokio_multi_runtime();
        let runtime = TokioRuntime::new(tokio_runtime.handle().clone());
        std::thread::scope(move |scope| {
            scope
                .spawn(move || {
                    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    let _udp = runtime.wrap_udp_socket(udp).unwrap();
                })
                .join()
        })
        .unwrap();
    }
}
