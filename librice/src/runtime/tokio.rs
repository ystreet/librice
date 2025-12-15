// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};

use tokio::time::sleep_until;

use crate::runtime::{AsyncTcpStream, AsyncTcpStreamRead, AsyncTcpStreamWrite, Runtime};

/// An async implementation for use with Tokio.
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }
    fn new_timer(&self, i: std::time::Instant) -> std::pin::Pin<Box<dyn super::AsyncTimer>> {
        Box::pin(sleep_until(i.into()))
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<std::sync::Arc<dyn super::AsyncUdpSocket>> {
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
