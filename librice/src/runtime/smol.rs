// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::future::Future;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Poll};

use futures::FutureExt;
use smol::{Async, Timer};

use crate::runtime::{
    AsyncTcpStream, AsyncTcpStreamRead, AsyncTcpStreamWrite, AsyncTimer, Runtime,
};

/// An async implemtnation for use with `smol`.
#[derive(Debug)]
pub struct SmolRuntime;

impl Runtime for SmolRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        smol::spawn(future).detach()
    }
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn super::AsyncTimer>> {
        Box::pin(smol::Timer::at(i))
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn super::AsyncUdpSocket>> {
        Ok(Arc::new(SmolUdpSocket {
            io: Async::new_nonblocking(socket)?,
        }))
    }
    fn new_tcp_listener(
        &self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn super::AsyncTcpListener>>> + Send>>
    {
        Box::pin(async move { SmolTcpListener::bind(addr).map(|s| Arc::new(s) as _) })
    }
    fn tcp_connect(
        &self,
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Box<dyn AsyncTcpStream>>> + Send>> {
        Box::pin(async move {
            Async::<TcpStream>::connect(peer)
                .await
                .map(|s| Box::new(smol::net::TcpStream::from(s)) as _)
        })
    }
}

#[derive(Debug)]
struct SmolUdpSocket {
    io: Async<std::net::UdpSocket>,
}

impl super::AsyncUdpSocket for SmolUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        dest: &mut [u8],
    ) -> Poll<std::io::Result<(usize, std::net::SocketAddr)>> {
        loop {
            ready!(self.io.poll_readable(cx))?;
            if let Ok(res) = self.io.get_ref().recv_from(dest) {
                return Poll::Ready(Ok(res));
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
            ready!(self.io.poll_writable(cx))?;
            match self.io.get_ref().send_to(src, to) {
                Ok(bytes) => return Poll::Ready(Ok(bytes)),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    } else {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct SmolTcpListener {
    io: Async<TcpListener>,
}

impl super::AsyncTcpListener for SmolTcpListener {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
    fn poll_next(
        &self,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<Box<dyn super::AsyncTcpStream>>> {
        ready!(self.io.poll_readable(cx))?;
        let fut = self.io.accept();
        let mut fut = core::pin::pin!(fut);
        fut.poll_unpin(cx)
            .map_ok(|(stream, _remote_addr)| Box::new(smol::net::TcpStream::from(stream)) as _)
    }
}

impl SmolTcpListener {
    fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            io: Async::<TcpListener>::bind(addr)?,
        })
    }
}

impl super::AsyncTcpStream for smol::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::peer_addr(self)
    }
    fn split(self: Box<Self>) -> (Box<dyn AsyncTcpStreamRead>, Box<dyn AsyncTcpStreamWrite>) {
        (self.clone(), self)
    }
}

impl super::AsyncTcpStreamRead for smol::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::peer_addr(self)
    }
    fn poll_read(
        &mut self,
        cx: &mut std::task::Context,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        smol::io::AsyncRead::poll_read(Pin::new(&mut *self), cx, buf)
    }
}

impl super::AsyncTcpStreamWrite for smol::net::TcpStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::local_addr(self)
    }
    fn remote_addr(&self) -> std::io::Result<SocketAddr> {
        smol::net::TcpStream::peer_addr(self)
    }
    fn poll_write(
        &mut self,
        cx: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        smol::io::AsyncWrite::poll_write(Pin::new(&mut *self), cx, buf)
    }
    fn poll_flush(&mut self, cx: &mut std::task::Context) -> Poll<std::io::Result<()>> {
        smol::io::AsyncWrite::poll_flush(Pin::new(&mut *self), cx)
    }
    fn poll_shutdown(
        &mut self,
        cx: &mut std::task::Context,
        how: std::net::Shutdown,
    ) -> Poll<std::io::Result<()>> {
        self.shutdown(how)?;
        smol::io::AsyncWrite::poll_close(Pin::new(&mut *self), cx)
    }
}

impl AsyncTimer for Timer {
    fn reset(mut self: Pin<&mut Self>, i: std::time::Instant) {
        self.set_at(i)
    }
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<()> {
        Future::poll(self, cx).map(|_| ())
    }
}
