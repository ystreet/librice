// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use futures::{AsyncReadExt, AsyncWriteExt};
use rice_c::Instant;
use smol::channel::Sender;
use smol::net::{TcpListener, TcpStream, UdpSocket};
use smol::stream::StreamExt;
use stun_proto::agent::Transmit;
use stun_proto::types::{AddressFamily, TransportType};
use turn_server_proto::api::{SocketAllocateError, TurnServerApi, TurnServerPollRet};
use turn_server_proto::server::TurnServer as TurnServerProto;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Allocation {
    client_transport: TransportType,
    client_addr: SocketAddr,
    turn_listen_addr: SocketAddr,
    relayed_udp: Arc<UdpSocket>,
}

#[derive(Debug)]
pub struct TurnServer {
    inner: Arc<Mutex<TurnServerInner>>,
}

impl TurnServer {
    pub async fn new_udp(listen_addr: SocketAddr, realm: String, relay_addr: IpAddr) -> Self {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.unwrap());
        let listen_addr = socket.local_addr().unwrap();
        let inner = Arc::new(Mutex::new(TurnServerInner {
            proto: TurnServerProto::new(TransportType::Udp, listen_addr, realm),
            allocations: Default::default(),
            waker: None,
            socket: ListenSocket::Udp(socket.clone()),
        }));
        let base_instant = std::time::Instant::now();
        Self::udp_listen_task(inner.clone(), socket, base_instant).detach();
        Self::start_task(inner.clone(), relay_addr, base_instant).detach();
        Self { inner }
    }

    pub async fn new_tcp(listen_addr: SocketAddr, realm: String, relay_addr: IpAddr) -> Self {
        let listener = TcpListener::bind(listen_addr).await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let inner = Arc::new(Mutex::new(TurnServerInner {
            proto: TurnServerProto::new(TransportType::Tcp, listen_addr, realm),
            allocations: Default::default(),
            waker: None,
            socket: ListenSocket::Tcp(TcpTurnClient {
                listener: listener.clone(),
                clients: vec![],
            }),
        }));
        let base_instant = std::time::Instant::now();
        Self::tcp_listen_task(inner.clone(), listener, base_instant).detach();
        Self::start_task(inner.clone(), relay_addr, base_instant).detach();
        Self { inner }
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.inner.lock().unwrap().proto.listen_address()
    }

    pub fn add_user(&self, user: &str, pass: &str) {
        self.inner
            .lock()
            .unwrap()
            .proto
            .add_user(user.to_string(), pass.to_string());
    }

    fn start_task(
        inner: Arc<Mutex<TurnServerInner>>,
        relay_addr: IpAddr,
        base_instant: std::time::Instant,
    ) -> smol::Task<()> {
        let mut driver = TurnServerDriver::new(inner, relay_addr, base_instant);
        smol::spawn(async move { while driver.next().await.is_some() {} })
    }

    fn udp_listen_task(
        inner: Arc<Mutex<TurnServerInner>>,
        socket: Arc<UdpSocket>,
        base_instant: std::time::Instant,
    ) -> smol::Task<()> {
        let weak_inner = Arc::downgrade(&inner);
        let listen_addr = socket.local_addr().unwrap();
        smol::spawn(async move {
            let mut buf = [0; 2048];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let buf = &buf[..n];
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let (socket, reply) = {
                    let mut inner = inner.lock().unwrap();
                    trace!(
                        "udp listen {listen_addr} server received {} bytes from {from}",
                        buf.len()
                    );
                    let Some(reply) = inner.proto.recv(
                        Transmit::new(buf, TransportType::Udp, from, listen_addr),
                        Instant::from_std(base_instant),
                    ) else {
                        trace!("udp listen {listen_addr} server no direct reply");
                        if let Some(waker) = inner.waker.take() {
                            waker.wake();
                        }
                        continue;
                    };
                    let Some(socket) =
                        inner.socket_for_5tuple(reply.transport, reply.from, reply.to)
                    else {
                        warn!(
                            "no {} socket for {} -> {}",
                            reply.transport, reply.from, reply.to
                        );
                        continue;
                    };
                    (socket, reply.build())
                };
                trace!(
                    "udp listen {listen_addr} server reply to incoming data: {}",
                    reply.to
                );
                let _ = socket.send_to(reply.data, reply.to).await;
                {
                    let mut inner = inner.lock().unwrap();
                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }
                }
            }
        })
    }

    fn tcp_listen_task(
        inner: Arc<Mutex<TurnServerInner>>,
        listener: TcpListener,
        base_instant: std::time::Instant,
    ) -> smol::Task<()> {
        let weak_inner = Arc::downgrade(&inner);
        smol::spawn(async move {
            let mut incoming = listener.incoming();
            while let Some(Ok(stream)) = incoming.next().await {
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                Self::tcp_stream_listen_task(inner, stream, base_instant).detach();
            }
        })
    }

    fn tcp_stream_listen_task(
        inner: Arc<Mutex<TurnServerInner>>,
        mut stream: TcpStream,
        base_instant: std::time::Instant,
    ) -> smol::Task<()> {
        let weak_inner = Arc::downgrade(&inner);
        let Ok(remote_addr) = stream.peer_addr() else {
            return smol::spawn(async move {});
        };
        let (send, recv) = smol::channel::bounded(4);
        {
            let mut inner = inner.lock().unwrap();
            if let ListenSocket::Tcp(ref mut tcp) = inner.socket {
                tcp.clients.push((remote_addr, send));
            }
        }
        smol::spawn({
            let mut stream = stream.clone();
            async move {
                while let Ok(data) = recv.recv().await {
                    let Ok(_) = stream.write_all(&data).await else {
                        break;
                    };
                }
            }
        })
        .detach();
        smol::spawn(async move {
            let Ok(local_addr) = stream.local_addr() else {
                return;
            };
            let Ok(remote_addr) = stream.peer_addr() else {
                return;
            };
            let mut buf = [0; 2048];
            loop {
                let Ok(n) = stream.read(&mut buf).await else {
                    break;
                };
                if n == 0 {
                    break;
                }
                let buf = &buf[..n];
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let (socket, reply) = {
                    let mut inner = inner.lock().unwrap();
                    trace!("tcp stream received {} bytes from {remote_addr}", buf.len());
                    let Some(reply) = inner.proto.recv(
                        Transmit::new(buf, TransportType::Tcp, remote_addr, local_addr),
                        Instant::from_std(base_instant),
                    ) else {
                        trace!("listen server no direct reply");
                        if let Some(waker) = inner.waker.take() {
                            waker.wake();
                        }
                        continue;
                    };
                    let Some(socket) =
                        inner.socket_for_5tuple(reply.transport, reply.from, reply.to)
                    else {
                        warn!(
                            "no {} socket for {} -> {}",
                            reply.transport, reply.from, reply.to
                        );
                        continue;
                    };
                    (socket, reply.build())
                };
                trace!(
                    "tcp listen {remote_addr} server reply to incoming data over {}: {} -> {}",
                    reply.transport,
                    reply.from,
                    reply.to
                );
                let _ = socket.send_to(reply.data, reply.to).await;
                {
                    let mut inner = inner.lock().unwrap();
                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }
                }
            }
        })
    }
}

#[derive(Debug)]
struct TurnServerInner {
    proto: TurnServerProto,
    allocations: Vec<Allocation>,
    waker: Option<Waker>,
    socket: ListenSocket,
}

#[derive(Debug)]
enum ListenSocket {
    Udp(Arc<UdpSocket>),
    Tcp(TcpTurnClient),
}

#[derive(Debug)]
struct TcpTurnClient {
    listener: TcpListener,
    clients: Vec<(SocketAddr, Sender<Vec<u8>>)>,
}

#[derive(Debug)]
enum SocketOrChannel {
    Socket(Arc<UdpSocket>),
    Channel(Sender<Vec<u8>>),
}

impl SocketOrChannel {
    async fn send_to(&self, data: Vec<u8>, to: SocketAddr) -> std::io::Result<()> {
        match self {
            Self::Socket(socket) => socket.send_to(&data, to).await.map(|_| ()),
            Self::Channel(channel) => channel.send(data).await.map(|_| ()).map_err(|e| match e {
                smol::channel::SendError(_) => {
                    std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted")
                }
            }),
        }
    }
}

impl TurnServerInner {
    fn socket_for_5tuple(
        &self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<SocketOrChannel> {
        match &self.socket {
            ListenSocket::Udp(socket)
                if transport == TransportType::Udp
                    && socket.local_addr().unwrap() == local_addr =>
            {
                return Some(SocketOrChannel::Socket(socket.clone()));
            }
            ListenSocket::Tcp(tcp)
                if transport == TransportType::Tcp
                    && tcp.listener.local_addr().unwrap() == local_addr =>
            {
                return tcp.clients.iter().find_map(|(client_addr, sender)| {
                    if remote_addr == *client_addr {
                        Some(SocketOrChannel::Channel(sender.clone()))
                    } else {
                        None
                    }
                });
            }
            _ => (),
        }
        trace!("allocations: {:?}", self.allocations);
        for alloc in self.allocations.iter() {
            if transport == TransportType::Udp
                && alloc.relayed_udp.local_addr().unwrap() == local_addr
            {
                return Some(SocketOrChannel::Socket(alloc.relayed_udp.clone()));
            }
        }
        None
    }
}

#[derive(Debug)]
struct TurnServerDriver {
    inner: Arc<Mutex<TurnServerInner>>,
    base_instant: std::time::Instant,
    timer: Pin<Box<smol::Timer>>,
    relayed_ip: IpAddr,
    pending_transmit: Option<stun_proto::agent::Transmit<Vec<u8>>>,
    transmit_sender: Sender<stun_proto::agent::Transmit<Vec<u8>>>,
}

impl TurnServerDriver {
    fn new(
        inner: Arc<Mutex<TurnServerInner>>,
        relayed_ip: IpAddr,
        base_instant: std::time::Instant,
    ) -> Self {
        let weak_inner = Arc::downgrade(&inner);
        let (send, recv) = smol::channel::bounded::<Transmit<Vec<u8>>>(4);
        smol::spawn(async move {
            while let Ok(transmit) = recv.recv().await {
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let socket = {
                    let inner = inner.lock().unwrap();
                    let Some(socket) =
                        inner.socket_for_5tuple(transmit.transport, transmit.from, transmit.to)
                    else {
                        warn!(
                            "no {} socket for {} -> {}",
                            transmit.transport, transmit.from, transmit.to
                        );
                        continue;
                    };
                    socket
                };
                trace!(
                    "sender server sending {} bytes over {} {} -> {}",
                    transmit.data.len(),
                    transmit.transport,
                    transmit.from,
                    transmit.to
                );
                let _ = socket.send_to(transmit.data, transmit.to).await;
                {
                    let mut inner = inner.lock().unwrap();
                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }
                }
            }
        })
        .detach();
        Self {
            inner,
            base_instant,
            timer: Box::pin(smol::Timer::never()),
            relayed_ip,
            pending_transmit: None,
            transmit_sender: send,
        }
    }

    fn udp_allocate(
        &self,
        client_transport: TransportType,
        listen_addr: SocketAddr,
        client_addr: SocketAddr,
        family: AddressFamily,
    ) {
        let weak_inner = Arc::downgrade(&self.inner);
        let relayed_ip = self.relayed_ip;
        let base_instant = self.base_instant;
        smol::spawn(async move {
            let socket = if (family == stun_proto::types::AddressFamily::IPV4
                && relayed_ip.is_ipv4())
                || (family == stun_proto::types::AddressFamily::IPV6 && relayed_ip.is_ipv6())
            {
                UdpSocket::bind(SocketAddr::new(relayed_ip, 0)).await
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "Wrong address family",
                ))
            };
            let Some(inner) = weak_inner.upgrade() else {
                return;
            };
            let socket = socket
                .and_then(|s| {
                    s.local_addr().map(|local_addr| {
                        let socket = Arc::new(s);
                        TurnServer::udp_listen_task(inner.clone(), socket.clone(), base_instant)
                            .detach();
                        (local_addr, socket)
                    })
                })
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AddrNotAvailable {
                        SocketAllocateError::AddressFamilyNotSupported
                    } else {
                        SocketAllocateError::InsufficientCapacity
                    }
                });
            let mut inner = inner.lock().unwrap();
            let socket_addr = socket.map(|(addr, socket)| {
                inner.allocations.push(Allocation {
                    client_transport,
                    client_addr,
                    turn_listen_addr: listen_addr,
                    relayed_udp: socket,
                });
                addr
            });
            inner.proto.allocated_socket(
                client_transport,
                listen_addr,
                client_addr,
                TransportType::Udp,
                family,
                socket_addr,
                Instant::from_std(base_instant),
            );
            if let Some(waker) = inner.waker.take() {
                waker.wake();
            }
        })
        .detach();
    }
}

impl futures::Stream for TurnServerDriver {
    type Item = ();
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some(transmit) = self.pending_transmit.take() {
            let mut inner = self.inner.lock().unwrap();
            inner.waker = Some(cx.waker().clone());
            if let Err(smol::channel::TrySendError::Full(transmit)) =
                self.transmit_sender.try_send(transmit)
            {
                drop(inner);
                self.pending_transmit = Some(transmit);
            }
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.waker = Some(cx.waker().clone());
        if let Some(transmit) = inner
            .proto
            .poll_transmit(Instant::from_std(self.base_instant))
        {
            if let Err(smol::channel::TrySendError::Full(transmit)) =
                self.transmit_sender.try_send(transmit)
            {
                drop(inner);
                self.pending_transmit = Some(transmit);
            }
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        let wait = match inner.proto.poll(Instant::from_std(self.base_instant)) {
            TurnServerPollRet::WaitUntil(wait_until) => wait_until,
            TurnServerPollRet::AllocateSocket {
                transport,
                listen_addr,
                client_addr,
                allocation_transport: _,
                family,
            } => {
                drop(inner);
                trace!(
                    "allocating socket for {transport}, {listen_addr} -> {client_addr} {family}"
                );
                self.udp_allocate(transport, listen_addr, client_addr, family);
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            TurnServerPollRet::TcpClose {
                local_addr: _,
                remote_addr: _,
            } => unimplemented!(),
            TurnServerPollRet::TcpConnect {
                relayed_addr: _,
                peer_addr: _,
                listen_addr: _,
                client_addr: _,
            } => unimplemented!(),
            TurnServerPollRet::SocketClose {
                transport: _,
                listen_addr: _,
            } => {
                warn!("TURN Server socket close unimplemented");
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        drop(inner);
        let instant = wait.to_std(self.base_instant);
        self.as_mut().timer.as_mut().set_at(instant);
        if core::future::Future::poll(self.as_mut().timer.as_mut(), cx).is_pending() {
            return std::task::Poll::Pending;
        }
        // timeout value passed, rerun our loop which will make more progress
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }
}
