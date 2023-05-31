// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::{SocketAddr, TcpListener, UdpSocket};

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use futures::StreamExt;

use get_if_addrs::get_if_addrs;

use crate::candidate::{Candidate, CandidateType, TcpType, TransportType};
use crate::stun::agent::StunAgent;
use crate::stun::agent::StunError;
use crate::stun::attribute::*;
use crate::stun::message::*;
use crate::stun::socket::{StunChannel, UdpSocketChannel};

#[derive(Debug, Clone)]
pub enum GatherSocket {
    Udp(UdpSocketChannel),
    Tcp(Arc<TcpListener>),
    #[cfg(test)]
    Async(crate::stun::socket::tests::AsyncChannel),
}

impl GatherSocket {
    pub fn transport(&self) -> TransportType {
        match self {
            GatherSocket::Udp(_) => TransportType::Udp,
            GatherSocket::Tcp(_) => TransportType::Tcp,
            #[cfg(test)]
            GatherSocket::Async(_) => TransportType::AsyncChannel,
        }
    }
}

fn address_is_ignorable(ip: IpAddr) -> bool {
    // TODO: add is_benchmarking() and is_documentation() when they become stable
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_broadcast() || ipv4.is_link_local(),
        IpAddr::V6(_ipv6) => false,
    }
}

pub fn iface_sockets() -> Result<impl Stream<Item = Result<GatherSocket, std::io::Error>>, StunError>
{
    let mut ifaces = get_if_addrs()?;
    // We only care about non-loopback interfaces for now
    // TODO: remove 'Deprecated IPv4-compatible IPv6 addresses [RFC4291]'
    // TODO: remove 'IPv6 site-local unicast addresses [RFC3879]'
    // TODO: remove 'IPv4-mapped IPv6 addresses unless ipv6 only'
    // TODO: location tracking Ipv6 address mismatches
    ifaces.retain(|e| !address_is_ignorable(e.ip()));

    for _f in ifaces.iter().inspect(|iface| {
        info!("Found interface {} address {:?}", iface.name, iface.ip());
    }) {}

    Ok(futures::stream::iter(ifaces.clone().into_iter())
        .then(|iface| async move {
            Ok(GatherSocket::Udp(UdpSocketChannel::new(
                UdpSocket::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
            )))
        })
        .chain(
            futures::stream::iter(ifaces.into_iter()).then(|iface| async move {
                Ok(GatherSocket::Tcp(Arc::new(
                    TcpListener::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
                )))
            }),
        ))
}

fn generate_bind_request() -> std::io::Result<Message> {
    let mut out = Message::new_request(BINDING);
    out.add_fingerprint()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;

    trace!("generated to {}", out);
    Ok(out)
}

#[derive(Debug)]
struct GatherCandidateAddress {
    ctype: CandidateType,
    other_preference: u16,
    transport: TransportType,
    tcp_type: Option<TcpType>,
    address: SocketAddr,
    base: SocketAddr,
    related: Option<SocketAddr>,
}

async fn gather_stun_xor_address(
    other_preference: u16,
    socket: GatherSocket,
    stun_transport: TransportType,
    stun_server: SocketAddr,
) -> Result<GatherCandidateAddress, StunError> {
    let msg = generate_bind_request()?;

    match socket {
        GatherSocket::Udp(channel) => {
            let agent = StunAgent::new(StunChannel::UdpAny(channel));
            if stun_transport != TransportType::Udp {
                return Err(StunError::WrongImplementation);
            }
            agent
                .stun_request_transaction(&msg, stun_server)?
                .build()?
                .perform()
                .await
                .and_then(move |(response, from)| {
                    if let Some(attr) = response.attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS) {
                        debug!(
                            "got external address {:?}",
                            attr.addr(response.transaction_id())
                        );
                        return Ok(GatherCandidateAddress {
                            ctype: CandidateType::ServerReflexive,
                            other_preference,
                            transport: stun_transport,
                            tcp_type: None,
                            address: attr.addr(response.transaction_id()),
                            base: from,
                            related: Some(stun_server),
                        });
                    }
                    Err(StunError::Failed)
                })
        }
        // FIXME: implement TCP STUN gather
        GatherSocket::Tcp(_listener) => Err(StunError::ResourceNotFound),
        #[cfg(test)]
        GatherSocket::Async(_channel) => Err(StunError::ResourceNotFound),
    }
}

fn udp_socket_host_gather_candidate(
    socket: Arc<UdpSocket>,
    other_preference: u16,
) -> Result<GatherCandidateAddress, StunError> {
    let local_addr = socket.local_addr().unwrap();
    Ok(GatherCandidateAddress {
        ctype: CandidateType::Host,
        other_preference,
        transport: TransportType::Udp,
        tcp_type: None,
        address: local_addr,
        base: local_addr,
        related: None,
    })
}

fn tcp_passive_host_gather_candidate(
    socket: Arc<TcpListener>,
    other_preference: u16,
) -> Result<GatherCandidateAddress, StunError> {
    let local_addr = socket.local_addr().unwrap();
    Ok(GatherCandidateAddress {
        ctype: CandidateType::Host,
        other_preference,
        transport: TransportType::Tcp,
        tcp_type: Some(TcpType::Passive),
        address: local_addr,
        base: local_addr,
        related: None,
    })
}

fn tcp_active_host_gather_candidate(
    socket: Arc<TcpListener>,
    other_preference: u16,
) -> Result<GatherCandidateAddress, StunError> {
    let local_addr = socket.local_addr().unwrap();
    // port is ignored with tcp active candidates
    let local_addr = SocketAddr::new(local_addr.ip(), 9);
    Ok(GatherCandidateAddress {
        ctype: CandidateType::Host,
        other_preference,
        transport: TransportType::Tcp,
        tcp_type: Some(TcpType::Active),
        address: local_addr,
        base: local_addr,
        related: None,
    })
}

pub fn gather_component(
    component_id: usize,
    sockets: &[GatherSocket],
    stun_servers: Vec<(TransportType, SocketAddr)>,
) -> impl Stream<Item = (Candidate, GatherSocket)> {
    let futures = futures::stream::FuturesUnordered::new();

    let sockets_len = sockets.len();

    for (i, socket) in sockets.iter().enumerate() {
        match socket {
            GatherSocket::Udp(channel) => futures.push(
                futures::future::ready(
                    udp_socket_host_gather_candidate(
                        channel.socket(),
                        (sockets_len - i) as u16 * 3 + 2,
                    )
                    .map(|ga| (ga, socket.clone())),
                )
                .boxed_local(),
            ),
            GatherSocket::Tcp(listener) => {
                futures.push(
                    futures::future::ready(
                        tcp_passive_host_gather_candidate(
                            listener.clone(),
                            (sockets_len - i) as u16 * 2 + 1,
                        )
                        .map(|ga| (ga, socket.clone())),
                    )
                    .boxed_local(),
                );
                futures.push(
                    futures::future::ready(
                        tcp_active_host_gather_candidate(
                            listener.clone(),
                            (sockets_len - i) as u16 * 3,
                        )
                        .map(|ga| (ga, socket.clone())),
                    )
                    .boxed_local(),
                );
            }
            #[cfg(test)]
            GatherSocket::Async(_channel) => (),
        };
    }

    for (i, socket) in sockets.iter().cloned().enumerate() {
        for stun_server in stun_servers.iter() {
            futures.push(
                {
                    let socket = socket.clone();
                    let stun_server = *stun_server;
                    async move {
                        gather_stun_xor_address(
                            (sockets_len - i) as u16 * 3,
                            socket.clone(),
                            stun_server.0,
                            stun_server.1,
                        )
                        .await
                        .map(move |ga| (ga, socket))
                    }
                }
                .boxed_local(),
            )
        }
    }

    // TODO: add peer-reflexive and relayed (TURN) candidates

    let produced = Arc::new(Mutex::new(Vec::new()));
    futures.filter_map(move |ga| {
        let produced = produced.clone();
        async move {
            match ga {
                Ok((ga, channel)) => {
                    let priority = Candidate::calculate_priority(
                        ga.ctype,
                        ga.transport,
                        ga.tcp_type,
                        ga.other_preference as u32,
                        component_id,
                    );
                    trace!("candidate {:?}, {:?}", ga, priority);
                    if address_is_ignorable(ga.address.ip()) {
                        return None;
                    }
                    if address_is_ignorable(ga.base.ip()) {
                        return None;
                    }
                    let mut produced = produced.lock().unwrap();
                    let mut builder = Candidate::builder(
                        component_id,
                        ga.ctype,
                        ga.transport,
                        &produced.len().to_string(),
                        ga.address,
                    )
                    .priority(priority)
                    .base_address(ga.base);
                    if let Some(related) = ga.related {
                        builder = builder.related_address(related);
                    }
                    if let Some(tcp_type) = ga.tcp_type {
                        builder = builder.tcp_type(tcp_type);
                    }
                    let cand = builder.build();
                    for c in produced.iter() {
                        // ignore candidates that produce the same local/remote pair of
                        // addresses
                        if cand.redundant_with(c) {
                            trace!("redundant {:?}", cand);
                            return None;
                        }
                    }
                    debug!("producing {:?}", cand);
                    produced.push(cand.clone());
                    Some((cand, channel))
                }
                Err(e) => {
                    trace!("candidate retrieval error \'{:?}\'", e);
                    None
                }
            }
        }
    })
}
