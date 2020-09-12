// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::{SocketAddr, UdpSocket};

use async_channel;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures;
use futures::future::{AbortHandle, Either};
use futures::prelude::*;
use futures::StreamExt;
use futures_timer::Delay;

use get_if_addrs::get_if_addrs;

use crate::agent::AgentError;
use crate::candidate::{Candidate, CandidateType, TransportType};
use crate::stun::message::*;
use crate::stun::attribute::*;
use crate::socket::{SocketChannel, UdpSocketChannel};

fn priority_type_preference(ctype: CandidateType) -> u32 {
    match ctype {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
        CandidateType::Relayed => 0,
    }
}

fn calculate_priority(ctype: CandidateType, local_preference: u32, component_id: u32) -> u32 {
    ((1 << 24) * priority_type_preference(ctype)) + ((1 << 8) * local_preference) + 256 - component_id
}

fn candidate_is_redundant_with(a: &Candidate, b: &Candidate) -> bool {
    a.address.ip() == b.address.ip() && a.base_address.ip() == b.base_address.ip()
}

pub fn iface_udp_sockets() -> Result<impl Stream<Item = Result<Arc<SocketChannel>, std::io::Error>>, AgentError> {
    let mut ifaces = get_if_addrs ().map_err(|e| AgentError::IoError(e))?;
    // We only care about non-loopback interfaces for now
    // TODO: remove 'Deprecated IPv4-compatible IPv6 addresses [RFC4291]'
    // TODO: remove 'IPv6 site-local unicast addresses [RFC3879]'
    // TODO: remove 'IPv4-mapped IPv6 addresses unless ipv6 only'
    // TODO: location tracking Ipv6 address mismatches
    ifaces.retain(|e| {!e.is_loopback()});

    for _f in ifaces.iter().inspect(|iface| {
        info!("Found interface {} address {:?}", iface.name, iface.ip());
    }) {}

    Ok(futures::stream::iter(ifaces.into_iter()).then(|iface| async move {
        Ok(Arc::new(SocketChannel::Udp(UdpSocketChannel::new(UdpSocket::bind(SocketAddr::new(iface.clone().ip(), 0)).await?))))
    }))
}

fn generate_bind_request(from: SocketAddr) -> std::io::Result<Message> {
    let mtype = MessageType::from_class_method(MessageClass::Request, BINDING);
    let mut out = Message::new(mtype, Message::generate_transaction());
    out.add_attribute(
        XorMappedAddress::new(from, out.transaction_id())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?
            .to_raw(),
    )
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;

    info!("generated to {}", out);
    Ok(out)
}

async fn send_message_with_retransmissions_delay(
    msg: Message,
    addr: SocketAddr,
    send_channel: async_channel::Sender<(Vec<u8>, SocketAddr)>,
    recv_abort_handle: AbortHandle,
) -> std::io::Result<SocketAddr> {
    // FIXME: fix these timeout values
    let timeouts: [u64; 4] = [0, 1, 2, 3];
    for timeout in timeouts.iter() {
        Delay::new(Duration::from_secs(timeout.clone())).await;
        info!("sending to {:?} {}", addr, msg);
        let buf = msg.to_bytes();
        trace!("sending to {:?} {:?}", addr, buf);
        send_channel.send((buf, addr)).await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "sending connection closed",
            )
        })?;
    }

    // on failure, abort the receiver waiting
    recv_abort_handle.abort();
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "request timed out",
    ))
}

async fn listen_for_xor_address_response(
    transaction_id: u128,
    stun_server: SocketAddr,
    recv_channel: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
    send_abort_handle: AbortHandle,
) -> std::io::Result<SocketAddr> {
    loop {
        let (buf, from): (Vec<_>, SocketAddr) = recv_channel.recv().await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "receive connection closed",
            )
        })?;

        trace!("got from {:?} data {:?}", from, buf);

        // XXX: Too restrictive?
        if from != stun_server {
            continue;
        }
        if let Ok(msg) = Message::from_bytes(&buf) {
            if msg.get_type().class() != MessageClass::Success {
                continue;
            }
            if msg.transaction_id() != transaction_id {
                continue;
            }

            info!("got response from {:?} {}", from, msg);

            // TODO: handle ALTERNATIVE-SERVER attribute for redirects

            // ignore failed parsing, retransmissions may produce a better value
            if let Some(attr) = msg.get_attribute(XOR_MAPPED_ADDRESS) {
                if let Ok(attr) = XorMappedAddress::from_raw(attr.clone()) {
                    debug!("got external address {:?}", attr.addr(transaction_id));
                    // we don't need any more retransmissions
                    send_abort_handle.abort();
                    return Ok(attr.addr(transaction_id));
                }
            }
        }
    }
}

#[derive(Debug)]
struct GatherCandidateAddress {
    ctype: CandidateType,
    local_preference: u8,
    local: SocketAddr,
    remote: SocketAddr,
}

async fn gather_stun_xor_address(
    from: SocketAddr,
    stun_server: SocketAddr,
    local_preference: u8,
    receive_channel: async_channel::Receiver<(Vec<u8>, SocketAddr)>,
    send_channel: async_channel::Sender<(Vec<u8>, SocketAddr)>,
) -> Result<GatherCandidateAddress, AgentError> {
    let msg = generate_bind_request(from)
        .map_err(|e| AgentError::IoError(e))?;
    let transaction_id = msg.transaction_id();

    let (recv_abort_handle, recv_registration) = futures::future::AbortHandle::new_pair();
    let (send_abortable, send_abort_handle) = futures::future::abortable(
        send_message_with_retransmissions_delay(msg, stun_server, send_channel, recv_abort_handle),
    );

    let recv_abortable = futures::future::Abortable::new(
        listen_for_xor_address_response(transaction_id, stun_server, receive_channel, send_abort_handle),
        recv_registration,
    );

    futures::pin_mut!(recv_abortable);
    futures::pin_mut!(send_abortable);

    // race the sending and receiving futures returing the first that succeeds
    match futures::future::try_select(send_abortable, recv_abortable).await {
        Ok(Either::Left((x, _))) => x,
        Ok(Either::Right((y, _))) => y,
        Err(_) => unreachable!(),
    }.map_err(|e| {
        AgentError::IoError(e)
    }).and_then(move |addr| {
        Ok(GatherCandidateAddress {
            ctype: CandidateType::ServerReflexive,
            local_preference,
            local: from.clone(),
            remote: addr,
        })
    })
}

fn udp_socket_host_gather_candidate(
    socket: Arc<UdpSocket>,
    local_preference: u8,
) -> Result<GatherCandidateAddress, AgentError> {
    let local_addr = socket.local_addr().unwrap();
    Ok(GatherCandidateAddress {
        ctype: CandidateType::Host,
        local_preference,
        local: local_addr.clone(),
        remote: local_addr.clone()
    })
}

pub fn gather_component (
    component_id: u32,
    schannels: Vec<Arc<SocketChannel>>,
    stun_servers: Vec<SocketAddr>,
) -> Result<impl Stream<Item = Candidate>, AgentError> {
    let futures = futures::stream::FuturesUnordered::new();

    for f in schannels.iter().enumerate().map(|(i, schannel)| match &*schannel.as_ref() {
        SocketChannel::Udp(udp) => futures::future::ready(udp_socket_host_gather_candidate(udp.socket(), (i * 10) as u8)),
    }) {
        futures.push(f.boxed());
    }

    for (i, schannel) in schannels.iter().enumerate() {
        for stun_server in stun_servers.iter() {
            futures.push(gather_stun_xor_address(schannel.local_addr().unwrap(), stun_server.clone(), (i * 10) as u8, schannel.receive_channel(), schannel.send_channel()).boxed())
        }
    }

    // TODO: add peer-reflexive and relayed (TURN) candidates

    let produced = Arc::new(Mutex::new(Vec::new()));
    Ok(futures
        .filter_map(move |ga| {
            let produced = produced.clone();
            async move {
                match ga {
                    Ok(ga) => {
                        let priority = calculate_priority(ga.ctype, ga.local_preference as u32, component_id);
                        trace!("candidate {:?}, {:?}", ga, priority);
                        let mut produced = produced.lock().unwrap();
                        let cand = Candidate::new(ga.ctype, TransportType::Udp, &produced.len().to_string(), priority, ga.remote, ga.local);
                        for c in produced.iter() {
                            //trace!("reduntant {:?} redundant with produced? {:?}", cand, c);
                            if candidate_is_redundant_with(&cand, c) {
                                trace!("redundant {:?}", cand);
                                return None;
                            }
                        }
                        info!("producing {:?}", cand);
                        produced.push(cand.clone());
                        Some(cand)
                    },
                    Err(e) => {
                        trace!("candidate retrieval error \'{:?}\'", e);
                        None
                    },
                }
            }
        })
    )
}
