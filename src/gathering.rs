// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::{SocketAddr, UdpSocket};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{AbortHandle, Either};
use futures::prelude::*;
use futures::StreamExt;
use futures_timer::Delay;

use get_if_addrs::get_if_addrs;

use crate::agent::AgentError;
use crate::candidate::{Candidate, CandidateType, TransportType};
use crate::socket::{SocketChannel, UdpConnectionChannel, UdpSocketChannel};
use crate::stun::attribute::*;
use crate::stun::message::*;

fn priority_type_preference(ctype: CandidateType) -> u32 {
    match ctype {
        CandidateType::Host => 126,
        CandidateType::PeerReflexive => 110,
        CandidateType::ServerReflexive => 100,
        CandidateType::Relayed => 0,
    }
}

fn calculate_priority(ctype: CandidateType, local_preference: u32, component_id: usize) -> u32 {
    ((1 << 24) * priority_type_preference(ctype)) + ((1 << 8) * local_preference) + 256
        - component_id as u32
}

fn candidate_is_redundant_with(a: &Candidate, b: &Candidate) -> bool {
    a.address.ip() == b.address.ip() && a.base_address.ip() == b.base_address.ip()
}

pub fn iface_udp_sockets(
) -> Result<impl Stream<Item = Result<Arc<UdpSocketChannel>, std::io::Error>>, AgentError> {
    let mut ifaces = get_if_addrs()?;
    // We only care about non-loopback interfaces for now
    // TODO: remove 'Deprecated IPv4-compatible IPv6 addresses [RFC4291]'
    // TODO: remove 'IPv6 site-local unicast addresses [RFC3879]'
    // TODO: remove 'IPv4-mapped IPv6 addresses unless ipv6 only'
    // TODO: location tracking Ipv6 address mismatches
    ifaces.retain(|e| !e.is_loopback());

    for _f in ifaces.iter().inspect(|iface| {
        info!("Found interface {} address {:?}", iface.name, iface.ip());
    }) {}

    Ok(
        futures::stream::iter(ifaces.into_iter()).then(|iface| async move {
            Ok(Arc::new(UdpSocketChannel::new(
                UdpSocket::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
            )))
        }),
    )
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
    schannel: Arc<SocketChannel>,
    recv_abort_handle: AbortHandle,
) -> Result<SocketAddr,AgentError> {
    // FIXME: fix these timeout values
    let timeouts: [u64; 4] = [0, 1, 2, 3];
    for timeout in timeouts.iter() {
        Delay::new(Duration::from_secs(*timeout)).await;
        info!("sending {}", msg);
        let buf = msg.to_bytes();
        trace!("sending {:?}", buf);
        schannel.send(&buf).await?;
    }

    // on failure, abort the receiver waiting
    recv_abort_handle.abort();
    Err(AgentError::TimedOut)
}

async fn listen_for_xor_address_response(
    transaction_id: u128,
    schannel: Arc<SocketChannel>,
    send_abort_handle: AbortHandle,
) -> Result<SocketAddr,AgentError> {
    let mut s = schannel.receive_stream();
    while let Some(buf) = s.next().await {
        let from = schannel.remote_addr().unwrap();
        trace!("got from {:?} data {:?}", from, buf);

        // XXX: Too restrictive?
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
                if let Ok(attr) = XorMappedAddress::from_raw(&attr) {
                    debug!("got external address {:?}", attr.addr(transaction_id));
                    // we don't need any more retransmissions
                    send_abort_handle.abort();
                    return Ok(attr.addr(transaction_id));
                }
            }
        }
    }
    Err(AgentError::ConnectionClosed)
}

#[derive(Debug)]
struct GatherCandidateAddress {
    ctype: CandidateType,
    local_preference: u8,
    address: SocketAddr,
    base: SocketAddr,
    related: Option<SocketAddr>,
}

async fn gather_stun_xor_address(
    from: SocketAddr,
    local_preference: u8,
    schannel: Arc<SocketChannel>,
) -> Result<GatherCandidateAddress, AgentError> {
    // perform an unauthenticated stun binding request against the stun server pointed to by
    // @schannel and wait for the response (or timeout).
    let remote_addr = schannel.remote_addr().unwrap();

    let msg = generate_bind_request(from)?;
    let transaction_id = msg.transaction_id();

    let (recv_abort_handle, recv_registration) = futures::future::AbortHandle::new_pair();
    let (send_abortable, send_abort_handle) = futures::future::abortable(
        send_message_with_retransmissions_delay(msg, schannel.clone(), recv_abort_handle),
    );

    let recv_abortable = futures::future::Abortable::new(
        listen_for_xor_address_response(transaction_id, schannel, send_abort_handle),
        recv_registration,
    );

    futures::pin_mut!(recv_abortable);
    futures::pin_mut!(send_abortable);

    // race the sending and receiving futures returning the first that succeeds
    match futures::future::try_select(send_abortable, recv_abortable).await {
        Ok(Either::Left((x, _))) => x,
        Ok(Either::Right((y, _))) => y,
        Err(_) => unreachable!(),
    }
    .map(move |addr| {
        GatherCandidateAddress {
            ctype: CandidateType::ServerReflexive,
            local_preference,
            address: addr,
            base: from,
            related: Some(remote_addr),
        }
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
        address: local_addr,
        base: local_addr,
        related: None,
    })
}

pub fn gather_component(
    component_id: usize,
    schannels: Vec<Arc<UdpSocketChannel>>,
    stun_servers: Vec<SocketAddr>,
) -> Result<impl Stream<Item = (Candidate, Arc<UdpSocketChannel>)>, AgentError> {
    let futures = futures::stream::FuturesUnordered::new();

    for f in schannels.iter().enumerate().map(|(i, schannel)| {
        futures::future::ready(
            udp_socket_host_gather_candidate(schannel.socket(), (i * 10) as u8)
                .map(|ga| (ga, schannel.clone())),
        )
    }) {
        futures.push(f.boxed_local());
    }

    for (i, schannel) in schannels.iter().cloned().enumerate() {
        for stun_server in stun_servers.iter() {
            futures.push(
                {
                    let schannel = schannel.clone();
                    let stun_server = *stun_server;
                    let local_addr = schannel.local_addr().unwrap();
                    async move {
                        let chan = Arc::new(SocketChannel::Udp(UdpConnectionChannel::new(
                            schannel.clone(),
                            stun_server,
                        )));
                        gather_stun_xor_address(local_addr, (i * 10) as u8, chan)
                            .await
                            .map(move |ga| (ga, schannel))
                    }
                }
                .boxed_local(),
            )
        }
    }

    // TODO: add peer-reflexive and relayed (TURN) candidates

    let produced = Arc::new(Mutex::new(Vec::new()));
    Ok(futures.filter_map(move |ga| {
        let produced = produced.clone();
        async move {
            match ga {
                Ok((ga, channel)) => {
                    let priority =
                        calculate_priority(ga.ctype, ga.local_preference as u32, component_id);
                    trace!("candidate {:?}, {:?}", ga, priority);
                    let mut produced = produced.lock().unwrap();
                    let cand = Candidate::new(
                        ga.ctype,
                        TransportType::Udp,
                        &produced.len().to_string(),
                        priority,
                        ga.address,
                        ga.base,
                        ga.related,
                    );
                    for c in produced.iter() {
                        // ignore candidates that produce the same local/remote pair of
                        // addresses
                        if candidate_is_redundant_with(&cand, c) {
                            trace!("redundant {:?}", cand);
                            return None;
                        }
                    }
                    info!("producing {:?}", cand);
                    produced.push(cand.clone());
                    Some((cand, channel))
                }
                Err(e) => {
                    trace!("candidate retrieval error \'{:?}\'", e);
                    None
                }
            }
        }
    }))
}
