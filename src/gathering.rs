// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::net::{SocketAddr, UdpSocket};

use std::sync::{Arc, Mutex};

use futures::prelude::*;
use futures::StreamExt;

use get_if_addrs::get_if_addrs;

use crate::agent::AgentError;
use crate::candidate::{Candidate, CandidateType, TransportType};
use crate::socket::{SocketChannel, UdpSocketChannel};
use crate::stun::agent::StunAgent;
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
) -> Result<impl Stream<Item = Result<SocketChannel, std::io::Error>>, AgentError> {
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
            Ok(SocketChannel::Udp(UdpSocketChannel::new(
                UdpSocket::bind(SocketAddr::new(iface.clone().ip(), 0)).await?,
            )))
        }),
    )
}

fn generate_bind_request() -> std::io::Result<Message> {
    let mut out = Message::new_request(BINDING);
    out.add_fingerprint()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message"))?;

    info!("generated to {}", out);
    Ok(out)
}

#[derive(Debug)]
struct GatherCandidateAddress {
    ctype: CandidateType,
    local_preference: u8,
    transport: TransportType,
    address: SocketAddr,
    base: SocketAddr,
    related: Option<SocketAddr>,
}

async fn gather_stun_xor_address(
    local_preference: u8,
    agent: StunAgent,
    transport: TransportType,
    stun_server: SocketAddr,
) -> Result<GatherCandidateAddress, AgentError> {
    let msg = generate_bind_request()?;

    agent.stun_request_transaction(&msg, stun_server).await
        .and_then(move |(response, _msg_data, from)| {
            if let Some(attr) = response.get_attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS) {
                debug!("got external address {:?}", attr.addr(response.transaction_id()));
                // we don't need any more retransmissions
                return Ok(GatherCandidateAddress {
                    ctype: CandidateType::ServerReflexive,
                    local_preference,
                    transport,
                    address: attr.addr(response.transaction_id()),
                    base: from,
                    related: Some(stun_server),
                });
            }
            Err(AgentError::Malformed)
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
        transport: TransportType::Udp,
        address: local_addr,
        base: local_addr,
        related: None,
    })
}

pub fn gather_component(
    component_id: usize,
    local_agents: Vec<StunAgent>,
    stun_servers: Vec<(TransportType, SocketAddr)>,
) -> Result<impl Stream<Item = (Candidate, StunAgent)>, AgentError> {
    let futures = futures::stream::FuturesUnordered::new();

    for f in local_agents.iter().enumerate().filter_map(|(i, agent)| {
        match &agent.inner.channel {
            SocketChannel::Udp(schannel) => {
                Some(futures::future::ready(
                    udp_socket_host_gather_candidate(schannel.socket(), (i * 10) as u8)
                        .map(|ga| (ga, agent.clone())),
                ))
            },
            _ => None,
        }
    }) {
        futures.push(f.boxed_local());
    }

    for (i, agent) in local_agents.iter().cloned().enumerate() {
        for stun_server in stun_servers.iter() {
            futures.push(
                {
                    let agent = agent.clone();
                    let stun_server = *stun_server;
                    async move {
                        gather_stun_xor_address(
                            (i * 10) as u8,
                            agent.clone(),
                            stun_server.0,
                            stun_server.1
                        )
                        .await
                        .map(move |ga| (ga, agent))
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
