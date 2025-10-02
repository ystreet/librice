// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Helpers for retrieving a list of local candidates

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
#[cfg(feature = "openssl")]
use turn_client_proto::openssl::TurnClientOpensslTls;
use turn_client_proto::rustls::TurnClientRustls;

use crate::candidate::{Candidate, TcpType, TransportType};
use crate::turn::TurnConfig;
#[cfg(feature = "rustls")]
use crate::turn::TurnTlsConfig;
use stun_proto::agent::{HandleStunReply, StunAgent, StunAgentPollRet, StunError, Transmit};
use stun_proto::types::attribute::XorMappedAddress;
use stun_proto::types::data::Data;
use stun_proto::types::message::{
    Message, MessageHeader, MessageWriteVec, StunParseError, TransactionId, BINDING,
};
use stun_proto::types::prelude::{MessageWrite, MessageWriteExt};
use stun_proto::types::AddressFamily;
use stun_proto::Instant;
use turn_client_proto::api::{TurnEvent, TurnPollRet, TurnRecvRet};
use turn_client_proto::client::TurnClient;
use turn_client_proto::prelude::*;
use turn_client_proto::tcp::TurnClientTcp;
use turn_client_proto::types::message::ALLOCATE;
use turn_client_proto::udp::TurnClientUdp;

use tracing::{debug, info, trace};

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

#[derive(Debug)]
enum RequestProtocol {
    Udp,
    Tcp(Option<TransactionId>),
}

impl RequestProtocol {
    fn transport(&self) -> TransportType {
        match self {
            RequestProtocol::Udp => TransportType::Udp,
            RequestProtocol::Tcp(_) => TransportType::Tcp,
        }
    }
}

#[derive(Debug)]
enum StunOrTurnClient {
    Stun(Box<StunAgent>),
    Turn(Box<TurnClient>),
}

#[derive(Debug)]
struct Request {
    protocol: RequestProtocol,
    agent: StunOrTurnClient,
    base_addr: SocketAddr,
    server: SocketAddr,
    other_preference: u32,
    component_id: usize,
    completed: bool,
}

#[derive(Debug)]
enum Method {
    Stun,
    Turn(TurnConfig),
}

#[derive(Debug)]
struct PendingRequest {
    completed: bool,
    method: Method,
    component_id: usize,
    transport_type: TransportType,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    other_preference: u32,
    agent_request_time: Option<Instant>,
}

impl PendingRequest {
    fn as_tcp_request(&self, local_addr: SocketAddr) -> Request {
        assert_eq!(self.transport_type, TransportType::Tcp);
        match &self.method {
            Method::Stun => {
                let agent = StunAgent::builder(TransportType::Tcp, local_addr)
                    .remote_addr(self.server_addr)
                    .build();
                Request {
                    protocol: RequestProtocol::Tcp(None),
                    agent: StunOrTurnClient::Stun(Box::new(agent)),
                    base_addr: local_addr,
                    server: self.server_addr,
                    other_preference: self.other_preference,
                    component_id: self.component_id,
                    completed: false,
                }
            }
            Method::Turn(config) => {
                let mut client = None;
                if let Some(tls) = config.tls_config() {
                    match tls {
                        #[cfg(feature = "rustls")]
                        TurnTlsConfig::Rustls(rustls) => {
                            client = Some(TurnClient::from(TurnClientRustls::allocate(
                                local_addr,
                                self.server_addr,
                                config.credentials().clone(),
                                &[AddressFamily::IPV4],
                                rustls.server_name(),
                                rustls.client_config(),
                            )))
                        }
                        #[cfg(feature = "openssl")]
                        TurnTlsConfig::Openssl(ossl) => {
                            client = Some(TurnClient::from(TurnClientOpensslTls::allocate(
                                TransportType::Tcp,
                                local_addr,
                                self.server_addr,
                                config.credentials().clone(),
                                &[AddressFamily::IPV4],
                                ossl.ssl_context().clone(),
                            )))
                        }
                    }
                }
                let client = client.unwrap_or_else(|| {
                    TurnClientTcp::allocate(
                        local_addr,
                        self.server_addr,
                        config.credentials().clone(),
                        &[AddressFamily::IPV4],
                    )
                    .into()
                });
                Request {
                    protocol: RequestProtocol::Tcp(None),
                    agent: StunOrTurnClient::Turn(Box::new(client)),
                    base_addr: local_addr,
                    server: self.server_addr,
                    other_preference: self.other_preference,
                    component_id: self.component_id,
                    completed: false,
                }
            }
        }
    }
}

#[derive(Debug)]
struct PendingTcp {
    from: SocketAddr,
    to: SocketAddr,
}

/// Gatherer that uses STUN to gather a list of local candidates
#[derive(Debug)]
pub struct StunGatherer {
    component_id: usize,
    requests: Vec<Request>,
    pending_candidates: VecDeque<GatheredCandidate>,
    produced_candidates: VecDeque<Candidate>,
    produced_i: usize,
    pending_transmits: VecDeque<Transmit<Data<'static>>>,
    pending_requests: VecDeque<PendingRequest>,
    pending_tcp: VecDeque<PendingTcp>,
    tcp_buffers: VecDeque<GatherTcpBuffer>,
    completed: bool,
}

#[derive(Debug)]
struct GatherTcpBuffer {
    requested_local_addr: SocketAddr,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    tcp_buffer: Vec<u8>,
}

/// A candidate that has been gathered.
#[derive(Debug)]
pub struct GatheredCandidate {
    /// The [`Candidate`].
    pub candidate: Candidate,
    /// An optional TURN agent associated with the candidate.
    pub turn_agent: Option<Box<TurnClient>>,
}

/// Return value for the gather state machine
#[derive(Debug)]
pub(crate) enum GatherPoll {
    /// Need a socket for the specified 5-tuple network address
    AllocateSocket {
        component_id: usize,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    },
    /// Wait until the specified Instant passes
    WaitUntil(Instant),
    /// A new local candidate was discovered
    NewCandidate(GatheredCandidate),
    /// Gathering process is complete for a component
    Complete(usize),
    /// Gathering complete. No further progress can be made.
    Finished,
}

impl StunGatherer {
    /// Create a new gatherer
    pub(crate) fn new(
        component_id: usize,
        sockets: &[(TransportType, SocketAddr)],
        stun_servers: &[(TransportType, SocketAddr)],
        turn_servers: &[&TurnConfig],
    ) -> Self {
        // TODO: what to do on duplicate socket or stun_server addresses?
        let mut pending_candidates = VecDeque::new();
        let mut pending_requests = VecDeque::new();
        for (i, (socket_transport, socket_addr)) in sockets.iter().enumerate() {
            if address_is_ignorable(socket_addr.ip()) {
                continue;
            }
            let other_preference = (sockets.len() - i) as u32 * 2;
            match socket_transport {
                TransportType::Udp => {
                    let priority = Candidate::calculate_priority(
                        crate::candidate::CandidateType::Host,
                        *socket_transport,
                        None,
                        other_preference,
                        component_id,
                    );
                    pending_candidates.push_front(GatheredCandidate {
                        candidate: Candidate::builder(
                            component_id,
                            crate::candidate::CandidateType::Host,
                            *socket_transport,
                            &pending_candidates.len().to_string(),
                            *socket_addr,
                        )
                        .priority(priority)
                        .base_address(*socket_addr)
                        .build(),
                        turn_agent: None,
                    });
                }
                TransportType::Tcp => {
                    let priority = Candidate::calculate_priority(
                        crate::candidate::CandidateType::Host,
                        *socket_transport,
                        Some(crate::candidate::TcpType::Active),
                        other_preference,
                        component_id,
                    );
                    let active_addr = SocketAddr::new(socket_addr.ip(), 9);
                    pending_candidates.push_front(GatheredCandidate {
                        candidate: Candidate::builder(
                            component_id,
                            crate::candidate::CandidateType::Host,
                            *socket_transport,
                            &pending_candidates.len().to_string(),
                            active_addr,
                        )
                        .priority(priority)
                        .tcp_type(crate::candidate::TcpType::Active)
                        .build(),
                        turn_agent: None,
                    });
                    let priority = Candidate::calculate_priority(
                        crate::candidate::CandidateType::Host,
                        *socket_transport,
                        Some(crate::candidate::TcpType::Passive),
                        other_preference + 1,
                        component_id,
                    );
                    pending_candidates.push_front(GatheredCandidate {
                        candidate: Candidate::builder(
                            component_id,
                            crate::candidate::CandidateType::Host,
                            *socket_transport,
                            &pending_candidates.len().to_string(),
                            *socket_addr,
                        )
                        .priority(priority)
                        .tcp_type(crate::candidate::TcpType::Passive)
                        .base_address(*socket_addr)
                        .build(),
                        turn_agent: None,
                    });
                }
            }
            for (stun_transport, stun_addr) in stun_servers.iter().copied().chain(
                turn_servers
                    .iter()
                    .map(|turn_config| (turn_config.client_transport(), turn_config.addr())),
            ) {
                if *socket_transport != stun_transport {
                    continue;
                }
                if socket_addr.is_ipv4() && !stun_addr.is_ipv4() {
                    continue;
                }
                if socket_addr.is_ipv6() && !stun_addr.is_ipv6() {
                    continue;
                }
                pending_requests.push_back(PendingRequest {
                    component_id,
                    transport_type: *socket_transport,
                    local_addr: *socket_addr,
                    server_addr: stun_addr,
                    other_preference,
                    completed: false,
                    agent_request_time: None,
                    method: Method::Stun,
                });
            }
            for turn_config in turn_servers.iter() {
                if *socket_transport != turn_config.client_transport() {
                    continue;
                }
                if socket_addr.is_ipv4() && !turn_config.addr().is_ipv4() {
                    continue;
                }
                if socket_addr.is_ipv6() && !turn_config.addr().is_ipv6() {
                    continue;
                }
                pending_requests.push_back(PendingRequest {
                    component_id,
                    transport_type: *socket_transport,
                    local_addr: *socket_addr,
                    server_addr: turn_config.addr(),
                    other_preference,
                    completed: false,
                    agent_request_time: None,
                    method: Method::Turn((*turn_config).clone()),
                });
            }
        }

        Self {
            component_id,
            requests: Vec::new(),
            pending_candidates,
            produced_candidates: Default::default(),
            produced_i: 0,
            pending_transmits: Default::default(),
            pending_requests,
            pending_tcp: Default::default(),
            tcp_buffers: Default::default(),
            completed: false,
        }
    }

    /// Poll the gatherer.  Should be called repeatedly until [`GatherPoll::WaitUntil`]
    /// or [`GatherPoll::Complete`] is returned.
    #[tracing::instrument(name = "gatherer_poll", level = "trace", ret, skip(self))]
    pub(crate) fn poll(&mut self, now: Instant) -> GatherPoll {
        let mut lowest_wait = None;

        for pending_request in self.pending_requests.iter_mut() {
            if pending_request.completed {
                continue;
            }

            let (protocol, agent, base_addr) = match pending_request.transport_type {
                TransportType::Udp => {
                    pending_request.completed = true;
                    let agent = match &pending_request.method {
                        Method::Stun => {
                            let mut msg = Message::builder_request(BINDING, MessageWriteVec::new());
                            msg.add_fingerprint().unwrap();
                            let mut agent =
                                StunAgent::builder(TransportType::Udp, pending_request.local_addr)
                                    .remote_addr(pending_request.server_addr)
                                    .build();
                            trace!(
                                "adding gather request UDP from {local_addr} to {server_addr}",
                                local_addr = pending_request.local_addr,
                                server_addr = pending_request.server_addr
                            );
                            self.pending_transmits.push_front(
                                agent
                                    .send_request(msg.finish(), pending_request.server_addr, now)
                                    .unwrap()
                                    .into_owned(),
                            );
                            StunOrTurnClient::Stun(Box::new(agent))
                        }
                        Method::Turn(config) => {
                            let mut client = None;
                            if let Some(tls) = config.tls_config() {
                                match tls {
                                    #[cfg(feature = "rustls")]
                                    TurnTlsConfig::Rustls(_rustls) => {
                                        pending_request.completed = true;
                                        continue;
                                    }
                                    #[cfg(feature = "openssl")]
                                    TurnTlsConfig::Openssl(ossl) => {
                                        client =
                                            Some(TurnClient::from(TurnClientOpensslTls::allocate(
                                                TransportType::Udp,
                                                pending_request.local_addr,
                                                pending_request.server_addr,
                                                config.credentials().clone(),
                                                &[AddressFamily::IPV4],
                                                ossl.ssl_context().clone(),
                                            )))
                                    }
                                }
                            }
                            let client = client.unwrap_or_else(|| {
                                TurnClientUdp::allocate(
                                    pending_request.local_addr,
                                    pending_request.server_addr,
                                    config.credentials().clone(),
                                    &[AddressFamily::IPV4],
                                )
                                .into()
                            });
                            StunOrTurnClient::Turn(Box::new(client))
                        }
                    };
                    (RequestProtocol::Udp, agent, pending_request.local_addr)
                }
                TransportType::Tcp => {
                    if pending_request.agent_request_time.is_none() {
                        let active_addr = SocketAddr::new(pending_request.local_addr.ip(), 9);
                        if let Some(idx) = self.tcp_buffers.iter().position(|buf| {
                            buf.requested_local_addr == active_addr
                                && buf.remote_addr == pending_request.server_addr
                        }) {
                            pending_request.completed = true;
                            self.requests.push(
                                pending_request.as_tcp_request(self.tcp_buffers[idx].local_addr),
                            );
                            continue;
                        }
                        pending_request.local_addr = active_addr;
                        pending_request.agent_request_time = Some(now);
                        if self.pending_tcp.iter().all(|pending_tcp| {
                            pending_tcp.from != active_addr
                                || pending_tcp.to != pending_request.server_addr
                        }) {
                            trace!(
                                "adding gather request TCP {active_addr} from {local_addr} to {server_addr}",
                                local_addr = pending_request.local_addr,
                                server_addr = pending_request.server_addr,
                            );
                            self.pending_tcp.push_back(PendingTcp {
                                from: active_addr,
                                to: pending_request.server_addr,
                            });
                            return GatherPoll::AllocateSocket {
                                component_id: self.component_id,
                                transport: TransportType::Tcp,
                                local_addr: active_addr,
                                remote_addr: pending_request.server_addr,
                            };
                        };
                    }
                    if lowest_wait.is_none() {
                        lowest_wait = Some(now + Duration::from_secs(600));
                    }
                    continue;
                }
            };
            self.requests.push(Request {
                protocol,
                base_addr,
                server: pending_request.server_addr,
                other_preference: pending_request.other_preference,
                component_id: pending_request.component_id,
                completed: false,
                agent,
            });
        }

        if let Some(cand) = self.pending_candidates.pop_back() {
            info!("produced {cand:?}");
            self.produced_candidates.push_front(cand.candidate.clone());
            return GatherPoll::NewCandidate(cand);
        }

        for request in self.requests.iter_mut() {
            if request.completed {
                continue;
            }
            match request.protocol {
                RequestProtocol::Udp => (),
                RequestProtocol::Tcp(ref mut tcp) => {
                    if tcp.is_none() {
                        return GatherPoll::WaitUntil(now);
                    } else {
                        if lowest_wait.is_none() {
                            lowest_wait = Some(now + Duration::from_secs(600));
                        }
                        continue;
                    }
                }
            };
            match &mut request.agent {
                StunOrTurnClient::Stun(agent) => match agent.poll(now) {
                    StunAgentPollRet::TransactionCancelled(_msg) => {
                        request.completed = true;
                    }
                    StunAgentPollRet::TransactionTimedOut(_msg) => {
                        request.completed = true;
                    }
                    StunAgentPollRet::WaitUntil(new_time) => {
                        if let Some(time) = lowest_wait {
                            if new_time < time {
                                lowest_wait = Some(new_time);
                            }
                        } else {
                            lowest_wait = Some(new_time);
                        }
                    }
                },
                StunOrTurnClient::Turn(client) => match client.poll(now) {
                    TurnPollRet::Closed => {
                        request.completed = true;
                    }
                    TurnPollRet::WaitUntil(new_time) => {
                        if let Some(time) = lowest_wait {
                            if new_time < time {
                                lowest_wait = Some(new_time);
                            }
                        } else {
                            lowest_wait = Some(new_time);
                        }
                    }
                },
            }
        }
        if let Some(lowest_wait) = lowest_wait {
            GatherPoll::WaitUntil(lowest_wait)
        } else if self.completed {
            GatherPoll::Finished
        } else {
            self.completed = true;
            GatherPoll::Complete(self.component_id)
        }
    }

    /// Poll the gatherer for transmission.  Should be called repeatedly until None is returned.
    #[tracing::instrument(name = "gatherer_poll_transmit", level = "trace", skip(self))]
    pub(crate) fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'_>>> {
        if let Some(transmit) = self.pending_transmits.pop_back() {
            trace!(
                "returning {:?} byte {} transmission from {} -> {}",
                transmit.data.len(),
                transmit.transport,
                transmit.from,
                transmit.to
            );
            return Some(transmit);
        }
        for request in self.requests.iter_mut() {
            if request.completed {
                continue;
            }
            trace!("poll transmit request {request:?}");

            match request.protocol {
                RequestProtocol::Udp => (),
                RequestProtocol::Tcp(ref mut tcp) => {
                    if tcp.is_none() {
                        match &mut request.agent {
                            StunOrTurnClient::Stun(agent) => {
                                let mut msg =
                                    Message::builder_request(BINDING, MessageWriteVec::new());
                                msg.add_fingerprint().unwrap();
                                *tcp = Some(msg.transaction_id());
                                let Ok(transmit) =
                                    agent.send_request(msg.finish(), request.server, now)
                                else {
                                    continue;
                                };
                                trace!(
                                    "returning {:?} byte {} transmission from {} -> {}",
                                    transmit.data.len(),
                                    transmit.transport,
                                    transmit.from,
                                    transmit.to
                                );
                                return Some(transmit.into_owned());
                            }
                            StunOrTurnClient::Turn(_) => *tcp = Some(TransactionId::generate()),
                        }
                    }
                }
            }

            match &mut request.agent {
                StunOrTurnClient::Stun(agent) => {
                    if let Some(transmit) = agent.poll_transmit(now) {
                        trace!(
                            "returning {:?} byte {} transmission from {} -> {}",
                            transmit.data.len(),
                            transmit.transport,
                            transmit.from,
                            transmit.to
                        );
                        return Some(Transmit::new(
                            transmit.data.into(),
                            transmit.transport,
                            transmit.from,
                            transmit.to,
                        ));
                    }
                }
                StunOrTurnClient::Turn(client) => {
                    if let Some(transmit) = client.poll_transmit(now) {
                        trace!(
                            "returning {:?} byte {} transmission from {} -> {}",
                            transmit.data.len(),
                            transmit.transport,
                            transmit.from,
                            transmit.to
                        );
                        return Some(transmit);
                    }
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_stun_response_address(
        stun_addr: SocketAddr,
        transport: TransportType,
        other_preference: u32,
        component_id: usize,
        foundation: String,
        base_addr: SocketAddr,
        server: SocketAddr,
        tcp_type: Option<TcpType>,
    ) -> Option<Candidate> {
        if address_is_ignorable(stun_addr.ip()) {
            return None;
        }
        let priority = Candidate::calculate_priority(
            crate::candidate::CandidateType::Host,
            transport,
            tcp_type,
            other_preference,
            component_id,
        );
        let stun_addr = if tcp_type == Some(TcpType::Active) {
            SocketAddr::new(stun_addr.ip(), 9)
        } else {
            stun_addr
        };
        let mut builder = Candidate::builder(
            component_id,
            crate::candidate::CandidateType::ServerReflexive,
            transport,
            &foundation,
            stun_addr,
        )
        .priority(priority)
        .base_address(base_addr)
        .related_address(server);
        if let Some(tcp_type) = tcp_type {
            builder = builder.tcp_type(tcp_type);
        }
        let cand = builder.build();
        Some(cand)
    }

    /// Provide the gatherer with data received from a socket.  If [`HandleStunReply::StunResponse`] is
    /// returned, then `poll()` should to be called at the next earliest opportunity.
    #[tracing::instrument(
        name = "gatherer_handle_data",
        level = "trace",
        ret,
        skip(self, transmit)
        fields(
            transport = %transmit.transport,
            from = %transmit.from,
            to = %transmit.to,
        )
    )]
    pub(crate) fn handle_data<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: &Transmit<T>,
        now: Instant,
    ) -> bool {
        trace!(
            "received {} bytes over {}: {} -> {}",
            transmit.data.as_ref().len(),
            transmit.transport,
            transmit.from,
            transmit.to
        );
        trace!("requests {:?}", self.requests);

        let mut turn_ret = None;
        let mut handled = false;
        for (idx, request) in self.requests.iter_mut().enumerate() {
            if request.completed
                || request.protocol.transport() != transmit.transport
                || request.server != transmit.from
                || request.base_addr != transmit.to
            {
                continue;
            }
            match &mut request.protocol {
                RequestProtocol::Tcp(_stun_transaction) => {
                    let Some(tcp_idx) = self.tcp_buffers.iter().position(|tcp| {
                        tcp.local_addr == transmit.to && tcp.remote_addr == transmit.from
                    }) else {
                        unreachable!();
                    };
                    self.tcp_buffers[tcp_idx]
                        .tcp_buffer
                        .extend_from_slice(transmit.data.as_ref());
                    match MessageHeader::from_bytes(&self.tcp_buffers[tcp_idx].tcp_buffer) {
                        // we fail for anything that is not a BINDING/ALLOCATE response
                        Ok(header) => {
                            if !header.get_type().is_response()
                                || ![BINDING, ALLOCATE].contains(&header.get_type().method())
                            {
                                request.completed = true;
                                return false;
                            }
                        }
                        Err(StunParseError::NotStun) => {
                            request.completed = true;
                            return false;
                        }
                        _ => (),
                    }
                    match &mut request.agent {
                        StunOrTurnClient::Stun(agent) => {
                            let Ok(msg) =
                                Message::from_bytes(&self.tcp_buffers[tcp_idx].tcp_buffer)
                            else {
                                // TODO: should signal closure of the TCP connection
                                request.completed = true;
                                return false;
                            };
                            trace!("parsed STUN message {msg}");
                            let base_active_addr = SocketAddr::new(request.base_addr.ip(), 9);
                            let base_passive_addr = request.base_addr;
                            let other_preference = request.other_preference;
                            let component_id = request.component_id;
                            let server = request.server;
                            if let HandleStunReply::ValidatedStunResponse(response) =
                                agent.handle_stun(msg, transmit.from)
                            {
                                request.completed = true;
                                let Ok(xor_addr) = response.attribute::<XorMappedAddress>() else {
                                    return true;
                                };
                                let stun_addr = xor_addr.addr(response.transaction_id());
                                for tcp_type in [TcpType::Active, TcpType::Passive] {
                                    let foundation = self.produced_i.to_string();
                                    let base_addr = match tcp_type {
                                        TcpType::Active => base_active_addr,
                                        TcpType::Passive => base_passive_addr,
                                        TcpType::So => unreachable!(),
                                    };
                                    if let Some(cand) = Self::handle_stun_response_address(
                                        stun_addr,
                                        TransportType::Tcp,
                                        other_preference,
                                        component_id,
                                        foundation,
                                        base_addr,
                                        server,
                                        Some(tcp_type),
                                    ) {
                                        self.produced_i += 1;
                                        self.pending_candidates.push_front(GatheredCandidate {
                                            candidate: cand.clone(),
                                            turn_agent: None,
                                        });
                                    }
                                }
                                handled = true;
                                break;
                            }
                        }
                        StunOrTurnClient::Turn(client) => {
                            let transmit = transmit_send_unframed(transmit);
                            match client.recv(transmit, now) {
                                TurnRecvRet::PeerData(_peer) => handled = true,
                                TurnRecvRet::Handled => {
                                    handled = true;
                                    if let Some(TurnEvent::AllocationCreated(
                                        transport,
                                        relayed_address,
                                    )) = client.poll_event()
                                    {
                                        request.completed = true;
                                        let foundation = self.produced_i.to_string();
                                        let priority = Candidate::calculate_priority(
                                            crate::candidate::CandidateType::Host,
                                            transport,
                                            None,
                                            request.other_preference,
                                            self.component_id,
                                        );
                                        let cand = Candidate::builder(
                                            self.component_id,
                                            crate::candidate::CandidateType::Relayed,
                                            transport,
                                            &foundation,
                                            relayed_address,
                                        )
                                        .priority(priority)
                                        .related_address(request.server)
                                        .base_address(relayed_address)
                                        .build();
                                        self.produced_i += 1;
                                        turn_ret = Some((idx, cand));
                                    }
                                    break;
                                }
                                TurnRecvRet::Ignored(_) => (),
                                TurnRecvRet::PeerIcmp {
                                    transport,
                                    peer,
                                    icmp_type,
                                    icmp_code,
                                    icmp_data: _,
                                } => {
                                    debug!("gathering received ICMP(type:{icmp_type:x}, code:{icmp_code:x}) over TURN from {transport}:{peer}");
                                    return true;
                                }
                            }
                        }
                    }
                }
                RequestProtocol::Udp => match Message::from_bytes(transmit.data.as_ref()) {
                    Ok(msg) => {
                        trace!("parsed STUN message {msg}, {request:?}");
                        match &mut request.agent {
                            StunOrTurnClient::Stun(agent) => {
                                if let HandleStunReply::ValidatedStunResponse(response) =
                                    agent.handle_stun(msg, transmit.from)
                                {
                                    request.completed = true;
                                    let foundation = self.produced_i.to_string();
                                    let Ok(xor_addr) = response.attribute::<XorMappedAddress>()
                                    else {
                                        return true;
                                    };
                                    let stun_addr = xor_addr.addr(response.transaction_id());
                                    if let Some(cand) = Self::handle_stun_response_address(
                                        stun_addr,
                                        TransportType::Udp,
                                        request.other_preference,
                                        request.component_id,
                                        foundation,
                                        request.base_addr,
                                        request.server,
                                        None,
                                    ) {
                                        self.produced_i += 1;
                                        self.pending_candidates.push_front(GatheredCandidate {
                                            candidate: cand.clone(),
                                            turn_agent: None,
                                        });
                                    }
                                    handled = true;
                                    break;
                                }
                            }
                            StunOrTurnClient::Turn(client) => {
                                let transmit = transmit_send_unframed(transmit);
                                match client.recv(transmit, now) {
                                    TurnRecvRet::PeerData(_peer) => {
                                        handled = true;
                                    }
                                    TurnRecvRet::Handled => {
                                        if let Some(TurnEvent::AllocationCreated(
                                            transport,
                                            relayed_address,
                                        )) = client.poll_event()
                                        {
                                            request.completed = true;
                                            let foundation = self.produced_i.to_string();
                                            let priority = Candidate::calculate_priority(
                                                crate::candidate::CandidateType::Host,
                                                transport,
                                                None,
                                                request.other_preference,
                                                self.component_id,
                                            );
                                            let cand = Candidate::builder(
                                                self.component_id,
                                                crate::candidate::CandidateType::Relayed,
                                                transport,
                                                &foundation,
                                                relayed_address,
                                            )
                                            .priority(priority)
                                            .related_address(request.server)
                                            .base_address(relayed_address)
                                            .build();
                                            self.produced_i += 1;
                                            turn_ret = Some((idx, cand));
                                        }
                                        handled = true;
                                        break;
                                    }
                                    TurnRecvRet::Ignored(_) => (),
                                    TurnRecvRet::PeerIcmp {
                                        transport,
                                        peer,
                                        icmp_type,
                                        icmp_code,
                                        icmp_data: _,
                                    } => {
                                        debug!("gathering received ICMP(type:{icmp_type:x}, code:{icmp_code:x}) over TURN from {transport}:{peer}");
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    Err(_e) => (),
                },
            }
        }
        if let Some((turn_idx, cand)) = turn_ret {
            let request = self.requests.remove(turn_idx);
            let StunOrTurnClient::Turn(client) = request.agent else {
                unreachable!();
            };
            self.pending_candidates.push_front(GatheredCandidate {
                candidate: cand.clone(),
                turn_agent: Some(client),
            });
        }
        handled
    }

    /// Provide a socket as requested through [`GatherPoll::AllocateSocket`].  The transport and address
    /// must match the value from the corresponding [`GatherPoll::AllocateSocket`].
    #[tracing::instrument(name = "gatherer_allocated_socket", level = "debug", skip(self))]
    pub(crate) fn allocated_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        socket: &Result<SocketAddr, StunError>,
    ) {
        if transport != TransportType::Tcp {
            return;
        };
        trace!("{:?}", self.pending_tcp);
        let Some(pending_tcp_idx) = self
            .pending_tcp
            .iter()
            .position(|pending| pending.from == local_addr && pending.to == remote_addr)
        else {
            return;
        };
        self.pending_tcp.swap_remove_back(pending_tcp_idx);
        let mut tcp_buffer_added = false;
        for request in self.pending_requests.iter_mut() {
            if !request.completed
                && request.agent_request_time.is_some()
                && transport == request.transport_type
                && request.local_addr == local_addr
                && request.server_addr == remote_addr
            {
                info!("adding TCP socket with local addr {socket:?}",);
                request.completed = true;
                if let Ok(socket_addr) = socket {
                    self.requests.push(request.as_tcp_request(*socket_addr));
                    if !tcp_buffer_added {
                        tcp_buffer_added = true;
                        self.tcp_buffers.push_back(GatherTcpBuffer {
                            requested_local_addr: local_addr,
                            local_addr: *socket_addr,
                            remote_addr,
                            tcp_buffer: Vec::new(),
                        });
                    }
                }
            }
        }
    }
}

fn transmit_send_unframed<'a, T: AsRef<[u8]>>(transmit: &Transmit<T>) -> Transmit<Data<'a>> {
    Transmit::new(
        Data::from(transmit.data.as_ref()),
        transmit.transport,
        transmit.from,
        transmit.to,
    )
    .into_owned()
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use turn_client_proto::types::TurnCredentials;

    use crate::candidate::{CandidateType, TcpType};
    use stun_proto::types::{
        message::{MessageClass, MessageWriteVec},
        prelude::{MessageWrite, MessageWriteExt},
    };
    use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};

    use super::*;

    use tracing::error;

    #[test]
    fn host_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, &[(TransportType::Udp, local_addr)], &[], &[]);
        let now = Instant::ZERO;
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Host);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, local_addr);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    #[test]
    fn host_udp_incoming_data_ignored() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, &[(TransportType::Udp, local_addr)], &[], &[]);
        let now = Instant::ZERO;
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Host);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, local_addr);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let remote_addr = "192.168.1.2:2000".parse().unwrap();
        let transmit = Transmit::new([6; 10], TransportType::Udp, remote_addr, local_addr);
        assert!(!gather.handle_data(&transmit, now));

        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    #[test]
    fn host_tcp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, &[(TransportType::Tcp, local_addr)], &[], &[]);
        let now = Instant::ZERO;
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            let local_addr = SocketAddr::new(local_addr.ip(), 9);
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Host);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, local_addr);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Active));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Host);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, local_addr);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Passive));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    fn respond_to_stun_binding(
        transmit: Transmit<Data<'_>>,
        public_ip: SocketAddr,
    ) -> Transmit<Data<'static>> {
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(BINDING));
        assert!(msg.has_class(MessageClass::Request));
        let mut response = Message::builder_success(&msg, MessageWriteVec::new());
        let xor_addr = XorMappedAddress::new(public_ip, response.transaction_id());
        response.add_attribute(&xor_addr).unwrap();
        let response = response.finish();
        Transmit::new(
            response.into_boxed_slice().into(),
            transmit.transport,
            transmit.to,
            transmit.from,
        )
    }

    #[test]
    fn stun_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let stun_addr = "192.168.1.2:2000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let mut gather = StunGatherer::new(
            1,
            &[(TransportType::Udp, local_addr)],
            &[(TransportType::Udp, stun_addr)],
            &[],
        );
        let now = Instant::ZERO;
        /* host candidate contents checked in `host_udp()` */
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));
        let transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, stun_addr);
        let response = respond_to_stun_binding(transmit, public_ip);
        assert!(matches!(gather.poll(now), GatherPoll::WaitUntil(_)));
        gather.handle_data(&response, now);

        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    fn handle_allocate_socket(gather: &mut StunGatherer, local_addr: SocketAddr, now: Instant) {
        let ret = gather.poll(now);
        if let GatherPoll::AllocateSocket {
            component_id: _,
            transport,
            local_addr: from,
            remote_addr: to,
        } = ret
        {
            gather.allocated_socket(transport, from, to, &Ok(local_addr));
        } else {
            error!("{ret:?}");
            unreachable!();
        }
    }

    #[test]
    fn stun_tcp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let stun_addr = "192.168.1.2:2000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let mut gather = StunGatherer::new(
            1,
            &[(TransportType::Tcp, local_addr)],
            &[(TransportType::Tcp, stun_addr)],
            &[],
        );
        let now = Instant::ZERO;
        handle_allocate_socket(&mut gather, local_addr, now);
        /* host candidate contents checked in `host_tcp()` */
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));

        let transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, stun_addr);
        let response = respond_to_stun_binding(transmit, public_ip);
        assert!(matches!(gather.poll(now), GatherPoll::WaitUntil(_)));
        gather.handle_data(&response, now);

        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            let local_addr = SocketAddr::new(local_addr.ip(), 9);
            let public_ip = SocketAddr::new(public_ip.ip(), 9);
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Active));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Passive));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    #[test]
    fn stun_interrupted_by_non_stun() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let stun_addr = "192.168.1.2:2000".parse().unwrap();
        let mut gather = StunGatherer::new(
            1,
            &[(TransportType::Tcp, local_addr)],
            &[(TransportType::Tcp, stun_addr)],
            &[],
        );
        let now = Instant::ZERO;
        handle_allocate_socket(&mut gather, local_addr, now);
        /* host candidate contents checked in `host_tcp()` */
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));

        let transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, stun_addr);

        let response = [4; 12];
        let response = Transmit::new(&response, transmit.transport, transmit.to, transmit.from);
        assert!(matches!(gather.poll(now), GatherPoll::WaitUntil(_)));
        assert!(!gather.handle_data(&response, now));

        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    #[test]
    fn turn_udp_allocate_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let turn_listen_addr = "192.168.1.2:2000".parse().unwrap();
        let turn_alloc_addr = "192.168.40.4:4000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let turn_credentials = TurnCredentials::new("tuser", "tpass");

        let mut turn_server = turn_server_proto::server::TurnServer::new(
            TransportType::Udp,
            turn_listen_addr,
            "realm".to_string(),
        );
        turn_server.add_user(
            turn_credentials.username().to_string(),
            turn_credentials.password().to_string(),
        );
        let mut gather = StunGatherer::new(
            1,
            &[(TransportType::Udp, local_addr)],
            &[],
            &[&TurnConfig::new(
                TransportType::Udp,
                turn_listen_addr,
                turn_credentials,
            )],
        );
        let now = Instant::ZERO;
        /* host candidate contents checked in `host_udp()` */
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));
        let stun_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(stun_transmit.from, local_addr);
        assert_eq!(stun_transmit.to, turn_listen_addr);
        let response = respond_to_stun_binding(stun_transmit, public_ip);
        assert!(matches!(gather.poll(now), GatherPoll::WaitUntil(_)));
        gather.handle_data(&response, now);

        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }

        // unauthenticated TURN ALLOCATE
        let turn_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(turn_transmit.from, local_addr);
        assert_eq!(turn_transmit.to, turn_listen_addr);
        let reply = turn_server.recv(turn_transmit, now).unwrap().build();
        assert!(gather.handle_data(&reply, now));

        // authenticated TURN ALLOCATE
        let turn_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(turn_transmit.from, local_addr);
        assert_eq!(turn_transmit.to, turn_listen_addr);
        assert!(turn_server.recv(turn_transmit, now).is_none());
        let TurnServerPollRet::AllocateSocketUdp {
            transport,
            local_addr,
            remote_addr,
            family,
        } = turn_server.poll(now)
        else {
            unreachable!();
        };
        turn_server.allocated_udp_socket(
            transport,
            local_addr,
            remote_addr,
            family,
            Ok(turn_alloc_addr),
            now,
        );
        let reply = turn_server.poll_transmit(now).unwrap();
        assert!(gather.handle_data(&reply, now));
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_some());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Relayed);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, turn_alloc_addr);
            assert_eq!(cand.base_address, turn_alloc_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }

        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }

    #[test]
    fn turn_tcp_allocate_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let turn_listen_addr = "192.168.1.2:2000".parse().unwrap();
        let turn_alloc_addr = "192.168.40.4:4000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let turn_credentials = TurnCredentials::new("tuser", "tpass");

        let mut turn_server = turn_server_proto::server::TurnServer::new(
            TransportType::Tcp,
            turn_listen_addr,
            "realm".to_string(),
        );
        turn_server.add_user(
            turn_credentials.username().to_string(),
            turn_credentials.password().to_string(),
        );
        let mut gather = StunGatherer::new(
            1,
            &[(TransportType::Tcp, local_addr)],
            &[],
            &[&TurnConfig::new(
                TransportType::Tcp,
                turn_listen_addr,
                turn_credentials,
            )],
        );
        let now = Instant::ZERO;
        handle_allocate_socket(&mut gather, local_addr, now);
        /* host candidate contents checked in `host_tcp()` */
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));
        assert!(matches!(gather.poll(now), GatherPoll::NewCandidate(_cand)));

        let stun_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(stun_transmit.from, local_addr);
        assert_eq!(stun_transmit.to, turn_listen_addr);
        let response = respond_to_stun_binding(stun_transmit, public_ip);
        assert!(matches!(gather.poll(now), GatherPoll::WaitUntil(_)));
        gather.handle_data(&response, now);

        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            let local_addr = SocketAddr::new(local_addr.ip(), 9);
            let public_ip = SocketAddr::new(public_ip.ip(), 9);
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Active));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_none());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::ServerReflexive);
            assert_eq!(cand.transport_type, TransportType::Tcp);
            assert_eq!(cand.address, public_ip);
            assert_eq!(cand.base_address, local_addr);
            assert_eq!(cand.tcp_type, Some(TcpType::Passive));
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }

        // unauthenticated TURN ALLOCATE
        let turn_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(turn_transmit.from, local_addr);
        assert_eq!(turn_transmit.to, turn_listen_addr);
        let reply = turn_server.recv(turn_transmit, now).unwrap().build();
        assert!(gather.handle_data(&reply, now));

        // authenticated TURN ALLOCATE
        let turn_transmit = gather.poll_transmit(now).unwrap();
        assert_eq!(turn_transmit.from, local_addr);
        assert_eq!(turn_transmit.to, turn_listen_addr);
        assert!(turn_server.recv(turn_transmit, now).is_none());
        let TurnServerPollRet::AllocateSocketUdp {
            transport,
            local_addr,
            remote_addr,
            family,
        } = turn_server.poll(now)
        else {
            unreachable!();
        };
        turn_server.allocated_udp_socket(
            transport,
            local_addr,
            remote_addr,
            family,
            Ok(turn_alloc_addr),
            now,
        );
        let reply = turn_server.poll_transmit(now).unwrap();
        assert!(gather.handle_data(&reply, now));
        let ret = gather.poll(now);
        if let GatherPoll::NewCandidate(cand) = ret {
            assert!(cand.turn_agent.is_some());
            let cand = cand.candidate;
            assert_eq!(cand.component_id, 1);
            assert_eq!(cand.candidate_type, CandidateType::Relayed);
            assert_eq!(cand.transport_type, TransportType::Udp);
            assert_eq!(cand.address, turn_alloc_addr);
            assert_eq!(cand.base_address, turn_alloc_addr);
            assert_eq!(cand.tcp_type, None);
            assert_eq!(cand.extensions, vec![]);
        } else {
            error!("{ret:?}");
            unreachable!();
        }

        assert!(matches!(gather.poll(now), GatherPoll::Complete(_)));
        assert!(matches!(gather.poll(now), GatherPoll::Finished));
    }
}
