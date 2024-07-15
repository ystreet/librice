// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Helpers for retrieving a list of local candidates

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::candidate::{Candidate, TcpType, TransportType};
use stun_proto::agent::{HandleStunReply, StunAgent, StunAgentPollRet, StunError, Transmit};
use stun_proto::types::attribute::XorMappedAddress;
use stun_proto::types::message::{Message, MessageHeader, StunParseError, TransactionId, BINDING};

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
    Tcp(RequestTcp),
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
struct RequestTcp {
    request: Option<TransactionId>,
    tcp_buffer: Vec<u8>,
}

#[derive(Debug)]
struct Request {
    protocol: RequestProtocol,
    // TODO: remove this Arc<Mutex<>>,
    agent: Arc<Mutex<StunAgent>>,
    base_addr: SocketAddr,
    server: SocketAddr,
    other_preference: u32,
    component_id: usize,
    completed: bool,
}

#[derive(Debug)]
struct PendingRequest {
    completed: bool,
    component_id: usize,
    transport_type: TransportType,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    other_preference: u32,
    agent_request_time: Option<Instant>,
}

/// Gatherer that uses STUN to gather a list of local candidates
#[derive(Debug)]
pub struct StunGatherer {
    component_id: usize,
    requests: Vec<Request>,
    pending_candidates: VecDeque<Candidate>,
    produced_candidates: VecDeque<Candidate>,
    produced_i: usize,
    pending_transmits: VecDeque<(usize, Transmit<'static>)>,
    pending_requests: VecDeque<PendingRequest>,
}

/// Return value for the gather state machine
#[derive(Debug)]
pub enum GatherPoll<'a> {
    /// Need an agent (and socket) for the specified 5-tuple network address
    NeedAgent(usize, TransportType, SocketAddr, SocketAddr),
    /// Send data from the specified address to the specified address
    SendData(usize, Transmit<'a>),
    /// Wait until the specified Instant passes
    WaitUntil(Instant),
    /// A new local candidate was discovered
    NewCandidate(Candidate),
    /// Gathering process is complete, no further progress is possible.
    Complete,
}

impl StunGatherer {
    /// Create a new gatherer
    pub fn new(
        component_id: usize,
        sockets: Vec<(TransportType, SocketAddr)>,
        stun_servers: Vec<(TransportType, SocketAddr)>,
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
                    pending_candidates.push_front(
                        Candidate::builder(
                            component_id,
                            crate::candidate::CandidateType::Host,
                            *socket_transport,
                            &pending_candidates.len().to_string(),
                            *socket_addr,
                        )
                        .priority(priority)
                        .base_address(*socket_addr)
                        .build(),
                    );
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
                    pending_candidates.push_front(
                        Candidate::builder(
                            component_id,
                            crate::candidate::CandidateType::Host,
                            *socket_transport,
                            &pending_candidates.len().to_string(),
                            active_addr,
                        )
                        .priority(priority)
                        .tcp_type(crate::candidate::TcpType::Active)
                        .build(),
                    );
                    let priority = Candidate::calculate_priority(
                        crate::candidate::CandidateType::Host,
                        *socket_transport,
                        Some(crate::candidate::TcpType::Passive),
                        other_preference + 1,
                        component_id,
                    );
                    pending_candidates.push_front(
                        Candidate::builder(
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
                    );
                }
            }
            for (stun_transport, stun_addr) in stun_servers.iter() {
                if socket_transport != stun_transport {
                    continue;
                }
                if socket_addr.is_ipv4() && !stun_addr.is_ipv4() {
                    continue;
                }
                if socket_addr.is_ipv6() && !stun_addr.is_ipv6() {
                    continue;
                }
                pending_requests.push_front(PendingRequest {
                    component_id,
                    transport_type: *socket_transport,
                    local_addr: *socket_addr,
                    server_addr: *stun_addr,
                    other_preference,
                    completed: false,
                    agent_request_time: None,
                });
            }
        }

        Self {
            component_id,
            requests: vec![],
            pending_candidates,
            produced_candidates: Default::default(),
            produced_i: 0,
            pending_transmits: Default::default(),
            pending_requests,
        }
    }

    /// The component ID of this gatherer
    pub fn component_id(&self) -> usize {
        self.component_id
    }

    /// Poll the gatherer.  Should be called repeatedly until [`GatherPoll::WaitUntil`]
    /// or [`GatherPoll::Complete`] is returned.
    #[tracing::instrument(name = "gatherer_poll", level = "trace", ret, err, skip(self))]
    pub fn poll(&mut self, now: Instant) -> Result<GatherPoll, StunError> {
        let mut lowest_wait = None;

        if let Some(cand) = self.pending_candidates.pop_back() {
            info!("produced {cand:?}");
            self.produced_candidates.push_front(cand.clone());
            return Ok(GatherPoll::NewCandidate(cand));
        }

        for pending_request in self.pending_requests.iter_mut() {
            if pending_request.completed {
                continue;
            }

            let (protocol, agent, base_addr) = match pending_request.transport_type {
                TransportType::Udp => {
                    pending_request.completed = true;
                    let mut msg = Message::builder_request(BINDING);
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
                    self.pending_transmits.push_front((
                        pending_request.component_id,
                        agent
                            .send(msg, pending_request.server_addr, now)
                            .unwrap()
                            .into_owned(),
                    ));
                    (
                        RequestProtocol::Udp,
                        Arc::new(Mutex::new(agent)),
                        pending_request.local_addr,
                    )
                }
                TransportType::Tcp => {
                    if pending_request.agent_request_time.is_none() {
                        let active_addr = SocketAddr::new(pending_request.local_addr.ip(), 9);
                        trace!(
                            "adding gather request TCP {active_addr} from {local_addr} to {server_addr}",
                            local_addr = pending_request.local_addr,
                            server_addr = pending_request.server_addr,
                        );
                        pending_request.local_addr = active_addr;
                        pending_request.agent_request_time = Some(now);
                        return Ok(GatherPoll::NeedAgent(
                            self.component_id,
                            TransportType::Tcp,
                            active_addr,
                            pending_request.server_addr,
                        ));
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

        if let Some((component_id, transmit)) = self.pending_transmits.pop_back() {
            return Ok(GatherPoll::SendData(component_id, transmit));
        }

        for request in self.requests.iter_mut() {
            if request.completed {
                continue;
            }
            match request.protocol {
                RequestProtocol::Udp => (),
                RequestProtocol::Tcp(ref mut tcp) => {
                    if tcp.request.is_none() {
                        let mut msg = Message::builder_request(BINDING);
                        msg.add_fingerprint().unwrap();
                        tcp.request = Some(msg.transaction_id());
                        return Ok(GatherPoll::SendData(
                            self.component_id,
                            request
                                .agent
                                .lock()
                                .unwrap()
                                .send(msg, request.server, now)?
                                .into_owned(),
                        ));
                    } else {
                        if lowest_wait.is_none() {
                            lowest_wait = Some(now + Duration::from_secs(600));
                        }
                        continue;
                    }
                }
            };
            let mut agent = request.agent.lock().unwrap();
            match agent.poll(now) {
                StunAgentPollRet::TransactionCancelled(_msg) => {
                    request.completed = true;
                }
                StunAgentPollRet::TransactionTimedOut(_msg) => {
                    request.completed = true;
                }
                StunAgentPollRet::SendData(transmit) => {
                    return Ok(GatherPoll::SendData(
                        self.component_id,
                        transmit.into_owned(),
                    ))
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
            }
        }
        if let Some(lowest_wait) = lowest_wait {
            Ok(GatherPoll::WaitUntil(lowest_wait))
        } else {
            Ok(GatherPoll::Complete)
        }
    }

    fn handle_stun_response(
        response: Message<'_>,
        transport: TransportType,
        other_preference: u32,
        component_id: usize,
        foundation: String,
        base_addr: SocketAddr,
        server: SocketAddr,
        tcp_type: Option<TcpType>,
    ) -> Option<(Candidate, Message<'_>)> {
        if let Ok(xor_addr) = response.attribute::<XorMappedAddress>() {
            let stun_addr = xor_addr.addr(response.transaction_id());
            if !address_is_ignorable(stun_addr.ip()) {
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
                return Some((cand, response));
            }
        }
        None
    }

    /// Provide the gatherer with data received from a socket.  If [`HandleStunReply::StunResponse`] is
    /// returned, then `poll()` should to be called at the next earliest opportunity.
    #[tracing::instrument(
        name = "gatherer_handle_data",
        level = "trace",
        ret,
        err,
        skip(self, transmit)
        fields(
            transport = %transmit.transport,
            from = %transmit.from,
            to = %transmit.to,
        )
    )]
    pub fn handle_data<'a>(&'a mut self, transmit: &Transmit<'a>) -> Result<bool, StunError> {
        trace!("received {} bytes", transmit.data.len());
        trace!("requests {:?}", self.requests);
        for request in self.requests.iter_mut() {
            if !request.completed
                && request.protocol.transport() == transmit.transport
                && request.server == transmit.from
                && request.base_addr == transmit.to
            {
                let mut agent_inner = request.agent.lock().unwrap();
                let mut handled = false;
                match &mut request.protocol {
                    RequestProtocol::Tcp(ref mut tcp) => {
                        tcp.tcp_buffer.extend_from_slice(&transmit.data);
                        match MessageHeader::from_bytes(&tcp.tcp_buffer) {
                            // we fail for anything that is not a BINDING response
                            Ok(header) => {
                                if !header.get_type().is_response()
                                    || header.get_type().method() != BINDING
                                {
                                    request.completed = true;
                                    return Ok(false);
                                }
                            }
                            Err(StunParseError::NotStun) => {
                                request.completed = true;
                                return Ok(false);
                            }
                            _ => (),
                        }
                        match Message::from_bytes(&tcp.tcp_buffer) {
                            Ok(msg) => {
                                trace!("parsed STUN message {msg}");
                                if let HandleStunReply::StunResponse(response) =
                                    agent_inner.handle_stun(msg, transmit.from)
                                {
                                    request.completed = true;
                                    for tcp_type in [TcpType::Active, TcpType::Passive] {
                                        let foundation = self.produced_i.to_string();
                                        let base_addr = match tcp_type {
                                            TcpType::Active => {
                                                SocketAddr::new(request.base_addr.ip(), 9)
                                            }
                                            TcpType::Passive => request.base_addr,
                                            TcpType::So => unreachable!(),
                                        };
                                        if let Some((cand, _response)) = Self::handle_stun_response(
                                            response.clone(),
                                            TransportType::Tcp,
                                            request.other_preference,
                                            request.component_id,
                                            foundation,
                                            base_addr,
                                            request.server,
                                            Some(tcp_type),
                                        ) {
                                            for c in self
                                                .produced_candidates
                                                .iter()
                                                .chain(self.pending_candidates.iter())
                                            {
                                                if cand.redundant_with(c) {
                                                    trace!("redundant {cand:?}");
                                                    return Ok(true);
                                                }
                                            }
                                            self.produced_i += 1;
                                            self.pending_candidates.push_front(cand.clone());
                                        }
                                    }
                                    handled = true;
                                }
                            }
                            // TODO: should signal closure of the TCP connection
                            Err(_e) => request.completed = true,
                        }
                    }
                    RequestProtocol::Udp => match Message::from_bytes(&transmit.data) {
                        Ok(msg) => {
                            trace!("parsed STUN message {msg}");
                            if let HandleStunReply::StunResponse(response) =
                                agent_inner.handle_stun(msg, transmit.from)
                            {
                                request.completed = true;
                                let foundation = self.produced_i.to_string();
                                if let Some((cand, _response)) = Self::handle_stun_response(
                                    response,
                                    TransportType::Udp,
                                    request.other_preference,
                                    request.component_id,
                                    foundation,
                                    request.base_addr,
                                    request.server,
                                    None,
                                ) {
                                    for c in self
                                        .produced_candidates
                                        .iter()
                                        .chain(self.pending_candidates.iter())
                                    {
                                        if cand.redundant_with(c) {
                                            trace!("redundant {cand:?}");
                                            return Ok(true);
                                        }
                                    }
                                    self.produced_i += 1;
                                    self.pending_candidates.push_front(cand.clone());
                                }
                                handled = true;
                            }
                        }
                        Err(_e) => (),
                    },
                }
                return Ok(handled);
            }
        }
        Ok(false)
    }

    /// Provide an agent as requested through [`GatherPoll::NeedAgent`].  The transport and address
    /// must match the value from the corresponding [`GatherPoll::NeedAgent`].
    #[tracing::instrument(name = "gatherer_add_agent", level = "debug", skip(self, agent))]
    pub fn add_agent(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        agent: Result<StunAgent, StunError>,
    ) {
        trace!("{:?}", self.pending_requests);
        for request in self.pending_requests.iter_mut() {
            if !request.completed
                && request.agent_request_time.is_some()
                && transport == request.transport_type
                && request.local_addr == local_addr
                && request.server_addr == remote_addr
            {
                info!(
                    "adding agent with local addr {:?}",
                    agent.as_ref().map(|agent| agent.local_addr())
                );
                request.completed = true;
                match agent {
                    Ok(agent) => {
                        let local_addr = agent.local_addr();
                        self.requests.push(Request {
                            protocol: RequestProtocol::Tcp(RequestTcp {
                                request: None,
                                tcp_buffer: vec![],
                            }),
                            agent: Arc::new(Mutex::new(agent)),
                            base_addr: local_addr,
                            server: request.server_addr,
                            other_preference: request.other_preference,
                            component_id: request.component_id,
                            completed: false,
                        });
                    }
                    Err(_e) => {
                        request.completed = true;
                    }
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::candidate::{CandidateType, TcpType};
    use stun_proto::types::message::MessageClass;

    use super::*;

    #[test]
    fn host_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, vec![(TransportType::Udp, local_addr)], vec![]);
        let now = Instant::now();
        let ret = gather.poll(now);
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
    }

    #[test]
    fn host_tcp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, vec![(TransportType::Tcp, local_addr)], vec![]);
        let now = Instant::now();
        let ret = gather.poll(now);
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
            let local_addr = SocketAddr::new(local_addr.ip(), 9);
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
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
    }

    #[test]
    fn stun_udp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let stun_addr = "192.168.1.2:2000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let mut gather = StunGatherer::new(
            1,
            vec![(TransportType::Udp, local_addr)],
            vec![(TransportType::Udp, stun_addr)],
        );
        let now = Instant::now();
        /* host candidate contents checked in `host_udp()` */
        assert!(matches!(
            gather.poll(now),
            Ok(GatherPoll::NewCandidate(_cand))
        ));
        let ret = gather.poll(now);
        if let Ok(GatherPoll::SendData(_cid, transmit)) = ret {
            assert_eq!(transmit.from, local_addr);
            assert_eq!(transmit.to, stun_addr);
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(BINDING));
            assert!(msg.has_class(MessageClass::Request));
            let mut response = Message::builder_success(&msg);
            response
                .add_attribute(&XorMappedAddress::new(public_ip, response.transaction_id()))
                .unwrap();
            assert!(matches!(gather.poll(now), Ok(GatherPoll::WaitUntil(_))));
            let response = response.build();
            gather
                .handle_data(&Transmit::new(
                    &*response,
                    TransportType::Udp,
                    stun_addr,
                    local_addr,
                ))
                .unwrap();
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
    }

    #[test]
    fn stun_tcp() {
        let _log = crate::tests::test_init_log();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let stun_addr = "192.168.1.2:2000".parse().unwrap();
        let public_ip = "192.168.1.3:3000".parse().unwrap();
        let mut gather = StunGatherer::new(
            1,
            vec![(TransportType::Tcp, local_addr)],
            vec![(TransportType::Tcp, stun_addr)],
        );
        let now = Instant::now();
        /* host candidate contents checked in `host_tcp()` */
        assert!(matches!(
            gather.poll(now),
            Ok(GatherPoll::NewCandidate(_cand))
        ));
        assert!(matches!(
            gather.poll(now),
            Ok(GatherPoll::NewCandidate(_cand))
        ));
        let ret = gather.poll(now);
        if let Ok(GatherPoll::NeedAgent(_cid, transport, from, to)) = ret {
            let agent = StunAgent::builder(transport, local_addr)
                .remote_addr(to)
                .build();
            gather.add_agent(transport, from, to, Ok(agent));
        } else {
            error!("{ret:?}");
            unreachable!();
        }

        let ret = gather.poll(now);
        if let Ok(GatherPoll::SendData(_cid, transmit)) = ret {
            assert_eq!(transmit.from, local_addr);
            assert_eq!(transmit.to, stun_addr);
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(BINDING));
            assert!(msg.has_class(MessageClass::Request));
            let mut response = Message::builder_success(&msg);
            response
                .add_attribute(&XorMappedAddress::new(public_ip, response.transaction_id()))
                .unwrap();
            assert!(matches!(gather.poll(now), Ok(GatherPoll::WaitUntil(_))));
            let response = response.build();
            gather
                .handle_data(&Transmit::new(
                    &*response,
                    TransportType::Tcp,
                    stun_addr,
                    local_addr,
                ))
                .unwrap();
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
            let local_addr = SocketAddr::new(local_addr.ip(), 9);
            let public_ip = SocketAddr::new(public_ip.ip(), 9);
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
        if let Ok(GatherPoll::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherPoll::Complete)));
    }
}
