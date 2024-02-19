// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Helpers for retrieving a list of local candidates

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::candidate::{Candidate, TransportType};
use crate::stun::agent::{
    HandleStunReply, StunAgent, StunError, StunRequest, StunRequestPollRet, Transmit,
};
use crate::stun::attribute::{XorMappedAddress, XOR_MAPPED_ADDRESS};
use crate::stun::message::{Message, BINDING};

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
    Udp(RequestUdp),
    Tcp(RequestTcp),
}

impl RequestProtocol {
    fn transport(&self) -> TransportType {
        match self {
            RequestProtocol::Udp(_) => TransportType::Udp,
            RequestProtocol::Tcp(_) => TransportType::Tcp,
        }
    }
}

#[derive(Debug)]
struct RequestUdp {
    agent: StunAgent,
    request: StunRequest,
}

#[derive(Debug)]
struct RequestTcp {
    agent: Option<StunAgent>,
    request: Option<StunRequest>,
    active_addr: SocketAddr,
    asked_for_agent: bool,
}

#[derive(Debug)]
struct Request {
    protocol: RequestProtocol,
    base_addr: SocketAddr,
    server: SocketAddr,
    other_preference: u32,
    completed: bool,
}

impl Request {
    fn agent(&self) -> Option<&StunAgent> {
        match &self.protocol {
            RequestProtocol::Udp(udp) => Some(&udp.agent),
            RequestProtocol::Tcp(tcp) => tcp.agent.as_ref(),
        }
    }

    fn request(&self) -> Option<&StunRequest> {
        match &self.protocol {
            RequestProtocol::Udp(udp) => Some(&udp.request),
            RequestProtocol::Tcp(tcp) => tcp.request.as_ref(),
        }
    }
}

/// Gatherer that uses STUN to gather a list of local candidates
#[derive(Debug)]
pub struct StunGatherer {
    component_id: usize,
    requests: Vec<Request>,
    pending_candidates: Vec<Candidate>,
    produced_i: usize,
}

/// Return value for the gather state machine
#[derive(Debug)]
pub enum GatherRet {
    /// Need an agent (and socket) for the specified 5-tuple network address
    NeedAgent(TransportType, SocketAddr, SocketAddr),
    /// Send data from the specified address to the specified address
    SendData(Transmit),
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
        let (requests, pending_candidates) = {
            let mut requests = vec![];
            let mut pending_candidates = vec![];
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
                        pending_candidates.push(
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
                        pending_candidates.push(
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
                        pending_candidates.push(
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
                    let mut msg = Message::new_request(BINDING);
                    msg.add_fingerprint().unwrap();
                    let (protocol, base_addr) = match socket_transport {
                        TransportType::Udp => {
                            let agent = StunAgent::builder(*socket_transport, *socket_addr)
                                .remote_addr(*stun_addr)
                                .build();
                            trace!("adding gather request {socket_transport} from {socket_addr} to {stun_addr}");
                            let request = agent
                                .stun_request_transaction(&msg, *stun_addr)
                                .build()
                                .unwrap();
                            (
                                RequestProtocol::Udp(RequestUdp {
                                    agent: agent.clone(),
                                    request,
                                }),
                                *socket_addr,
                            )
                        }
                        TransportType::Tcp => {
                            let active_addr = SocketAddr::new(socket_addr.ip(), 9);
                            trace!("adding gather request {active_addr} from {socket_addr} to {stun_addr}");
                            (
                                RequestProtocol::Tcp(RequestTcp {
                                    agent: None,
                                    active_addr,
                                    request: None,
                                    asked_for_agent: false,
                                }),
                                active_addr,
                            )
                        }
                    };
                    requests.push(Request {
                        protocol,
                        base_addr,
                        server: *stun_addr,
                        other_preference,
                        completed: false,
                    });
                }
            }
            (requests, pending_candidates)
        };

        Self {
            component_id,
            requests,
            pending_candidates,
            produced_i: 0,
        }
    }

    /// The component ID of this gatherer
    pub fn component_id(&self) -> usize {
        self.component_id
    }

    /// Poll the gatherer.  Should be called repeatedly until [`GatherRet::WaitUntil`]
    /// or [`GatherRet::Complete`] is returned.
    #[tracing::instrument(name = "gather_poll", level = "trace", ret, err, skip(self))]
    pub fn poll(&mut self, now: Instant) -> Result<GatherRet, StunError> {
        if self.produced_i < self.pending_candidates.len() {
            let cand = self.pending_candidates[self.produced_i].clone();
            self.produced_i += 1;
            return Ok(GatherRet::NewCandidate(cand));
        }
        let mut lowest_wait = None;
        'next_request: for request in self.requests.iter_mut() {
            if request.completed {
                continue;
            }
            let stun_request = if let Some(request) = request.request() {
                request
            } else {
                match request.protocol {
                    RequestProtocol::Udp(ref _udp) => unreachable!(),
                    RequestProtocol::Tcp(ref mut tcp) => {
                        if !tcp.asked_for_agent {
                            tcp.asked_for_agent = true;
                            return Ok(GatherRet::NeedAgent(
                                TransportType::Tcp,
                                tcp.active_addr,
                                request.server,
                            ));
                        } else {
                            if lowest_wait.is_none() {
                                lowest_wait = Some(now + Duration::from_secs(999999));
                            }
                            continue;
                        }
                    }
                }
            };
            match stun_request.poll(now)? {
                StunRequestPollRet::Cancelled => return Err(StunError::Aborted),
                StunRequestPollRet::Response(response) => {
                    if let Some(xor_addr) =
                        response.attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS)
                    {
                        request.completed = true;
                        let stun_addr = xor_addr.addr(response.transaction_id());
                        if address_is_ignorable(stun_addr.ip()) {
                            continue;
                        }
                        let foundation = self.produced_i.to_string();
                        self.produced_i += 1;
                        let priority = Candidate::calculate_priority(
                            crate::candidate::CandidateType::Host,
                            request.protocol.transport(),
                            None,
                            request.other_preference,
                            self.component_id,
                        );
                        let builder = Candidate::builder(
                            self.component_id,
                            crate::candidate::CandidateType::ServerReflexive,
                            request.protocol.transport(),
                            &foundation,
                            stun_addr,
                        )
                        .priority(priority)
                        .base_address(request.base_addr)
                        .related_address(request.server);
                        let cand = builder.build();
                        for c in self.pending_candidates.iter() {
                            if cand.redundant_with(c) {
                                trace!("redundant {cand:?}");
                                continue 'next_request;
                            }
                        }
                        self.pending_candidates.push(cand.clone());
                        self.produced_i += 1;
                        return Ok(GatherRet::NewCandidate(cand));
                    }
                }
                StunRequestPollRet::SendData(transmit) => {
                    return Ok(GatherRet::SendData(
                        request
                            .agent()
                            .unwrap()
                            .send_data(&transmit.data, transmit.to),
                    ))
                }
                StunRequestPollRet::WaitUntil(new_time) => {
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
            Ok(GatherRet::WaitUntil(lowest_wait))
        } else {
            Ok(GatherRet::Complete)
        }
    }

    /// Provide the gatherer with data received from a socket.  If [`HandleStunReply::Stun`] is
    /// returned, then `poll()` should to be called at the next earliest opportunity.
    pub fn handle_data(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<Vec<HandleStunReply>, StunError> {
        for request in self.requests.iter() {
            if !request.completed && request.server == from {
                if let Some(agent) = request.agent() {
                    return agent.handle_incoming_data(data, from);
                }
            }
        }
        Err(StunError::ResourceNotFound)
    }

    /// Provide an agent as requested through [`GatherRet::NeedAgent`].  The transport and address
    /// must match the value from the corresponding [`GatherRet::NeedAgent`].
    pub fn add_agent(
        &mut self,
        transport: TransportType,
        addr: SocketAddr,
        agent: Result<StunAgent, StunError>,
    ) {
        for request in self.requests.iter_mut() {
            if transport == request.protocol.transport() && request.base_addr == addr {
                if let RequestProtocol::Tcp(ref mut tcp) = request.protocol {
                    if tcp.agent.is_none() {
                        match agent {
                            Ok(agent) => {
                                let local_addr = agent.local_addr();
                                let mut msg = Message::new_request(BINDING);
                                msg.add_fingerprint().unwrap();
                                tcp.request = Some(
                                    agent
                                        .stun_request_transaction(&msg, request.server)
                                        .build()
                                        .unwrap(),
                                );
                                tcp.agent = Some(agent);
                                request.base_addr = local_addr;
                                // XXX: wakeup?
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
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        candidate::{CandidateType, TcpType},
        stun::message::MessageClass,
    };

    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn host_udp() {
        init();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, vec![(TransportType::Udp, local_addr)], vec![]);
        let now = Instant::now();
        let ret = gather.poll(now);
        if let Ok(GatherRet::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
    }

    #[test]
    fn host_tcp() {
        init();
        let local_addr = "192.168.1.1:1000".parse().unwrap();
        let mut gather = StunGatherer::new(1, vec![(TransportType::Tcp, local_addr)], vec![]);
        let now = Instant::now();
        let ret = gather.poll(now);
        if let Ok(GatherRet::NewCandidate(cand)) = ret {
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
        if let Ok(GatherRet::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
    }

    #[test]
    fn stun_udp() {
        init();
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
            Ok(GatherRet::NewCandidate(_cand))
        ));
        let ret = gather.poll(now);
        if let Ok(GatherRet::SendData(transmit)) = ret {
            assert_eq!(transmit.from, local_addr);
            assert_eq!(transmit.to, stun_addr);
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(BINDING));
            assert!(msg.has_class(MessageClass::Request));
            assert!(matches!(gather.poll(now), Ok(GatherRet::WaitUntil(_))));
            let mut response = Message::new_success(&msg);
            response
                .add_attribute(XorMappedAddress::new(public_ip, response.transaction_id()))
                .unwrap();
            gather.handle_data(&response.to_bytes(), stun_addr).unwrap();
        } else {
            error!("{ret:?}");
            unreachable!();
        }
        let ret = gather.poll(now);
        if let Ok(GatherRet::NewCandidate(cand)) = ret {
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
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
        assert!(matches!(gather.poll(now), Ok(GatherRet::Complete)));
    }
}
