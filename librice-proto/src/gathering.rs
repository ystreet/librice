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

use crate::candidate::{Candidate, TransportType};
use stun_proto::agent::{
    HandleStunReply, StunAgent, StunAgentPollRet, StunError, TcpBuffer, Transmit,
};
use stun_proto::types::attribute::XorMappedAddress;
use stun_proto::types::message::{Message, TransactionId, BINDING};

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
    // TODO: remove this Arc<Mutex<>>,
    agent: Arc<Mutex<StunAgent>>,
    request: TransactionId,
}

#[derive(Debug)]
struct RequestTcp {
    // TODO: remove this Arc<Mutex<>>,
    agent: Option<Arc<Mutex<StunAgent>>>,
    request: Option<TransactionId>,
    active_addr: SocketAddr,
    asked_for_agent: bool,
    tcp_buffer: TcpBuffer,
}

#[derive(Debug)]
struct Request {
    protocol: RequestProtocol,
    base_addr: SocketAddr,
    server: SocketAddr,
    other_preference: u32,
    component_id: usize,
    completed: bool,
}

impl Request {
    fn agent(&self) -> Option<Arc<Mutex<StunAgent>>> {
        match &self.protocol {
            RequestProtocol::Udp(udp) => Some(udp.agent.clone()),
            RequestProtocol::Tcp(tcp) => tcp.agent.clone(),
        }
    }

    fn request(&self) -> Option<TransactionId> {
        match &self.protocol {
            RequestProtocol::Udp(udp) => Some(udp.request),
            RequestProtocol::Tcp(tcp) => tcp.request,
        }
    }
}

/// Gatherer that uses STUN to gather a list of local candidates
#[derive(Debug)]
pub struct StunGatherer {
    component_id: usize,
    requests: Vec<Request>,
    pending_candidates: VecDeque<Candidate>,
    produced_i: usize,
    pending_transmits: VecDeque<(usize, Transmit<'static>)>,
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
        let mut requests = vec![];
        let mut pending_candidates = VecDeque::new();
        let mut pending_transmits = VecDeque::new();
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
                let mut msg = Message::builder_request(BINDING);
                msg.add_fingerprint().unwrap();
                let (protocol, base_addr) = match socket_transport {
                    TransportType::Udp => {
                        let transaction_id = msg.transaction_id();
                        let mut agent = StunAgent::builder(*socket_transport, *socket_addr)
                            .remote_addr(*stun_addr)
                            .build();
                        trace!("adding gather request {socket_transport} from {socket_addr} to {stun_addr}");
                        pending_transmits.push_front((
                            component_id,
                            agent.send(msg, *stun_addr).unwrap().into_owned(),
                        ));
                        (
                            RequestProtocol::Udp(RequestUdp {
                                agent: Arc::new(Mutex::new(agent)),
                                request: transaction_id,
                            }),
                            *socket_addr,
                        )
                    }
                    TransportType::Tcp => {
                        let active_addr = SocketAddr::new(socket_addr.ip(), 9);
                        trace!(
                            "adding gather request {active_addr} from {socket_addr} to {stun_addr}"
                        );
                        (
                            RequestProtocol::Tcp(RequestTcp {
                                agent: None,
                                active_addr,
                                request: None,
                                asked_for_agent: false,
                                tcp_buffer: Default::default(),
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
                    component_id,
                    completed: false,
                });
            }
        }

        Self {
            component_id,
            requests,
            pending_candidates,
            produced_i: 0,
            pending_transmits,
        }
    }

    /// The component ID of this gatherer
    pub fn component_id(&self) -> usize {
        self.component_id
    }

    /// Poll the gatherer.  Should be called repeatedly until [`GatherPoll::WaitUntil`]
    /// or [`GatherPoll::Complete`] is returned.
    #[tracing::instrument(name = "poll_gather", level = "trace", ret, err, skip(self))]
    pub fn poll(&mut self, now: Instant) -> Result<GatherPoll, StunError> {
        if let Some(cand) = self.pending_candidates.pop_back() {
            return Ok(GatherPoll::NewCandidate(cand));
        }
        if let Some((component_id, transmit)) = self.pending_transmits.pop_back() {
            return Ok(GatherPoll::SendData(component_id, transmit));
        }
        let mut lowest_wait = None;
        for request in self.requests.iter_mut() {
            if request.completed {
                continue;
            }
            let _stun_request = if let Some(request) = request.request() {
                request
            } else {
                match request.protocol {
                    RequestProtocol::Udp(ref _udp) => unreachable!(),
                    RequestProtocol::Tcp(ref mut tcp) => {
                        if !tcp.asked_for_agent {
                            tcp.asked_for_agent = true;
                            return Ok(GatherPoll::NeedAgent(
                                self.component_id,
                                TransportType::Tcp,
                                tcp.active_addr,
                                request.server,
                            ));
                        } else {
                            if lowest_wait.is_none() {
                                lowest_wait = Some(now + Duration::from_secs(600));
                            }
                            continue;
                        }
                    }
                }
            };
            let Some(agent) = request.agent() else {
                continue;
            };
            let mut agent = agent.lock().unwrap();
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
    ) -> Option<(Candidate, Message<'_>)> {
        if let Ok(xor_addr) = response.attribute::<XorMappedAddress>() {
            let stun_addr = xor_addr.addr(response.transaction_id());
            if !address_is_ignorable(stun_addr.ip()) {
                let priority = Candidate::calculate_priority(
                    crate::candidate::CandidateType::Host,
                    transport,
                    None,
                    other_preference,
                    component_id,
                );
                let builder = Candidate::builder(
                    component_id,
                    crate::candidate::CandidateType::ServerReflexive,
                    transport,
                    &foundation,
                    stun_addr,
                )
                .priority(priority)
                .base_address(base_addr)
                .related_address(server);
                let cand = builder.build();
                return Some((cand, response));
            }
        }
        None
    }

    /// Provide the gatherer with data received from a socket.  If [`HandleStunReply::StunResponse`] is
    /// returned, then `poll()` should to be called at the next earliest opportunity.
    pub fn handle_data<'a>(
        &'a mut self,
        data: &'a [u8],
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<bool, StunError> {
        for request in self.requests.iter_mut() {
            if !request.completed
                && request.protocol.transport() == transport
                && request.server == from
                && request.base_addr == to
            {
                if let Some(agent) = request.agent() {
                    let mut agent_inner = agent.lock().unwrap();
                    let mut handled = false;
                    match &mut request.protocol {
                        RequestProtocol::Tcp(ref mut tcp) => {
                            tcp.tcp_buffer.push_data(data);
                            while let Some(data) = tcp.tcp_buffer.pull_data() {
                                // TODO: need to handle heteregoneous TCP data
                                match Message::from_bytes(&data) {
                                    Ok(msg) => {
                                        if let HandleStunReply::StunResponse(response) =
                                            agent_inner.handle_stun(msg, from)
                                        {
                                            if let Ok(_xor_addr) =
                                                response.attribute::<XorMappedAddress>()
                                            {
                                                request.completed = true;
                                            }
                                            let foundation = self.produced_i.to_string();
                                            if let Some((cand, _response)) =
                                                Self::handle_stun_response(
                                                    response,
                                                    TransportType::Tcp,
                                                    request.other_preference,
                                                    request.component_id,
                                                    foundation,
                                                    request.base_addr,
                                                    request.server,
                                                )
                                            {
                                                self.produced_i += 1;
                                                for c in self.pending_candidates.iter() {
                                                    if cand.redundant_with(c) {
                                                        trace!("redundant {cand:?}");
                                                        continue;
                                                    }
                                                }
                                                self.pending_candidates.push_front(cand.clone());
                                            }
                                            handled = true;
                                        }
                                    }
                                    Err(_e) => request.completed = true,
                                }
                            }
                        }
                        RequestProtocol::Udp(_udp) => match Message::from_bytes(data) {
                            Ok(msg) => {
                                if let HandleStunReply::StunResponse(response) =
                                    agent_inner.handle_stun(msg, from)
                                {
                                    if let Ok(_xor_addr) = response.attribute::<XorMappedAddress>()
                                    {
                                        request.completed = true;
                                    }
                                    let foundation = self.produced_i.to_string();
                                    if let Some((cand, _response)) = Self::handle_stun_response(
                                        response,
                                        TransportType::Udp,
                                        request.other_preference,
                                        request.component_id,
                                        foundation,
                                        request.base_addr,
                                        request.server,
                                    ) {
                                        self.produced_i += 1;
                                        for c in self.pending_candidates.iter() {
                                            if cand.redundant_with(c) {
                                                trace!("redundant {cand:?}");
                                                continue;
                                            }
                                        }
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
        }
        Err(StunError::ResourceNotFound)
    }

    /// Provide an agent as requested through [`GatherPoll::NeedAgent`].  The transport and address
    /// must match the value from the corresponding [`GatherPoll::NeedAgent`].
    pub fn add_agent(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        agent: Result<StunAgent, StunError>,
    ) {
        for request in self.requests.iter_mut() {
            if transport == request.protocol.transport()
                && request.base_addr == local_addr
                && request.server == remote_addr
            {
                if let RequestProtocol::Tcp(ref mut tcp) = request.protocol {
                    if tcp.agent.is_none() {
                        match agent {
                            Ok(mut agent) => {
                                let local_addr = agent.local_addr();
                                let mut msg = Message::builder_request(BINDING);
                                msg.add_fingerprint().unwrap();
                                let transaction_id = msg.transaction_id();
                                self.pending_transmits.push_front((
                                    self.component_id,
                                    agent.send(msg, request.server).unwrap().into_owned(),
                                ));
                                tcp.request = Some(transaction_id);
                                tcp.agent = Some(Arc::new(Mutex::new(agent)));
                                request.base_addr = local_addr;
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
    use crate::candidate::{CandidateType, TcpType};
    use stun_proto::types::message::MessageClass;

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
        init();
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
            gather
                .handle_data(&response.build(), TransportType::Udp, stun_addr, local_addr)
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
}
