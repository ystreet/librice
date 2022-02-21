// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use crate::stun::TransportType;

use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub component_id: usize,
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
    pub foundation: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub base_address: SocketAddr,
    pub related_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    PeerReflexive,
    ServerReflexive,
    Relayed,
}

#[derive(Debug)]
pub enum ParseCandidateTypeError {
    UnknownCandidateType,
}

impl Error for ParseCandidateTypeError {}

impl std::fmt::Display for ParseCandidateTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for CandidateType {
    type Err = ParseCandidateTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(CandidateType::Host),
            "prflx" => Ok(CandidateType::PeerReflexive),
            "srflx" => Ok(CandidateType::ServerReflexive),
            "relay" => Ok(CandidateType::Relayed),
            _ => Err(ParseCandidateTypeError::UnknownCandidateType),
        }
    }
}

pub struct CandidateBuilder {
    component_id: usize,
    ctype: CandidateType,
    ttype: TransportType,
    foundation: String,
    priority: u32,
    address: SocketAddr,
    base_address: Option<SocketAddr>,
    related_address: Option<SocketAddr>,
}

impl CandidateBuilder {
    pub fn build(self) -> Candidate {
        let base_address = self.base_address.unwrap_or(self.address);

        Candidate {
            component_id: self.component_id,
            candidate_type: self.ctype,
            transport_type: self.ttype,
            foundation: self.foundation.to_owned(),
            priority: self.priority,
            address: self.address,
            base_address,
            related_address: self.related_address,
        }
    }

    pub fn base_address(mut self, base_address: SocketAddr) -> Self {
        self.base_address = Some(base_address);
        self
    }

    pub fn related_address(mut self, related_address: SocketAddr) -> Self {
        self.related_address = Some(related_address);
        self
    }
}

impl Candidate {
    pub fn builder(
        component_id: usize,
        ctype: CandidateType,
        ttype: TransportType,
        foundation: &str,
        priority: u32,
        address: SocketAddr,
    ) -> CandidateBuilder {
        CandidateBuilder {
            component_id,
            ctype,
            ttype,
            foundation: foundation.to_owned(),
            priority,
            address,
            base_address: None,
            related_address: None,
        }
    }
}

pub mod parse {
    use std::{net::SocketAddr, str::FromStr};

    use nom::bytes::complete::{tag, take_while1, take_while_m_n};
    use nom::combinator::map_res;

    use super::{Candidate, CandidateType, ParseCandidateTypeError};
    use crate::stun::{ParseTransportTypeError, TransportType};

    #[derive(Debug)]
    pub enum ParseCandidateError {
        NotCandidate,
        BadFoundation,
        BadComponentId,
        BadTransportType,
        BadPriority,
        BadAddress,
        BadCandidateType,
        Malformed,
    }

    impl From<ParseTransportTypeError> for ParseCandidateError {
        fn from(_: ParseTransportTypeError) -> Self {
            ParseCandidateError::BadTransportType
        }
    }
    impl From<ParseCandidateTypeError> for ParseCandidateError {
        fn from(_: ParseCandidateTypeError) -> Self {
            ParseCandidateError::BadCandidateType
        }
    }

    fn is_alphabetic(c: char) -> bool {
        c.is_alphabetic()
    }

    fn is_digit(c: char) -> bool {
        c.is_digit(10)
    }

    fn is_ice_char(c: char) -> bool {
        c.is_alphanumeric() || c == '+' || c == '-'
    }

    fn skip_spaces(s: &str) -> Result<&str, ParseCandidateError> {
        let (s, _) = take_while1::<_, _, nom::error::Error<_>>(|c| c == ' ')(s)
            .map_err(|_| ParseCandidateError::Malformed)?;
        Ok(s)
    }

    fn is_part_of_socket_addr(c: char) -> bool {
        c.is_digit(16) || c == '.' || c == ':'
    }

    // https://datatracker.ietf.org/doc/html/rfc8839#section-5.1
    fn parse_candidate(s: &str) -> Result<Candidate, ParseCandidateError> {
        let (s, _) = tag::<_, _, nom::error::Error<_>>("candidate")(s)
            .map_err(|_| ParseCandidateError::NotCandidate)?;
        let s = skip_spaces(s)?;
        let (s, foundation) = take_while_m_n::<_, _, nom::error::Error<_>>(1, 32, is_ice_char)(s)
            .map_err(|_| ParseCandidateError::BadFoundation)?;
        let s = skip_spaces(s)?;
        let (s, component_id): (_, usize) = map_res(
            take_while_m_n::<_, _, nom::error::Error<_>>(1, 3, is_digit),
            str::parse,
        )(s)
        .map_err(|_| ParseCandidateError::BadComponentId)?;
        let s = skip_spaces(s)?;
        let (s, transport_type) = take_while1::<_, _, nom::error::Error<_>>(is_alphabetic)(s)
            .map_err(|_| ParseCandidateError::BadTransportType)?;
        let transport_type = TransportType::from_str(transport_type)?;
        let s = skip_spaces(s)?;
        let (s, priority) = map_res(
            take_while1::<_, _, nom::error::Error<_>>(is_digit),
            str::parse,
        )(s)
        .map_err(|_| ParseCandidateError::BadPriority)?;
        let s = skip_spaces(s)?;
        // FIXME: proper address parsing
        let (s, connection_address) = map_res(
            take_while1::<_, _, nom::error::Error<_>>(is_part_of_socket_addr),
            |s: &str| s.parse(),
        )(s)
        .map_err(|_| ParseCandidateError::BadAddress)?;
        let s = skip_spaces(s)?;
        let (s, port) = map_res(
            take_while1::<_, _, nom::error::Error<_>>(is_digit),
            str::parse,
        )(s)
        .map_err(|_| ParseCandidateError::BadAddress)?;
        let address = SocketAddr::new(connection_address, port);
        let s = skip_spaces(s)?;
        let (_s, candidate_type) = map_res(
            take_while1::<_, _, nom::error::Error<_>>(is_alphabetic),
            CandidateType::from_str,
        )(s)
        .map_err(|_| ParseCandidateError::BadCandidateType)?;
        // TODO: extensions, raddr, etc things

        Ok(Candidate::builder(
            component_id,
            candidate_type,
            transport_type,
            foundation,
            priority,
            address,
        )
        .base_address(address)
        .build())
    }

    impl FromStr for Candidate {
        type Err = ParseCandidateError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            parse_candidate(s)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub component_id: usize,
    // FIXME: currently unused
    //    default: bool,
    //    valid: bool,
    nominated: bool,
    pub local: Candidate,
    pub remote: Candidate,
}

impl CandidatePair {
    pub fn new(component_id: usize, local: Candidate, remote: Candidate) -> Self {
        Self {
            local,
            remote,
            component_id,
            nominated: false,
        }
    }

    pub(crate) fn foundation(&self) -> String {
        self.local.foundation.to_string() + ":" + &self.remote.foundation
    }

    pub fn priority(&self, are_controlling: bool) -> u64 {
        let controlling_priority = if are_controlling {
            self.local.priority
        } else {
            self.remote.priority
        } as u64;
        let controlled_priority = if are_controlling {
            self.remote.priority
        } else {
            self.local.priority
        } as u64;
        let extra = if controlled_priority > controlling_priority {
            1u64
        } else {
            0u64
        };
        (1 << 32) * controlling_priority.min(controlled_priority)
            + 2 * controlling_priority.max(controlled_priority)
            + extra
    }

    pub fn construct_valid(&self, mapped_address: SocketAddr) -> Self {
        let mut local = self.local.clone();
        local.address = mapped_address;
        Self {
            local,
            remote: self.remote.clone(),
            component_id: self.component_id,
            nominated: false,
        }
    }

    pub(crate) fn nominated(&self) -> bool {
        self.nominated
    }

    pub(crate) fn nominate(&mut self) {
        self.nominated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn pair_nominate() {
        init();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let cand =
            Candidate::builder(0, CandidateType::Host, TransportType::Udp, "0", 0, addr).build();
        let mut pair = CandidatePair::new(1, cand.clone(), cand);
        assert!(!pair.nominated());
        pair.nominate();
        assert!(pair.nominated());
        pair.nominate();
        assert!(pair.nominated());
    }

    mod parse {
        use super::*;
        use crate::candidate::parse::ParseCandidateError;

        #[test]
        fn udp_candidate() {
            init();
            let s = "candidate 0 0 UDP 1234 127.0.0.1 2345 host";
            let cand = Candidate::from_str(s).unwrap();
            debug!("cand {:?}", cand);
            let addr = "127.0.0.1:2345".parse().unwrap();
            assert_eq!(
                cand,
                Candidate::builder(0, CandidateType::Host, TransportType::Udp, "0", 1234, addr)
                    .build()
            );
        }
        #[test]
        fn candidate_not_candidate() {
            init();
            assert!(matches!(
                Candidate::from_str("a"),
                Err(ParseCandidateError::NotCandidate)
            ));
        }
        #[test]
        fn candidate_missing_space() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate0 0 UDP 1234 127.0.0.1 2345 host"),
                Err(ParseCandidateError::Malformed)
            ));
        }
        #[test]
        fn candidate_bad_foundation() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate = 0 UDP 1234 127.0.0.1 2345 host"),
                Err(ParseCandidateError::BadFoundation)
            ));
        }
        #[test]
        fn candidate_bad_component_id() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 component-id UDP 1234 127.0.0.1 2345 host"),
                Err(ParseCandidateError::BadComponentId)
            ));
        }
        #[test]
        fn candidate_bad_transport_type() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 0 transport 1234 127.0.0.1 2345 host"),
                Err(ParseCandidateError::BadTransportType)
            ));
        }
        #[test]
        fn candidate_bad_priority() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 0 UDP priority 127.0.0.1 2345 host"),
                Err(ParseCandidateError::BadPriority)
            ));
        }
        #[test]
        fn candidate_bad_address() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 0 UDP 1234 address 2345 host"),
                Err(ParseCandidateError::BadAddress)
            ));
        }
        #[test]
        fn candidate_bad_port() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 0 UDP 1234 127.0.0.1 port host"),
                Err(ParseCandidateError::BadAddress)
            ));
        }
        #[test]
        fn candidate_bad_candidate_type() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate 0 0 UDP 1234 127.0.0.1 2345 candidate-type"),
                Err(ParseCandidateError::BadCandidateType)
            ));
        }
    }
}
