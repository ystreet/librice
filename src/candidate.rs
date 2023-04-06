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
    pub tcp_type: Option<TcpType>,
    pub extensions: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    PeerReflexive,
    ServerReflexive,
    Relayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpType {
    Active,
    Passive,
    So,
}

impl FromStr for TcpType {
    type Err = ParseTcpTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "passive" => Ok(Self::Passive),
            "so" => Ok(Self::So),
            _ => Err(ParseTcpTypeError::UnknownTcpType),
        }
    }
}

impl std::fmt::Display for TcpType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            TcpType::Active => f.pad("active"),
            TcpType::Passive => f.pad("passive"),
            TcpType::So => f.pad("so"),
        }
    }
}

#[derive(Debug)]
pub enum ParseTcpTypeError {
    UnknownTcpType,
}

impl Error for ParseTcpTypeError {}

impl std::fmt::Display for ParseTcpTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub enum ParseCandidateTypeError {
    UnknownCandidateType,
}

impl Error for ParseCandidateTypeError {}

impl std::fmt::Display for ParseCandidateTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.pad(&format!("{:?}", self))
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

impl std::fmt::Display for CandidateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match &self {
            CandidateType::Host => "host",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::Relayed => "relay",
        })
    }
}

pub struct CandidateBuilder {
    component_id: usize,
    ctype: CandidateType,
    ttype: TransportType,
    foundation: String,
    address: SocketAddr,
    priority: Option<u32>,
    base_address: Option<SocketAddr>,
    related_address: Option<SocketAddr>,
    tcp_type: Option<TcpType>,
    extensions: Vec<(String, String)>,
}

impl CandidateBuilder {
    /// Builds the candidate
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::candidate::*;
    /// # use std::net::SocketAddr;
    /// let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "candidate foundation 0 UDP 1234 127.0.0.1 2345 host")
    /// ```
    pub fn build(self) -> Candidate {
        let base_address = self.base_address.unwrap_or(self.address);

        if self.ttype == TransportType::Tcp && self.tcp_type == None {
            panic!("A TCP tranport requires the a tcp_type to be specified");
        }
        if self.ttype != TransportType::Tcp && self.tcp_type != None {
            panic!("Specified a TCP type for a non TCP tranport");
        }

        Candidate {
            component_id: self.component_id,
            candidate_type: self.ctype,
            transport_type: self.ttype,
            foundation: self.foundation.to_owned(),
            priority: self.priority.unwrap_or_else(|| {
                crate::candidate::Candidate::calculate_priority(self.ctype, 0, self.component_id)
            }),
            address: self.address,
            base_address,
            related_address: self.related_address,
            tcp_type: self.tcp_type,
            extensions: self.extensions,
        }
    }

    /// Specify the priority of the to be built candidate
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Specify the base address of the to be built candidate
    pub fn base_address(mut self, base_address: SocketAddr) -> Self {
        self.base_address = Some(base_address);
        self
    }

    /// Specify the related address of the to be built candidate
    pub fn related_address(mut self, related_address: SocketAddr) -> Self {
        self.related_address = Some(related_address);
        self
    }

    /// Specify the type of TCP connection of the to be built candidate
    ///
    /// - This will panic at build() time if the transport type is not [`TransportType::Tcp`].
    /// - This will panic at build() time if this function is not called but the
    ///   transport type is [`TransportType::Tcp`]
    pub fn tcp_type(mut self, tcp_type: TcpType) -> Self {
        self.tcp_type = Some(tcp_type);
        self
    }

    /// Add an extension attribute to the candidate
    pub fn extension(mut self, key: &str, val: &str) -> Self {
        self.extensions.push((key.to_string(), val.to_string()));
        self
    }
}

impl Candidate {
    /// Construct a builder for building a new candidate
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::candidate::*;
    /// # use std::net::SocketAddr;
    /// let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "candidate foundation 0 UDP 1234 127.0.0.1 2345 host")
    /// ```
    pub fn builder(
        component_id: usize,
        ctype: CandidateType,
        ttype: TransportType,
        foundation: &str,
        address: SocketAddr,
    ) -> CandidateBuilder {
        CandidateBuilder {
            component_id,
            ctype,
            ttype,
            foundation: foundation.to_owned(),
            address,
            priority: None,
            base_address: None,
            related_address: None,
            tcp_type: None,
            extensions: vec![],
        }
    }

    /// Serialize this candidate to a string for use in SDP
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::candidate::*;
    /// # use std::net::SocketAddr;
    /// let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "candidate foundation 0 UDP 1234 127.0.0.1 2345 host")
    /// ```
    pub fn to_sdp_string(&self) -> String {
        let mut ret = String::from("candidate ")
            + &self.foundation
            + " "
            + &self.component_id.to_string()
            + " "
            + &self.transport_type.to_string()
            + " "
            + &self.priority.to_string()
            + " "
            + &self.address.ip().to_string()
            + " "
            + &self.address.port().to_string()
            + " "
            + &self.candidate_type.to_string();

        if let Some(related_address) = self.related_address {
            ret = ret
                + " raddr "
                + &related_address.ip().to_string()
                + " rport "
                + &related_address.port().to_string();
        }
        if let Some(tcp_type) = self.tcp_type {
            ret = ret + " tcptype " + &tcp_type.to_string();
        }

        for (key, val) in self.extensions.iter() {
            ret = ret + " " + key + " " + val;
        }
        ret
    }

    // can this candidate pair with 'remote' in any way
    pub(crate) fn can_pair_with(&self, remote: &Candidate) -> bool {
        let address = match self.candidate_type {
            CandidateType::Host => self.address,
            _ => self.base_address,
        };
        self.transport_type == remote.transport_type
            && self.component_id == remote.component_id
            && address.is_ipv4() == remote.address.is_ipv4()
            && address.is_ipv6() == remote.address.is_ipv6()
    }

    fn priority_type_preference(ctype: CandidateType) -> u32 {
        match ctype {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relayed => 0,
        }
    }

    pub(crate) fn calculate_priority(
        ctype: CandidateType,
        local_preference: u32,
        component_id: usize,
    ) -> u32 {
        ((1 << 24) * Self::priority_type_preference(ctype)) + ((1 << 8) * local_preference) + 256
            - component_id as u32
    }

    // RFC 8445 5.1.3.  "Eliminating Redundant Candidates"
    pub(crate) fn redundant_with(&self, other: &Candidate) -> bool {
        self.address.ip() == other.address.ip() && self.base_address.ip() == other.base_address.ip()
    }

    // RFC 8445 6.1.2.4.  Pruning the Pairs
    fn pair_prune_address(&self) -> SocketAddr {
        match self.candidate_type {
            CandidateType::Host => self.address,
            _ => self.base_address,
        }
    }
}

pub mod parse {
    use std::{net::SocketAddr, str::FromStr};

    use nom::bytes::complete::{tag, take_while1, take_while_m_n};
    use nom::combinator::map_res;

    use super::{Candidate, CandidateType, ParseCandidateTypeError};
    use super::{ParseTcpTypeError, TcpType};
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
        BadExtension,
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
    impl From<ParseTcpTypeError> for ParseCandidateError {
        fn from(_: ParseTcpTypeError) -> Self {
            ParseCandidateError::BadTransportType
        }
    }

    fn is_alphabetic(c: char) -> bool {
        c.is_alphabetic()
    }

    fn is_digit(c: char) -> bool {
        c.is_ascii_digit()
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
        c.is_ascii_hexdigit() || c == '.' || c == ':'
    }

    fn is_part_of_byte_string(c: char) -> bool {
        // not nul, cr or cf (or SP for separator)
        c != '\0' && c != '\x0a' && c != '\x0d' && c != ' '
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
        let (s, candidate_type) = map_res(
            take_while1::<_, _, nom::error::Error<_>>(is_alphabetic),
            CandidateType::from_str,
        )(s)
        .map_err(|_| ParseCandidateError::BadCandidateType)?;

        let mut builder = Candidate::builder(
            component_id,
            candidate_type,
            transport_type,
            foundation,
            address,
        )
        .priority(priority)
        .base_address(address);

        let mut iter_s = s;
        let mut expected_next = None;
        let mut raddr = None;
        while !iter_s.is_empty() {
            let s = skip_spaces(iter_s)?;
            let (s, ext_key) = take_while1::<_, _, nom::error::Error<_>>(is_part_of_byte_string)(s)
                .map_err(|_| ParseCandidateError::BadExtension)?;
            let s = skip_spaces(s)?;
            let (s, ext_value) =
                take_while1::<_, _, nom::error::Error<_>>(is_part_of_byte_string)(s)
                    .map_err(|_| ParseCandidateError::BadExtension)?;

            if let Some(expected_next) = expected_next {
                if ext_key != expected_next {
                    return Err(ParseCandidateError::BadExtension);
                }

                if expected_next == "rport" {
                    let raddr = raddr.take().ok_or(ParseCandidateError::BadAddress)?;
                    let port =
                        str::parse(ext_value).map_err(|_| ParseCandidateError::BadAddress)?;
                    builder = builder.related_address(SocketAddr::new(raddr, port));
                } else {
                    unreachable!();
                }
            } else {
                match ext_key {
                    "raddr" => {
                        raddr = Some(
                            ext_value
                                .parse()
                                .map_err(|_| ParseCandidateError::BadAddress)?,
                        );
                        expected_next = Some("rport");
                    }
                    "tcptype" => {
                        let tcp_type = TcpType::from_str(ext_value)?;
                        builder = builder.tcp_type(tcp_type);
                    }
                    _ => builder = builder.extension(ext_key, ext_value),
                }
            }

            iter_s = s;
        }

        if builder.ttype == TransportType::Tcp && builder.tcp_type == None {
            return Err(ParseCandidateError::BadTransportType);
        }

        Ok(builder.build())
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
    pub local: Candidate,
    pub remote: Candidate,
}

impl CandidatePair {
    /// Create a new [`CandidatePair`]
    ///
    /// # Panic
    ///
    /// - If the component id is different between the local and remote candidates
    /// - If the transport type is different between the local and remote candidates
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::candidate::*;
    /// # use std::net::SocketAddr;
    /// let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// let pair = CandidatePair::new(candidate.clone(), candidate);
    /// ```
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        if local.component_id != remote.component_id {
            panic!("attempt made to create a local candidate that has a different component id {} than remote component id {}", local.component_id, remote.component_id);
        }
        if local.transport_type != remote.transport_type {
            panic!("attempt made to create a local candidate that has a different transport {} than the remote transport type {}", local.transport_type, remote.transport_type);
        }

        Self { local, remote }
    }

    pub(crate) fn foundation(&self) -> String {
        self.local.foundation.to_string() + ":" + &self.remote.foundation
    }

    pub(crate) fn priority(&self, are_controlling: bool) -> u64 {
        let (controlling_priority, controlled_priority) = if are_controlling {
            (self.local.priority as u64, self.remote.priority as u64)
        } else {
            (self.remote.priority as u64, self.local.priority as u64)
        };
        let extra = if controlled_priority > controlling_priority {
            1u64
        } else {
            0u64
        };
        (1 << 32) * controlling_priority.min(controlled_priority)
            + 2 * controlling_priority.max(controlled_priority)
            + extra
    }

    pub(crate) fn construct_valid(&self, mapped_address: SocketAddr) -> Self {
        let mut local = self.local.clone();
        local.address = mapped_address;
        Self {
            local,
            remote: self.remote.clone(),
        }
    }

    pub(crate) fn redundant_with<'pair>(
        &self,
        others: impl IntoIterator<Item = &'pair CandidatePair>,
    ) -> Option<&'pair CandidatePair> {
        others.into_iter().find(|&pair| {
            self.local.pair_prune_address() == pair.local.pair_prune_address()
                && self.remote == pair.remote
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn candidate_pair_redundant_with_itself() {
        init();
        let local_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
        let pair = CandidatePair::new(
            Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Udp,
                "foundation",
                local_addr,
            )
            .build(),
            Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Udp,
                "foundation",
                remote_addr,
            )
            .build(),
        );
        let pair2 = pair.clone();
        assert!(pair.redundant_with([pair2].iter()).is_some());
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
                Candidate::builder(0, CandidateType::Host, TransportType::Udp, "0", addr)
                    .priority(1234)
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
        #[test]
        fn host_candidate_sdp_string() {
            init();
            let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
            let cand_sdp_str = "candidate foundation 0 UDP 1234 127.0.0.1 9000 host";
            let cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Udp,
                "foundation",
                addr,
            )
            .priority(1234)
            .build();
            assert_eq!(cand.to_sdp_string(), cand_sdp_str);
            let parsed_cand = Candidate::from_str(cand_sdp_str).unwrap();
            assert_eq!(cand, parsed_cand);
        }
        #[test]
        fn tcp_candidate() {
            init();
            let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
            let cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Tcp,
                "foundation",
                addr,
            )
            .priority(1234)
            .tcp_type(TcpType::Active)
            .build();
            let cand_str = "candidate foundation 0 TCP 1234 127.0.0.1 2345 host tcptype active";
            let parsed_cand = Candidate::from_str(cand_str).unwrap();
            assert_eq!(cand, parsed_cand);
            assert_eq!(cand_str, cand.to_sdp_string());
        }
        #[test]
        fn tcp_candidate_without_tcp_type() {
            init();
            assert!(matches!(
                Candidate::from_str("candidate foundation 0 TCP 1234 127.0.0.1 2345 host"),
                Err(ParseCandidateError::BadTransportType)
            ));
        }
        #[test]
        fn related_address() {
            init();
            let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
            let related_addr: SocketAddr = "192.168.0.1:9876".parse().unwrap();
            let cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Udp,
                "foundation",
                addr,
            )
            .priority(1234)
            .related_address(related_addr)
            .build();
            let cand_str =
                "candidate foundation 0 UDP 1234 127.0.0.1 2345 host raddr 192.168.0.1 rport 9876";
            let parsed_cand = Candidate::from_str(cand_str).unwrap();
            assert_eq!(cand, parsed_cand);
            assert_eq!(cand_str, cand.to_sdp_string());
        }
        #[test]
        fn extension_attributes() {
            init();
            let addr: SocketAddr = "127.0.0.1:2345".parse().unwrap();
            let cand = Candidate::builder(
                0,
                CandidateType::Host,
                TransportType::Udp,
                "foundation",
                addr,
            )
            .priority(1234)
            .extension("key1", "value1")
            .extension("key2", "value2")
            .build();
            let cand_str =
                "candidate foundation 0 UDP 1234 127.0.0.1 2345 host key1 value1 key2 value2";
            let parsed_cand = Candidate::from_str(cand_str).unwrap();
            assert_eq!(cand, parsed_cand);
            assert_eq!(cand_str, cand.to_sdp_string());
        }
    }
}
