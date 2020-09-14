// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub candidate_type: CandidateType,
    pub transport_type: TransportType,
    pub foundation: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub base_address: SocketAddr,
    // TODO: from stun/turn addr
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    PeerReflexive,
    ServerReflexive,
    Relayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Udp,
    Tcp,
}

impl Candidate {
    pub fn new(
        ctype: CandidateType,
        ttype: TransportType,
        foundation: &str,
        priority: u32,
        address: SocketAddr,
        base_address: SocketAddr,
    ) -> Self {
        Self {
            candidate_type: ctype,
            transport_type: ttype,
            foundation: foundation.to_owned(),
            priority,
            address,
            base_address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn initial_type_none() {
        init();
    }
}
