// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
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
        related_address: Option<SocketAddr>,
    ) -> Self {
        Self {
            candidate_type: ctype,
            transport_type: ttype,
            foundation: foundation.to_owned(),
            priority,
            address,
            base_address,
            related_address,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub component_id: usize,
    // FIXME: currently unused
    //    default: bool,
    //    valid: bool,
    nominated: bool,
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

    pub(crate) fn get_foundation(&self) -> String {
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
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn pair_nominate() {
        init();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let cand = Candidate::new(
            CandidateType::Host,
            TransportType::Udp,
            "0",
            0,
            addr.clone(),
            addr,
            None,
        );
        let mut pair = CandidatePair::new(1, cand.clone(), cand);
        assert_eq!(pair.nominated(), false);
        pair.nominate();
        assert_eq!(pair.nominated(), true);
        pair.nominate();
        assert_eq!(pair.nominated(), true);
    }
}
