// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::{CStr, CString};

#[derive(Eq)]
pub struct Candidate {
    ffi: *mut crate::ffi::RiceCandidate,
}

unsafe impl Send for Candidate {}
unsafe impl Sync for Candidate {}

impl core::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let mut dbg = f.debug_struct("Candidate");
            let dbg2 = &mut dbg;
            dbg2.field("ffi", &self.ffi);
            if !self.ffi.is_null() {
                dbg2.field("value", &*self.ffi);
            }
            dbg.finish()
        }
    }
}

impl PartialEq<Candidate> for Candidate {
    fn eq(&self, other: &Candidate) -> bool {
        unsafe { crate::ffi::rice_candidate_eq(self.ffi, other.ffi) }
    }
}

impl Clone for Candidate {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_candidate_copy(self.ffi) },
        }
    }
}

impl Drop for Candidate {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_candidate_free(self.ffi) }
    }
}

impl Candidate {
    pub fn builder(
        component_id: usize,
        ctype: CandidateType,
        ttype: TransportType,
        foundation: &str,
        address: crate::Address,
    ) -> CandidateBuilder {
        unsafe {
            let foundation = CString::new(foundation).unwrap();
            CandidateBuilder {
                ffi: crate::ffi::rice_candidate_new(
                    component_id,
                    ctype.into(),
                    ttype.into(),
                    foundation.as_ptr(),
                    address.into_c_full(),
                ),
            }
        }
    }

    pub(crate) fn from_c_full(ffi: *mut crate::ffi::RiceCandidate) -> Self {
        Self { ffi }
    }

    fn into_c_full(self) -> *mut crate::ffi::RiceCandidate {
        let ret = self.ffi;
        core::mem::forget(self);
        ret
    }

    pub(crate) fn as_c(&self) -> *const crate::ffi::RiceCandidate {
        self.ffi
    }

    // FIXME: proper error type
    pub fn from_sdp_string(s: &str) -> Result<Candidate, ()> {
        let cand_str = std::ffi::CString::new(s).unwrap();
        unsafe {
            let ret = crate::ffi::rice_candidate_new_from_sdp_string(cand_str.as_ptr());
            if ret.is_null() {
                return Err(());
            }
            Ok(Self::from_c_full(ret))
        }
    }

    pub fn component_id(&self) -> usize {
        unsafe { (*self.ffi).component_id }
    }

    pub fn candidate_type(&self) -> CandidateType {
        unsafe { (*self.ffi).candidate_type.into() }
    }

    pub fn transport(&self) -> TransportType {
        unsafe { (*self.ffi).transport_type.into() }
    }

    pub fn foundation(&self) -> String {
        unsafe {
            CStr::from_ptr((*self.ffi).foundation)
                .to_str()
                .unwrap()
                .to_owned()
        }
    }

    pub fn address(&self) -> crate::Address {
        unsafe { crate::Address::from_c_none((*self.ffi).address) }
    }

    pub fn base_address(&self) -> crate::Address {
        unsafe { crate::Address::from_c_none((*self.ffi).base_address) }
    }

    pub fn related_address(&self) -> Option<crate::Address> {
        unsafe {
            let related = (*self.ffi).related_address;
            if related.is_null() {
                None
            } else {
                Some(crate::Address::from_c_none(related))
            }
        }
    }

    pub fn tcp_type(&self) -> TcpType {
        unsafe { (*self.ffi).tcp_type.into() }
    }
}

#[derive(Debug)]
pub struct CandidateBuilder {
    ffi: *mut crate::ffi::RiceCandidate,
}

impl CandidateBuilder {
    pub fn build(mut self) -> Candidate {
        let ret = Candidate { ffi: self.ffi };
        self.ffi = core::ptr::null_mut();
        ret
    }

    pub fn base_address(self, base: crate::Address) -> Self {
        unsafe {
            crate::ffi::rice_candidate_set_base_address(self.ffi, base.into_c_full());
            self
        }
    }

    pub fn related_address(self, related: crate::Address) -> Self {
        unsafe {
            crate::ffi::rice_candidate_set_related_address(self.ffi, related.into_c_full());
            self
        }
    }

    pub fn tcp_type(self, typ: TcpType) -> Self {
        unsafe {
            if (*self.ffi).transport_type != TransportType::Tcp.into() && typ != TcpType::None {
                panic!("Attempt made to set the TcpType of a non-TCP candidate");
            }
            crate::ffi::rice_candidate_set_tcp_type(self.ffi, typ.into());
            self
        }
    }
}

/// The type of the candidate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CandidateType {
    /// The candidate is a local network interface
    Host = crate::ffi::RICE_CANDIDATE_TYPE_HOST,
    /// The candidate was discovered from incoming data
    PeerReflexive = crate::ffi::RICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
    /// The candidate was discovered by asking an external server (STUN/TURN)
    ServerReflexive = crate::ffi::RICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
    /// The candidate will relay all data through an external server (TURN).
    Relayed = crate::ffi::RICE_CANDIDATE_TYPE_RELAYED,
}

impl From<crate::ffi::RiceCandidateType> for CandidateType {
    fn from(value: crate::ffi::RiceCandidateType) -> Self {
        match value {
            crate::ffi::RICE_CANDIDATE_TYPE_HOST => Self::Host,
            crate::ffi::RICE_CANDIDATE_TYPE_PEER_REFLEXIVE => Self::PeerReflexive,
            crate::ffi::RICE_CANDIDATE_TYPE_SERVER_REFLEXIVE => Self::ServerReflexive,
            crate::ffi::RICE_CANDIDATE_TYPE_RELAYED => Self::Relayed,
            val => panic!("Unknown candidate type {val:x?}"),
        }
    }
}

impl From<CandidateType> for crate::ffi::RiceCandidateType {
    fn from(value: CandidateType) -> Self {
        match value {
            CandidateType::Host => crate::ffi::RICE_CANDIDATE_TYPE_HOST,
            CandidateType::PeerReflexive => crate::ffi::RICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
            CandidateType::ServerReflexive => crate::ffi::RICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
            CandidateType::Relayed => crate::ffi::RICE_CANDIDATE_TYPE_RELAYED,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum TcpType {
    /// Not a TCP candidate.
    None = crate::ffi::RICE_TCP_TYPE_NONE,
    /// The candidate address will connect to a remote address.
    Active = crate::ffi::RICE_TCP_TYPE_ACTIVE,
    /// The candidate will listen for incominng TCP connections.
    Passive = crate::ffi::RICE_TCP_TYPE_PASSIVE,
    /// Simultaneous open.  The candidate will both listen for incoming connections, and connect to
    /// remote addresses.
    So = crate::ffi::RICE_TCP_TYPE_SO,
}

impl From<crate::ffi::RiceTcpType> for TcpType {
    fn from(value: crate::ffi::RiceTcpType) -> Self {
        match value {
            crate::ffi::RICE_TCP_TYPE_NONE => Self::None,
            crate::ffi::RICE_TCP_TYPE_ACTIVE => Self::Active,
            crate::ffi::RICE_TCP_TYPE_PASSIVE => Self::Passive,
            crate::ffi::RICE_TCP_TYPE_SO => Self::So,
            val => panic!("Unknown RiceTcpType valyue {val:x?}"),
        }
    }
}

impl From<TcpType> for crate::ffi::RiceTcpType {
    fn from(value: TcpType) -> Self {
        match value {
            TcpType::None => crate::ffi::RICE_TCP_TYPE_NONE,
            TcpType::Active => crate::ffi::RICE_TCP_TYPE_ACTIVE,
            TcpType::Passive => crate::ffi::RICE_TCP_TYPE_PASSIVE,
            TcpType::So => crate::ffi::RICE_TCP_TYPE_SO,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportType {
    Udp,
    Tcp,
}

impl core::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<crate::ffi::RiceTransportType> for TransportType {
    fn from(value: crate::ffi::RiceTransportType) -> Self {
        match value {
            crate::ffi::RICE_TRANSPORT_TYPE_UDP => Self::Udp,
            crate::ffi::RICE_TRANSPORT_TYPE_TCP => Self::Tcp,
            _ => panic!("Unknown RiceTransportType value"),
        }
    }
}

impl From<TransportType> for crate::ffi::RiceTransportType {
    fn from(value: TransportType) -> Self {
        match value {
            TransportType::Udp => crate::ffi::RICE_TRANSPORT_TYPE_UDP,
            TransportType::Tcp => crate::ffi::RICE_TRANSPORT_TYPE_TCP,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
}

impl CandidatePair {
    pub fn new(local: Candidate, remote: Candidate) -> Self {
        Self { local, remote }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_address() -> crate::Address {
        "127.0.0.1:1000".parse().unwrap()
    }

    fn address() -> crate::Address {
        "127.0.0.2:2000".parse().unwrap()
    }

    fn related_address() -> crate::Address {
        "127.0.0.3:3000".parse().unwrap()
    }

    #[test]
    fn candidate_build() {
        let _log = crate::tests::test_init_log();

        let base = base_address();
        let addr = address();
        let related = related_address();
        let cand = Candidate::builder(
            1,
            CandidateType::PeerReflexive,
            TransportType::Tcp,
            "foundation",
            addr.clone(),
        )
        .base_address(base.clone())
        .related_address(related.clone())
        .tcp_type(TcpType::Active)
        .build();
        assert_eq!(cand.component_id(), 1);
        assert_eq!(cand.candidate_type(), CandidateType::PeerReflexive);
        assert_eq!(cand.transport(), TransportType::Tcp);
        assert_eq!(cand.foundation(), "foundation");
        assert_eq!(cand.address(), addr);
        assert_eq!(cand.base_address(), base);
        assert_eq!(cand.related_address(), Some(related));
        assert_eq!(cand.tcp_type(), TcpType::Active);

        let cand_clone = cand.clone();
        assert_eq!(cand, cand_clone);
    }
}
