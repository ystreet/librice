// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICE Candidates

use std::ffi::{CStr, CString};

use crate::agent::AgentError;

/// ICE candidate.
pub trait CandidateApi: sealed::CandidateAsC {
    /// The component
    fn component_id(&self) -> usize {
        unsafe { (*self.as_c()).component_id }
    }
    /// The type of the Candidate
    fn candidate_type(&self) -> CandidateType {
        unsafe { (*self.as_c()).candidate_type.into() }
    }
    /// The network transport
    fn transport(&self) -> TransportType {
        unsafe { (*self.as_c()).transport_type.into() }
    }

    /// The (unique) foundation
    fn foundation(&self) -> String {
        unsafe {
            CStr::from_ptr((*self.as_c()).foundation)
                .to_str()
                .unwrap()
                .to_owned()
        }
    }
    /// The priority
    fn priority(&self) -> u32 {
        unsafe { (*self.as_c()).priority }
    }
    /// The address to send to
    fn address(&self) -> crate::Address {
        unsafe { crate::Address::from_c_none((*self.as_c()).address) }
    }
    /// The address to send from
    fn base_address(&self) -> crate::Address {
        unsafe { crate::Address::from_c_none((*self.as_c()).base_address) }
    }
    /// Any related address that generated this candidate, e.g. STUN/TURN server
    fn related_address(&self) -> Option<crate::Address> {
        unsafe {
            let related = (*self.as_c()).related_address;
            if related.is_null() {
                None
            } else {
                Some(crate::Address::from_c_none(related))
            }
        }
    }
    /// The type of TCP candidate
    fn tcp_type(&self) -> TcpType {
        unsafe { (*self.as_c()).tcp_type.into() }
    }
    // TODO: extensions
}

mod sealed {
    pub trait CandidateAsC {
        fn as_c(&self) -> *const crate::ffi::RiceCandidate;
    }
}

/// An ICE candidate.
#[derive(Debug)]
pub struct Candidate {
    ffi: crate::ffi::RiceCandidate,
}

unsafe impl Send for Candidate {}
unsafe impl Sync for Candidate {}

impl PartialEq<Candidate> for Candidate {
    fn eq(&self, other: &Candidate) -> bool {
        unsafe { crate::ffi::rice_candidate_eq(&self.ffi, &other.ffi) }
    }
}

impl PartialEq<CandidateOwned> for Candidate {
    fn eq(&self, other: &CandidateOwned) -> bool {
        unsafe { crate::ffi::rice_candidate_eq(&self.ffi, other.ffi) }
    }
}

impl Clone for Candidate {
    fn clone(&self) -> Self {
        unsafe {
            let mut ret = Self {
                ffi: crate::ffi::RiceCandidate::zeroed(),
            };
            crate::ffi::rice_candidate_copy_into(&self.ffi, &mut ret.ffi);
            ret
        }
    }
}

impl CandidateApi for Candidate {}
impl sealed::CandidateAsC for Candidate {
    fn as_c(&self) -> *const crate::ffi::RiceCandidate {
        &self.ffi
    }
}

impl Drop for Candidate {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_candidate_clear(&mut self.ffi) }
    }
}

impl Candidate {
    /// Builds the candidate
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_c::candidate::*;
    /// # use rice_c::Address;
    /// let addr: Address = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     1,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "a=candidate:foundation 1 UDP 1234 127.0.0.1 2345 typ host")
    /// ```
    pub fn builder(
        component_id: usize,
        ctype: CandidateType,
        ttype: TransportType,
        foundation: &str,
        address: crate::Address,
    ) -> CandidateBuilder {
        unsafe {
            let foundation = CString::new(foundation).unwrap();
            let mut ret = CandidateBuilder {
                ffi: crate::ffi::RiceCandidate::zeroed(),
            };
            let address = address.into_c_full();
            let res = crate::ffi::rice_candidate_init(
                &mut ret.ffi,
                component_id,
                ctype.into(),
                ttype.into(),
                foundation.as_ptr(),
                address,
            );
            if res != crate::ffi::RICE_ERROR_SUCCESS {
                let _address = crate::Address::from_c_full(address);
                panic!("Failed to crate ICE candidate!");
            }
            ret
        }
    }

    pub(crate) fn as_c(&self) -> *const crate::ffi::RiceCandidate {
        &self.ffi
    }

    pub(crate) unsafe fn from_c_none(candidate: *const crate::ffi::RiceCandidate) -> Self {
        let mut ret = Self {
            ffi: crate::ffi::RiceCandidate::zeroed(),
        };
        crate::ffi::rice_candidate_copy_into(candidate, &mut ret.ffi);
        ret
    }

    pub(crate) fn from_c_full(candidate: crate::ffi::RiceCandidate) -> Self {
        Self { ffi: candidate }
    }

    /// Copy this candidate into a heap allocated [`CandidateOwned`].
    pub fn to_owned(&self) -> CandidateOwned {
        unsafe {
            CandidateOwned {
                ffi: crate::ffi::rice_candidate_copy(&self.ffi),
            }
        }
    }

    /// Serialize this candidate to a string for use in SDP
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_c::candidate::*;
    /// # use rice_c::Address;
    /// let addr: Address = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     1,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "a=candidate:foundation 1 UDP 1234 127.0.0.1 2345 typ host")
    /// ```
    pub fn to_sdp_string(&self) -> String {
        unsafe {
            let res = crate::ffi::rice_candidate_to_sdp_string(&self.ffi);
            let s = CStr::from_ptr(res);
            let ret = s.to_str().unwrap().to_owned();
            crate::ffi::rice_string_free(res);
            ret
        }
    }

    // FIXME: proper error type
    /// Parse an SDP candidate string into a candidate.
    pub fn from_sdp_string(s: &str) -> Result<Candidate, AgentError> {
        let cand_str = std::ffi::CString::new(s).unwrap();
        unsafe {
            let mut ret = Candidate {
                ffi: crate::ffi::RiceCandidate::zeroed(),
            };
            let res =
                crate::ffi::rice_candidate_init_from_sdp_string(&mut ret.ffi, cand_str.as_ptr());
            AgentError::from_c(res)?;
            Ok(ret)
        }
    }
}

/// An ICE candidate.
///
/// Backed inside a heap allocation.
#[derive(Eq)]
pub struct CandidateOwned {
    ffi: *mut crate::ffi::RiceCandidate,
}

unsafe impl Send for CandidateOwned {}
unsafe impl Sync for CandidateOwned {}

impl core::fmt::Debug for CandidateOwned {
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

impl PartialEq<CandidateOwned> for CandidateOwned {
    fn eq(&self, other: &CandidateOwned) -> bool {
        unsafe { crate::ffi::rice_candidate_eq(self.ffi, other.ffi) }
    }
}

impl PartialEq<Candidate> for CandidateOwned {
    fn eq(&self, other: &Candidate) -> bool {
        unsafe { crate::ffi::rice_candidate_eq(self.ffi, &other.ffi) }
    }
}

impl Clone for CandidateOwned {
    fn clone(&self) -> Self {
        unsafe {
            Self {
                ffi: crate::ffi::rice_candidate_copy(self.ffi),
            }
        }
    }
}

impl Drop for CandidateOwned {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_candidate_free(self.ffi) }
    }
}

impl CandidateApi for CandidateOwned {}
impl sealed::CandidateAsC for CandidateOwned {
    fn as_c(&self) -> *const crate::ffi::RiceCandidate {
        self.ffi
    }
}

impl CandidateOwned {
    pub(crate) fn as_c(&self) -> *const crate::ffi::RiceCandidate {
        self.ffi
    }

    /// Serialize this candidate to a string for use in SDP
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_c::candidate::*;
    /// # use rice_c::Address;
    /// let addr: Address = "127.0.0.1:2345".parse().unwrap();
    /// let candidate = Candidate::builder(
    ///     1,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "foundation",
    ///     addr,
    /// )
    /// .priority(1234)
    /// .build();
    /// assert_eq!(candidate.to_sdp_string(), "a=candidate:foundation 1 UDP 1234 127.0.0.1 2345 typ host")
    /// ```
    pub fn to_sdp_string(&self) -> String {
        unsafe {
            let res = crate::ffi::rice_candidate_to_sdp_string(self.ffi);
            let s = CStr::from_ptr(res);
            let ret = s.to_str().unwrap().to_owned();
            crate::ffi::rice_string_free(res);
            ret
        }
    }
}

/// A builder for a [`Candidate`]
#[derive(Debug)]
pub struct CandidateBuilder {
    ffi: crate::ffi::RiceCandidate,
}

impl CandidateBuilder {
    /// Consume this builder a construct a new [`Candidate`].
    pub fn build(self) -> Candidate {
        Candidate { ffi: self.ffi }
    }

    /// Specify the priority of the to be built candidate
    pub fn priority(mut self, priority: u32) -> Self {
        unsafe {
            crate::ffi::rice_candidate_set_priority(&mut self.ffi, priority);
            self
        }
    }

    /// Specify the base address of the to be built candidate
    pub fn base_address(mut self, base: crate::Address) -> Self {
        unsafe {
            crate::ffi::rice_candidate_set_base_address(&mut self.ffi, base.into_c_full());
            self
        }
    }

    /// Specify the related address of the to be built candidate
    pub fn related_address(mut self, related: crate::Address) -> Self {
        unsafe {
            crate::ffi::rice_candidate_set_related_address(&mut self.ffi, related.into_c_full());
            self
        }
    }

    /// Specify the type of TCP connection of the to be built candidate
    ///
    /// - This will panic at build() time if the transport type is not [`TransportType::Tcp`].
    /// - This will panic at build() time if this function is not called but the
    ///   transport type is [`TransportType::Tcp`]
    pub fn tcp_type(mut self, typ: TcpType) -> Self {
        unsafe {
            if self.ffi.transport_type != TransportType::Tcp.into() && typ != TcpType::None {
                panic!("Attempt made to set the TcpType of a non-TCP candidate");
            }
            crate::ffi::rice_candidate_set_tcp_type(&mut self.ffi, typ.into());
            self
        }
    }

    // TODO: extensions
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

/// The type of TCP candidate
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

/// The transport type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportType {
    /// UDP transport.
    Udp,
    /// TCP transport.
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

/// Paired local and remote candidate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    /// The local [`Candidate`]
    pub local: CandidateOwned,
    /// The remote [`Candidate`]
    pub remote: CandidateOwned,
}

impl CandidatePair {
    /// Create a new [`CandidatePair`]
    pub fn new(local: CandidateOwned, remote: CandidateOwned) -> Self {
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
