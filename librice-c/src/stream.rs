// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{candidate::TransportType, mut_override};

#[derive(Debug)]
pub struct Stream {
    ffi: *mut crate::ffi::RiceStream,
}

unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Clone for Stream {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_stream_ref(self.ffi) },
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_stream_unref(self.ffi) };
    }
}

impl Stream {
    pub(crate) fn from_c_full(stream: *mut crate::ffi::RiceStream) -> Self {
        Self { ffi: stream }
    }

    pub fn id(&self) -> usize {
        unsafe { crate::ffi::rice_stream_get_id(self.ffi) }
    }

    pub fn add_component(&self) -> crate::component::Component {
        unsafe {
            crate::component::Component::from_c_full(
                crate::ffi::rice_stream_add_component(self.ffi),
                self.id(),
            )
        }
    }

    pub fn component(&self, id: usize) -> Option<crate::component::Component> {
        let ret = unsafe { crate::ffi::rice_stream_get_component(self.ffi, id) };
        if ret.is_null() {
            None
        } else {
            Some(crate::component::Component::from_c_full(ret, self.id()))
        }
    }

    pub fn local_credentials(&self) -> Option<Credentials> {
        let ret = unsafe { crate::ffi::rice_stream_get_local_credentials(self.ffi) };
        if ret.is_null() {
            None
        } else {
            Some(Credentials::from_c_full(ret))
        }
    }

    pub fn remote_credentials(&self) -> Option<Credentials> {
        let ret = unsafe { crate::ffi::rice_stream_get_remote_credentials(self.ffi) };
        if ret.is_null() {
            None
        } else {
            Some(Credentials::from_c_full(ret))
        }
    }

    pub fn set_remote_credentials(&self, credentials: &Credentials) {
        unsafe {
            crate::ffi::rice_stream_set_remote_credentials(self.ffi, credentials.into_c_none())
        }
    }

    pub fn set_local_credentials(&self, credentials: &Credentials) {
        unsafe {
            crate::ffi::rice_stream_set_local_credentials(self.ffi, credentials.into_c_none())
        }
    }

    pub fn end_of_local_candidates(&self) {
        unsafe { crate::ffi::rice_stream_end_of_local_candidates(self.ffi) }
    }

    pub fn add_remote_candidate(&self, cand: crate::candidate::Candidate) {
        unsafe { crate::ffi::rice_stream_add_remote_candidate(self.ffi, cand.as_c()) }
    }

    pub fn end_of_remote_candidates(&self) {
        unsafe { crate::ffi::rice_stream_end_of_remote_candidates(self.ffi) }
    }

    pub fn add_local_gathered_candidate(&self, gathered: GatheredCandidate) -> bool {
        unsafe { crate::ffi::rice_stream_add_local_gathered_candidate(self.ffi, &gathered.ffi) }
    }

    pub fn allocated_socket(
        &self,
        component_id: usize,
        transport: TransportType,
        from: &crate::Address,
        to: &crate::Address,
        socket_addr: Option<crate::Address>,
    ) {
        let socket_addr = if let Some(addr) = socket_addr {
            addr.into_c_full()
        } else {
            core::ptr::null_mut()
        };
        unsafe {
            crate::ffi::rice_stream_handle_allocated_socket(
                self.ffi,
                component_id,
                transport.into(),
                from.as_c(),
                to.as_c(),
                socket_addr,
            )
        }
    }

    pub fn component_ids(&self) -> Vec<usize> {
        unsafe {
            let mut len = 0;
            crate::ffi::rice_stream_component_ids(self.ffi, &mut len, core::ptr::null_mut());
            let mut ret = vec![0; len];
            crate::ffi::rice_stream_component_ids(self.ffi, &mut len, ret.as_mut_ptr());
            ret
        }
    }

    pub fn handle_incoming_data<'a>(
        &self,
        component_id: usize,
        transport: TransportType,
        from: crate::Address,
        to: crate::Address,
        data: &'a [u8],
        now_micros: u64,
    ) -> StreamIncomingDataReply<'a> {
        unsafe {
            let mut stream_ret = crate::ffi::RiceStreamIncomingData::default();
            crate::ffi::rice_stream_handle_incoming_data(
                self.ffi,
                component_id,
                transport.into(),
                from.as_c(),
                to.as_c(),
                data.as_ptr(),
                data.len(),
                now_micros,
                &mut stream_ret,
            );
            let mut ret = StreamIncomingDataReply {
                handled: stream_ret.handled,
                have_more_data: stream_ret.have_more_data,
                data: None,
            };
            if !stream_ret.data.ptr.is_null() && stream_ret.data.size > 0 {
                ret.data = Some(data);
            }
            ret
        }
    }

    pub fn poll_recv(&self) -> Option<PollRecv> {
        unsafe {
            let mut len = 0;
            let mut component_id = 0;
            let ptr = crate::ffi::rice_stream_poll_recv(self.ffi, &mut component_id, &mut len);
            if ptr.is_null() {
                return None;
            }
            let slice = core::slice::from_raw_parts(ptr, len);
            Some(PollRecv {
                component_id,
                data: RecvData { data: slice },
            })
        }
    }
}

#[derive(Debug)]
pub struct PollRecv {
    pub component_id: usize,
    pub data: RecvData,
}

#[derive(Debug)]
pub struct RecvData {
    data: &'static [u8],
}

impl core::ops::Deref for RecvData {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl Drop for RecvData {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_free_data(mut_override(self.data.as_ptr())) }
    }
}

#[derive(Debug)]
pub struct StreamIncomingDataReply<'a> {
    pub handled: bool,
    pub have_more_data: bool,
    pub data: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct Credentials {
    ffi: *mut crate::ffi::RiceCredentials,
}

impl Credentials {
    pub fn new(ufrag: &str, passwd: &str) -> Self {
        let ufrag = std::ffi::CString::new(ufrag).unwrap();
        let passwd = std::ffi::CString::new(passwd).unwrap();
        unsafe {
            Self {
                ffi: crate::ffi::rice_credentials_new(ufrag.as_ptr(), passwd.as_ptr()),
            }
        }
    }

    pub(crate) fn from_c_full(ffi: *mut crate::ffi::RiceCredentials) -> Self {
        Self { ffi }
    }

    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn into_c_none(&self) -> *const crate::ffi::RiceCredentials {
        self.ffi
    }
}

impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        unsafe { crate::ffi::rice_credentials_eq(self.ffi, other.ffi) }
    }
}

impl Clone for Credentials {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_credentials_copy(self.ffi) },
        }
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_credentials_free(self.ffi) }
    }
}

#[derive(Debug, Default)]
pub struct GatheredCandidate {
    pub(crate) ffi: crate::ffi::RiceGatheredCandidate,
}

impl GatheredCandidate {
    pub(crate) fn from_c_full(ffi: crate::ffi::RiceGatheredCandidate) -> Self {
        Self { ffi }
    }

    pub fn take(&mut self) -> Self {
        core::mem::take(self)
    }

    pub(crate) fn into_c_full(self) -> crate::ffi::RiceGatheredCandidate {
        self.ffi
    }

    pub fn candidate(&self) -> crate::candidate::Candidate {
        unsafe {
            crate::candidate::Candidate::from_c_full(crate::ffi::rice_candidate_copy(
                &self.ffi.candidate,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentPoll};

    #[test]
    fn gather_candidates() {
        let addr: crate::Address = "192.168.0.1:1000".parse().unwrap();
        let stun_addr: crate::Address = "102.168.0.200:2000".parse().unwrap();
        let agent = Agent::builder().build();
        let stream = agent.add_stream();
        let component = stream.add_component();
        let transport = TransportType::Tcp;
        let local_credentials = Credentials::new("luser", "lpass");
        let remote_credentials = Credentials::new("ruser", "rpass");

        agent.add_stun_server(transport, stun_addr);
        stream.set_local_credentials(&local_credentials);
        stream.set_remote_credentials(&remote_credentials);
        component.gather_candidates([(transport, addr)]).unwrap();

        let AgentPoll::AllocateSocket(ref alloc) = agent.poll(0) else {
            unreachable!()
        };
        let from = &alloc.from;
        let to = &alloc.to;
        let component_id = alloc.component_id;

        let AgentPoll::GatheredCandidate(ref _candidate) = agent.poll(0) else {
            unreachable!()
        };

        let AgentPoll::GatheredCandidate(ref _candidate) = agent.poll(0) else {
            unreachable!()
        };

        let AgentPoll::WaitUntilMicros(_now) = agent.poll(0) else {
            unreachable!()
        };

        let tcp_from_addr: crate::Address = "192.168.200.4:3000".parse().unwrap();
        stream.allocated_socket(
            component_id,
            TransportType::Tcp,
            from,
            to,
            Some(tcp_from_addr),
        );

        let _ = agent.poll_transmit(0).unwrap();

        let _ = agent.poll(0);
        let _ = agent.poll(0);
    }
}
