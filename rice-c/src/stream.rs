// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A [`Stream`] in an ICE [`Agent`](crate::agent::Agent).

use sans_io_time::Instant;

use crate::{candidate::TransportType, mut_override};

/// An ICE [`Stream`]
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

    /// An agent-global unique identifier for the ICE stream.
    pub fn id(&self) -> usize {
        unsafe { crate::ffi::rice_stream_get_id(self.ffi) }
    }

    /// Add a `Component` to this stream.
    pub fn add_component(&self) -> crate::component::Component {
        unsafe {
            crate::component::Component::from_c_full(
                crate::ffi::rice_stream_add_component(self.ffi),
                self.id(),
            )
        }
    }

    /// Retrieve a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, `None` is returned
    pub fn component(&self, id: usize) -> Option<crate::component::Component> {
        let ret = unsafe { crate::ffi::rice_stream_get_component(self.ffi, id) };
        if ret.is_null() {
            None
        } else {
            Some(crate::component::Component::from_c_full(ret, self.id()))
        }
    }

    /// Retreive the previouly set local ICE credentials for this `Stream`.
    pub fn local_credentials(&self) -> Option<Credentials> {
        let ret = unsafe { crate::ffi::rice_stream_get_local_credentials(self.ffi) };
        if ret.is_null() {
            None
        } else {
            Some(Credentials::from_c_full(ret))
        }
    }

    /// Retreive the previouly set remote ICE credentials for this `Stream`.
    pub fn remote_credentials(&self) -> Option<Credentials> {
        let ret = unsafe { crate::ffi::rice_stream_get_remote_credentials(self.ffi) };
        if ret.is_null() {
            None
        } else {
            Some(Credentials::from_c_full(ret))
        }
    }

    /// Set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_c::agent::Agent;
    /// # use rice_c::stream::Credentials;
    /// let mut agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_local_credentials(&credentials);
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn set_local_credentials(&self, credentials: &Credentials) {
        unsafe {
            crate::ffi::rice_stream_set_local_credentials(self.ffi, credentials.into_c_none())
        }
    }

    /// Set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rice_c::agent::Agent;
    /// # use rice_c::stream::Credentials;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials::new("user", "pass");
    /// stream.set_remote_credentials(&credentials);
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn set_remote_credentials(&self, credentials: &Credentials) {
        unsafe {
            crate::ffi::rice_stream_set_remote_credentials(self.ffi, credentials.into_c_none())
        }
    }

    /// Signal the end of local candidates.  Calling this function may allow ICE processing to
    /// complete.
    pub fn end_of_local_candidates(&self) {
        unsafe { crate::ffi::rice_stream_end_of_local_candidates(self.ffi) }
    }

    /// Add a remote candidate for connection checks for use with this stream
    pub fn add_remote_candidate(&self, cand: &crate::candidate::Candidate) {
        unsafe { crate::ffi::rice_stream_add_remote_candidate(self.ffi, cand.as_c()) }
    }

    /// Indicate that no more candidates are expected from the peer.  This may allow the ICE
    /// process to complete.
    pub fn end_of_remote_candidates(&self) {
        unsafe { crate::ffi::rice_stream_end_of_remote_candidates(self.ffi) }
    }

    /// Add a local candidate for this stream.
    ///
    /// Returns whether the candidate was added internally.
    pub fn add_local_gathered_candidate(&self, gathered: GatheredCandidate) -> bool {
        unsafe { crate::ffi::rice_stream_add_local_gathered_candidate(self.ffi, &gathered.ffi) }
    }

    /// Provide a reply to the
    /// [`AgentPoll::AllocateSocket`](crate::agent::AgentPoll::AllocateSocket) request.  The
    /// `component_id`, `transport`, `from`, and `to` values must match exactly with the request.
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

    /// The list of component ids available in this stream
    pub fn component_ids(&self) -> Vec<usize> {
        unsafe {
            let mut len = 0;
            crate::ffi::rice_stream_component_ids(self.ffi, &mut len, core::ptr::null_mut());
            let mut ret = vec![0; len];
            crate::ffi::rice_stream_component_ids(self.ffi, &mut len, ret.as_mut_ptr());
            ret.resize(len.min(ret.len()), 0);
            ret
        }
    }

    /// Provide the stream with data that has been received on an external socket.  The returned
    /// value indicates what has been done with the data and any application data that has been
    /// received.
    pub fn handle_incoming_data<'a>(
        &self,
        component_id: usize,
        transport: TransportType,
        from: crate::Address,
        to: crate::Address,
        data: &'a [u8],
        now: Instant,
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
                now.as_nanos(),
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

    /// Poll for any received data.
    ///
    /// Must be called after `handle_incoming_data` if `have_more_data` is `true`.
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

/// Data that should be sent to a peer as a result of calling [`Stream::poll_recv()`].
#[derive(Debug)]
pub struct PollRecv {
    /// The component id that the data was received for.
    pub component_id: usize,
    /// The received data.
    pub data: RecvData,
}

/// Data to send.
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

/// Return value to [`Stream::handle_incoming_data`].
#[derive(Debug)]
pub struct StreamIncomingDataReply<'a> {
    /// Some of the data was handled
    pub handled: bool,
    /// Data was received in addition to any in the `data` field that could be retrieved with
    /// [`Stream::poll_recv`].
    pub have_more_data: bool,
    /// Any application data that could be parsed from the incoming data.
    pub data: Option<&'a [u8]>,
}

/// A set of ICE/TURN credentials.
#[derive(Debug)]
pub struct Credentials {
    ffi: *mut crate::ffi::RiceCredentials,
}

impl Credentials {
    /// Create a new set of ICE/TURN credentials with the provided username and password.
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

/// A locally gathered candidate.
#[derive(Debug)]
pub struct GatheredCandidate {
    pub(crate) ffi: crate::ffi::RiceGatheredCandidate,
}

unsafe impl Send for GatheredCandidate {}

impl GatheredCandidate {
    pub(crate) fn from_c_full(ffi: crate::ffi::RiceGatheredCandidate) -> Self {
        Self { ffi }
    }

    /// Consume the contents of the mutable reference without leaving an invalid invariant.
    ///
    /// THis is useful when handling
    /// [`AgentGatheredCandidate`](crate::agent::AgentGatheredCandidate).
    pub fn take(&mut self) -> Self {
        unsafe {
            let mut ffi = crate::ffi::RiceGatheredCandidate {
                candidate: crate::ffi::RiceCandidate::zeroed(),
                turn_agent: self.ffi.turn_agent,
            };
            crate::ffi::rice_candidate_copy_into(&self.ffi.candidate, &mut ffi.candidate);
            self.ffi.turn_agent = core::ptr::null_mut();
            Self { ffi }
        }
    }

    /// The [`Candidate`](crate::candidate::Candidate).
    pub fn candidate(&self) -> crate::candidate::Candidate {
        unsafe { crate::candidate::Candidate::from_c_none(&self.ffi.candidate) }
    }
}

#[cfg(test)]
mod tests {
    use sans_io_time::Instant;

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
        component
            .gather_candidates([(transport, &addr)], [])
            .unwrap();

        let AgentPoll::AllocateSocket(ref alloc) = agent.poll(Instant::ZERO) else {
            unreachable!()
        };
        let from = &alloc.from;
        let to = &alloc.to;
        let component_id = alloc.component_id;

        let AgentPoll::GatheredCandidate(ref _candidate) = agent.poll(Instant::ZERO) else {
            unreachable!()
        };

        let AgentPoll::GatheredCandidate(ref _candidate) = agent.poll(Instant::ZERO) else {
            unreachable!()
        };

        let AgentPoll::WaitUntilNanos(_now) = agent.poll(Instant::ZERO) else {
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

        let _ = agent.poll_transmit(Instant::ZERO).unwrap();

        let _ = agent.poll(Instant::ZERO);
        let _ = agent.poll(Instant::ZERO);
    }
}
