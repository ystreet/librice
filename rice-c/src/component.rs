// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A [`Component`] in an ICE [`Stream`](crate::stream::Stream)

use sans_io_time::Instant;

use crate::agent::{AgentError, AgentTransmit};
use crate::candidate::{CandidatePair, TransportType};
use crate::turn::TurnConfig;
use crate::{Address, const_override, mut_override};

/// A [`Component`] in an ICE [`Stream`](crate::stream::Stream)
#[derive(Debug)]
pub struct Component {
    ffi: *mut crate::ffi::RiceComponent,
    stream_id: usize,
}

unsafe impl Send for Component {}
unsafe impl Sync for Component {}

impl Clone for Component {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_component_ref(self.ffi) },
            stream_id: self.stream_id,
        }
    }
}

impl Drop for Component {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_component_unref(self.ffi) }
    }
}

impl Component {
    pub(crate) fn from_c_full(component: *mut crate::ffi::RiceComponent, stream_id: usize) -> Self {
        Self {
            ffi: component,
            stream_id,
        }
    }

    /// The component identifier within a particular ICE [`Stream`](crate::stream::Stream)
    pub fn id(&self) -> usize {
        unsafe { crate::ffi::rice_component_get_id(self.ffi) }
    }

    /// Retrieve the [`Stream`](crate::stream::Stream) for this component.
    pub fn stream(&self) -> crate::stream::Stream {
        unsafe {
            crate::stream::Stream::from_c_full(crate::ffi::rice_component_get_stream(self.ffi))
        }
    }

    /// Retrieve the current state of a `Component`
    pub fn state(&self) -> ComponentConnectionState {
        unsafe { crate::ffi::rice_component_get_state(self.ffi).into() }
    }

    /// The [`CandidatePair`] this component has selected to send/receive data with.  This will not
    /// be valid until the [`Component`] has reached [`ComponentConnectionState::Connected`]
    pub fn selected_pair(&self) -> Option<CandidatePair> {
        unsafe {
            let mut local = crate::ffi::RiceCandidate::zeroed();
            let mut remote = crate::ffi::RiceCandidate::zeroed();
            crate::ffi::rice_component_selected_pair(self.ffi, &mut local, &mut remote);
            if local.address.is_null() || remote.address.is_null() {
                None
            } else {
                Some(crate::candidate::CandidatePair::new(
                    crate::candidate::Candidate::from_c_full(local).to_owned(),
                    crate::candidate::Candidate::from_c_full(remote).to_owned(),
                ))
            }
        }
    }

    /// Start gathering candidates for this component.  The parent
    /// [`Agent::poll`](crate::agent::Agent::poll) is used to progress
    /// the gathering.
    ///
    /// Candidates will be generated as follows (if they succeed):
    ///
    /// 1. A host candidate for each `sockets[i]`. If TCP, then both an active and passive host
    ///    candidate will be generated.
    /// 2. For each configured STUN server a reflexive candidate if different from any
    ///    other candidate produced. The local address for each STUN server connection will be one
    ///    of the entries provided in `sockets`.
    /// 3. For each `turn_servers[i]` a TURN allocation will be attempted and a relayed candidate
    ///    produced on success.  If you would like multiple options for relayed candidates,
    ///    e.g. UDP, TCP, TCP/TLS, then provide each options as different entries in the provided
    ///    Iterator. The `Address` for each TURN server is the local address to communicate with
    ///    the TURN server and should be different than any value provided through `sockets`.
    pub fn gather_candidates<'a, 'b>(
        &self,
        sockets: impl IntoIterator<Item = (TransportType, &'a Address)>,
        turn_servers: impl IntoIterator<Item = (&'b Address, TurnConfig)>,
    ) -> Result<(), AgentError> {
        unsafe {
            let mut transports = vec![];
            let mut socket_addr = vec![];
            let mut socket_addresses = vec![];
            for (ttype, addr) in sockets.into_iter() {
                transports.push(ttype.into());
                socket_addresses.push(const_override(addr.ffi));
                socket_addr.push(addr);
            }
            let mut turn_sockets = vec![];
            let mut turn_configs = vec![];
            for (turn_addr, config) in turn_servers.into_iter() {
                turn_sockets.push(const_override(turn_addr.ffi));
                turn_configs.push(config.into_c_full());
            }
            AgentError::from_c(crate::ffi::rice_component_gather_candidates(
                self.ffi,
                transports.len(),
                socket_addresses.as_ptr(),
                transports.as_ptr(),
                turn_sockets.len(),
                turn_sockets.as_ptr(),
                turn_configs.as_ptr(),
            ))
        }
    }

    /// Set the pair that will be used to send/receive data.  This will override the ICE
    /// negotiation chosen value.
    pub fn set_selected_pair(&self, pair: CandidatePair) -> Result<(), AgentError> {
        unsafe {
            AgentError::from_c(crate::ffi::rice_component_set_selected_pair(
                self.ffi,
                pair.local.as_c(),
                pair.remote.as_c(),
            ))
        }
    }

    /// Send data to the peer using the selected pair.  This will not succeed until the
    /// [`Component`] has reached [`ComponentConnectionState::Connected`]
    pub fn send(&self, data: &[u8], now: Instant) -> Result<AgentTransmit, AgentError> {
        unsafe {
            let mut transmit = crate::ffi::RiceTransmit {
                stream_id: self.stream_id,
                transport: TransportType::Udp.into(),
                from: core::ptr::null(),
                to: core::ptr::null(),
                data: crate::ffi::RiceDataImpl {
                    ptr: core::ptr::null_mut(),
                    size: 0,
                },
            };
            AgentError::from_c(crate::ffi::rice_component_send(
                self.ffi,
                mut_override(data.as_ptr()),
                data.len(),
                now.as_nanos(),
                &mut transmit,
            ))?;
            Ok(AgentTransmit::from_c_full(transmit))
        }
    }
}

/// The state of a component
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ComponentConnectionState {
    /// Component is in initial state and no connectivity checks are in progress.
    New = crate::ffi::RICE_COMPONENT_CONNECTION_STATE_NEW,
    /// Connectivity checks are in progress for this candidate
    Connecting = crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTING,
    /// A [`CandidatePair`](crate::candidate::CandidatePair`) has been selected for this component
    Connected = crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTED,
    /// No connection could be found for this Component
    Failed = crate::ffi::RICE_COMPONENT_CONNECTION_STATE_FAILED,
}

impl ComponentConnectionState {
    pub(crate) fn from_c(ffi: crate::ffi::RiceComponentConnectionState) -> Self {
        match ffi {
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_NEW => Self::New,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTING => Self::Connecting,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTED => Self::Connected,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_FAILED => Self::Failed,
            _ => panic!("Unknown RiceComponentConnectionState value {ffi:x?}"),
        }
    }
}

impl From<crate::ffi::RiceComponentConnectionState> for ComponentConnectionState {
    fn from(value: crate::ffi::RiceComponentConnectionState) -> Self {
        match value {
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_NEW => Self::New,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTING => Self::Connecting,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_CONNECTED => Self::Connected,
            crate::ffi::RICE_COMPONENT_CONNECTION_STATE_FAILED => Self::Failed,
            val => panic!("Unknown component connection state value {val:x?}"),
        }
    }
}
