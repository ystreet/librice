// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{mut_override, stream::Stream};

pub use crate::stream::Credentials as TurnCredentials;

#[derive(Debug)]
pub struct Agent {
    ffi: *mut crate::ffi::RiceAgent,
}

unsafe impl Send for Agent {}
unsafe impl Sync for Agent {}

impl Clone for Agent {
    fn clone(&self) -> Self {
        Self {
            ffi: unsafe { crate::ffi::rice_agent_ref(self.ffi) },
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        unsafe { crate::ffi::rice_agent_unref(self.ffi) }
    }
}

impl Default for Agent {
    fn default() -> Self {
        Agent::builder().build()
    }
}

impl Agent {
    /// Create a new [`AgentBuilder`]
    pub fn builder() -> AgentBuilder {
        AgentBuilder::default()
    }

    pub fn id(&self) -> u64 {
        unsafe { crate::ffi::rice_agent_id(self.ffi) }
    }

    pub fn now(&self) -> u64 {
        unsafe { crate::ffi::rice_agent_now(self.ffi) }
    }

    /// Add a new `Stream` to this agent
    ///
    /// # Examples
    ///
    /// Add a `Stream`
    ///
    /// ```
    /// # use librice_c::agent::Agent;
    /// let agent = Agent::default();
    /// let s = agent.add_stream();
    /// ```
    pub fn add_stream(&self) -> crate::stream::Stream {
        unsafe { Stream::from_c_full(crate::ffi::rice_agent_add_stream(self.ffi)) }
    }

    pub fn stream(&self, id: usize) -> Option<crate::stream::Stream> {
        let ret = unsafe { crate::ffi::rice_agent_get_stream(self.ffi, id) };
        if ret.is_null() {
            None
        } else {
            Some(crate::stream::Stream::from_c_full(ret))
        }
    }

    /// Close the agent loop.  Applications should wait for [`Agent::poll`] to return
    /// [`AgentPoll::Closed`] after calling this function.
    pub fn close(&self, now_micros: u64) {
        unsafe { crate::ffi::rice_agent_close(self.ffi, now_micros) }
    }

    /// The controlling state of this ICE agent.  This value may change throughout the ICE
    /// negotiation process.
    pub fn controlling(&self) -> bool {
        unsafe { crate::ffi::rice_agent_get_controlling(self.ffi) }
    }

    /// Add a STUN server by address and transport to use for gathering potential candidates
    pub fn add_stun_server(
        &self,
        transport: crate::candidate::TransportType,
        addr: crate::Address,
    ) {
        unsafe { crate::ffi::rice_agent_add_stun_server(self.ffi, transport.into(), addr.as_c()) }
    }

    /// Add a STUN server by address and transport to use for gathering potential candidates
    pub fn add_turn_server(
        &self,
        transport: crate::candidate::TransportType,
        addr: crate::Address,
        credentials: TurnCredentials,
    ) {
        unsafe {
            crate::ffi::rice_agent_add_turn_server(
                self.ffi,
                transport.into(),
                addr.as_c(),
                credentials.into_c_none(),
            )
        }
    }

    pub fn poll(&self, now_micros: u64) -> AgentPoll {
        let mut ret = crate::ffi::RiceAgentPoll {
            tag: crate::ffi::RICE_AGENT_POLL_CLOSED,
            field1: crate::ffi::RiceAgentPoll__bindgen_ty_1 {
                field1: core::mem::ManuallyDrop::new(
                    crate::ffi::RiceAgentPoll__bindgen_ty_1__bindgen_ty_1 {
                        wait_until_micros: 0,
                    },
                ),
            },
        };

        unsafe {
            crate::ffi::rice_agent_poll_init(&mut ret);
            crate::ffi::rice_agent_poll(self.ffi, now_micros, &mut ret);
        }

        AgentPoll::from_c_full(ret)
    }

    pub fn poll_transmit(&self, now_micros: u64) -> Option<AgentTransmit> {
        let mut ret = crate::ffi::RiceTransmit {
            stream_id: 0,
            transport: crate::ffi::RICE_TRANSPORT_TYPE_UDP,
            from: core::ptr::null(),
            to: core::ptr::null(),
            data: crate::ffi::RiceDataImpl {
                ptr: core::ptr::null_mut(),
                size: 0,
            },
        };
        unsafe { crate::ffi::rice_agent_poll_transmit(self.ffi, now_micros, &mut ret) }
        if ret.from.is_null() || ret.to.is_null() {
            return None;
        }
        Some(AgentTransmit::from_c_full(ret))
    }
    // TODO: stun_servers(), add_turn_server(), turn_servers(), stream()
}

/// A builder for an [`Agent`]
#[derive(Debug, Default)]
pub struct AgentBuilder {
    trickle_ice: bool,
    controlling: bool,
}

impl AgentBuilder {
    /// Whether candidates can trickle in during ICE negotiation
    pub fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
        self
    }

    /// The initial value of the controlling attribute.  During the ICE negotiation, the
    /// controlling value may change.
    pub fn controlling(mut self, controlling: bool) -> Self {
        self.controlling = controlling;
        self
    }

    /// Construct a new [`Agent`]
    pub fn build(self) -> Agent {
        Agent {
            ffi: unsafe { crate::ffi::rice_agent_new(self.controlling, self.trickle_ice) },
        }
    }
}

#[derive(Debug, Default)]
pub enum AgentPoll {
    /// The Agent is closed.  No further progress will be made.
    #[default]
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event)
    WaitUntilMicros(u64),
    /// Connect from the specified interface to the specified address.  Reply (success or failure)
    /// should be notified using [`Stream::allocated_socket`] with the same parameters.
    AllocateSocket(AgentSocket),
    /// It is posible to remove the specified 5-tuple. The socket will not be referenced any
    /// further.
    RemoveSocket(AgentSocket),
    /// A new pair has been selected for a component.
    SelectedPair(AgentSelectedPair),
    /// A [`Component`](crate::component::Component) has changed state.
    ComponentStateChange(AgentComponentStateChange),
    /// A [`Component`](crate::component::Component) has gathered a candidate.
    GatheredCandidate(AgentGatheredCandidate),
    /// A [`Component`](crate::component::Component) has completed gathering.
    GatheringComplete(AgentGatheringComplete),
}

impl AgentPoll {
    fn from_c_full(mut ffi: crate::ffi::RiceAgentPoll) -> Self {
        unsafe {
            let ret = match ffi.tag {
                crate::ffi::RICE_AGENT_POLL_CLOSED => Self::Closed,
                crate::ffi::RICE_AGENT_POLL_WAIT_UNTIL_MICROS => Self::WaitUntilMicros(
                    core::mem::ManuallyDrop::into_inner(ffi.field1.field1).wait_until_micros,
                ),
                crate::ffi::RICE_AGENT_POLL_ALLOCATE_SOCKET => {
                    let ty = core::mem::ManuallyDrop::into_inner(ffi.field1.field2).allocate_socket;
                    Self::AllocateSocket(AgentSocket {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                        transport: ty.transport.into(),
                        from: crate::Address::from_c_full(mut_override(ty.from)),
                        to: crate::Address::from_c_full(mut_override(ty.to)),
                    })
                }
                crate::ffi::RICE_AGENT_POLL_REMOVE_SOCKET => {
                    let ty = core::mem::ManuallyDrop::into_inner(ffi.field1.field3).remove_socket;
                    ffi.tag = crate::ffi::RICE_AGENT_POLL_CLOSED;
                    Self::RemoveSocket(AgentSocket {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                        transport: ty.transport.into(),
                        from: crate::Address::from_c_full(mut_override(ty.from)),
                        to: crate::Address::from_c_full(mut_override(ty.to)),
                    })
                }
                crate::ffi::RICE_AGENT_POLL_SELECTED_PAIR => {
                    let mut ty =
                        core::mem::ManuallyDrop::into_inner(ffi.field1.field4).selected_pair;
                    let local = crate::candidate::Candidate::from_c_full(
                        crate::ffi::rice_candidate_copy(&ty.local),
                    );
                    let remote = crate::candidate::Candidate::from_c_full(
                        crate::ffi::rice_candidate_copy(&ty.remote),
                    );
                    crate::ffi::rice_candidate_clear(&mut ty.local);
                    crate::ffi::rice_candidate_clear(&mut ty.remote);
                    Self::SelectedPair(AgentSelectedPair {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                        local,
                        remote,
                    })
                }
                crate::ffi::RICE_AGENT_POLL_COMPONENT_STATE_CHANGE => {
                    let ty = core::mem::ManuallyDrop::into_inner(ffi.field1.field5)
                        .component_state_change;
                    Self::ComponentStateChange(AgentComponentStateChange {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                        state: crate::component::ComponentConnectionState::from_c(ty.state),
                    })
                }
                crate::ffi::RICE_AGENT_POLL_GATHERED_CANDIDATE => {
                    let ty =
                        core::mem::ManuallyDrop::into_inner(ffi.field1.field6).gathered_candidate;
                    let stream_id = ty.stream_id;
                    let gathered = crate::stream::GatheredCandidate::from_c_full(ty.gathered);
                    ffi.tag = crate::ffi::RICE_AGENT_POLL_CLOSED;
                    Self::GatheredCandidate(AgentGatheredCandidate {
                        stream_id,
                        gathered,
                    })
                }
                crate::ffi::RICE_AGENT_POLL_GATHERING_COMPLETE => {
                    let ty =
                        core::mem::ManuallyDrop::into_inner(ffi.field1.field7).gathering_complete;
                    Self::GatheringComplete(AgentGatheringComplete {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                    })
                }
                tag => panic!("Unkown AgentPoll value {tag:x?}"),
            };
            ret
        }
    }
}

impl Drop for AgentPoll {
    fn drop(&mut self) {
        unsafe {
            if let Self::GatheredCandidate(gathered) = self {
                let mut ret = crate::ffi::RiceAgentPoll {
                    tag: crate::ffi::RICE_AGENT_POLL_GATHERED_CANDIDATE,
                    field1: crate::ffi::RiceAgentPoll__bindgen_ty_1 {
                        field6: core::mem::ManuallyDrop::new(
                            crate::ffi::RiceAgentPoll__bindgen_ty_1__bindgen_ty_6 {
                                gathered_candidate: crate::ffi::RiceAgentGatheredCandidate {
                                    stream_id: gathered.stream_id,
                                    gathered: core::mem::take(&mut gathered.gathered.ffi),
                                },
                            },
                        ),
                    },
                };
                crate::ffi::rice_agent_poll_clear(&raw mut ret);
            }
        }
    }
}

/// Transmit the data using the specified 5-tuple.
#[derive(Debug)]
pub struct AgentTransmit {
    pub stream_id: usize,
    pub from: crate::Address,
    pub to: crate::Address,
    pub transport: crate::candidate::TransportType,
    pub data: &'static [u8],
}

impl AgentTransmit {
    pub(crate) fn from_c_full(ffi: crate::ffi::RiceTransmit) -> Self {
        unsafe {
            let data = ffi.data.ptr;
            let len = ffi.data.size;
            let data = core::slice::from_raw_parts(data, len);
            AgentTransmit {
                stream_id: ffi.stream_id,
                from: crate::Address::from_c_full(mut_override(ffi.from)),
                to: crate::Address::from_c_full(mut_override(ffi.to)),
                transport: ffi.transport.into(),
                data,
            }
        }
    }
}

impl Drop for AgentTransmit {
    fn drop(&mut self) {
        unsafe {
            let mut transmit = crate::ffi::RiceTransmit {
                stream_id: self.stream_id,
                from: core::ptr::null_mut(),
                to: core::ptr::null_mut(),
                transport: self.transport.into(),
                data: crate::ffi::RiceDataImpl::to_c(self.data),
            };
            crate::ffi::rice_transmit_clear(&mut transmit);
        }
    }
}

/// A socket with the specified network 5-tuple.
#[derive(Debug)]
pub struct AgentSocket {
    pub stream_id: usize,
    pub component_id: usize,
    pub transport: crate::candidate::TransportType,
    pub from: crate::Address,
    pub to: crate::Address,
}

/// A new pair has been selected for a component.
#[derive(Debug)]
pub struct AgentSelectedPair {
    pub stream_id: usize,
    pub component_id: usize,
    pub local: crate::candidate::Candidate,
    pub remote: crate::candidate::Candidate,
}

/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct AgentComponentStateChange {
    pub stream_id: usize,
    pub component_id: usize,
    pub state: crate::component::ComponentConnectionState,
}

/// A [`Component`](crate::component::Component) has gathered a candidate.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheredCandidate {
    pub stream_id: usize,
    pub gathered: crate::stream::GatheredCandidate,
}

/// A [`Component`](crate::component::Component) has completed gathering.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheringComplete {
    pub stream_id: usize,
    pub component_id: usize,
}

#[derive(Debug)]
#[repr(i32)]
pub enum AgentError {
    Failed = crate::ffi::RICE_ERROR_FAILED,
    ResourceNotFound = crate::ffi::RICE_ERROR_RESOURCE_NOT_FOUND,
    AlreadyInProgress = crate::ffi::RICE_ERROR_ALREADY_IN_PROGRESS,
}

impl core::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed => write!(f, "Failed"),
            Self::ResourceNotFound => write!(f, "Resource Not Found"),
            Self::AlreadyInProgress => write!(f, "Already In Progress"),
        }
    }
}

impl AgentError {
    pub(crate) fn from_c(value: crate::ffi::RiceError) -> Result<(), AgentError> {
        match value {
            crate::ffi::RICE_ERROR_SUCCESS => Ok(()),
            crate::ffi::RICE_ERROR_FAILED => Err(AgentError::Failed),
            crate::ffi::RICE_ERROR_RESOURCE_NOT_FOUND => Err(AgentError::ResourceNotFound),
            crate::ffi::RICE_ERROR_ALREADY_IN_PROGRESS => Err(AgentError::AlreadyInProgress),
            val => panic!("unknown RiceError value {val:x?}"),
        }
    }
}
