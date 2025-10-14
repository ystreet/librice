// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICE Agent implementation as specified in RFC 8445

use crate::{candidate::TransportType, mut_override, stream::Stream};

use sans_io_time::Instant;

/// An ICE agent as specified in RFC 8445
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

    /// A process-unique identifier for this agent.
    pub fn id(&self) -> u64 {
        unsafe { crate::ffi::rice_agent_id(self.ffi) }
    }

    /// Add a new `Stream` to this agent
    ///
    /// # Examples
    ///
    /// Add a `Stream`
    ///
    /// ```
    /// # use rice_c::agent::Agent;
    /// let agent = Agent::default();
    /// let s = agent.add_stream();
    /// ```
    pub fn add_stream(&self) -> crate::stream::Stream {
        unsafe { Stream::from_c_full(crate::ffi::rice_agent_add_stream(self.ffi)) }
    }

    /// Retrieve a [`Stream`] by its ID from this [`Agent`].
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
    pub fn close(&self, now: Instant) {
        unsafe { crate::ffi::rice_agent_close(self.ffi, now.as_nanos()) }
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

    /// Poll the [`Agent`] for further progress to be made.
    ///
    /// The returned value indicates what the application needs to do.
    pub fn poll(&self, now: Instant) -> AgentPoll {
        let mut ret = crate::ffi::RiceAgentPoll {
            tag: crate::ffi::RICE_AGENT_POLL_CLOSED,
            field1: crate::ffi::RiceAgentPoll__bindgen_ty_1 {
                field1: core::mem::ManuallyDrop::new(
                    crate::ffi::RiceAgentPoll__bindgen_ty_1__bindgen_ty_1 {
                        wait_until_nanos: 0,
                    },
                ),
            },
        };

        unsafe {
            crate::ffi::rice_agent_poll_init(&mut ret);
            crate::ffi::rice_agent_poll(self.ffi, now.as_nanos(), &mut ret);
        }

        AgentPoll::from_c_full(ret)
    }

    /// Poll for a transmission to be performed.
    ///
    /// If not-None, then the provided data must be sent to the peer from the provided socket
    /// address.
    pub fn poll_transmit(&self, now: Instant) -> Option<AgentTransmit> {
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
        unsafe { crate::ffi::rice_agent_poll_transmit(self.ffi, now.as_nanos(), &mut ret) }
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

/// Indicates what the caller should do after calling [`Agent::poll`]
#[derive(Debug, Default)]
pub enum AgentPoll {
    /// The Agent is closed.  No further progress will be made.
    #[default]
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event)
    WaitUntilNanos(i64),
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
                crate::ffi::RICE_AGENT_POLL_WAIT_UNTIL_NANOS => Self::WaitUntilNanos(
                    core::mem::ManuallyDrop::into_inner(ffi.field1.field1).wait_until_nanos,
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
                    let local = crate::candidate::Candidate::from_c_none(&ty.local);
                    let remote = crate::candidate::Candidate::from_c_none(&ty.remote);
                    crate::ffi::rice_candidate_clear(&mut ty.local);
                    crate::ffi::rice_candidate_clear(&mut ty.remote);
                    ffi.tag = crate::ffi::RICE_AGENT_POLL_CLOSED;
                    let turn = if !ty.local_turn_local_addr.is_null()
                        && !ty.local_turn_remote_addr.is_null()
                    {
                        Some(SelectedTurn {
                            transport: ty.local_turn_transport.into(),
                            local_addr: crate::Address::from_c_none(ty.local_turn_local_addr),
                            remote_addr: crate::Address::from_c_none(ty.local_turn_remote_addr),
                        })
                    } else {
                        None
                    };
                    crate::ffi::rice_address_free(mut_override(ty.local_turn_local_addr));
                    ty.local_turn_local_addr = core::ptr::null_mut();
                    crate::ffi::rice_address_free(mut_override(ty.local_turn_remote_addr));
                    ty.local_turn_remote_addr = core::ptr::null_mut();
                    Self::SelectedPair(AgentSelectedPair {
                        stream_id: ty.stream_id,
                        component_id: ty.component_id,
                        local,
                        remote,
                        turn,
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
                                    gathered: crate::stream::GatheredCandidate::take(
                                        &mut gathered.gathered,
                                    )
                                    .ffi,
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
    /// The ICE stream id.
    pub stream_id: usize,
    /// The socket to send the data from.
    pub from: crate::Address,
    /// The network address to send the data to.
    pub to: crate::Address,
    /// The transport to send the data over.
    pub transport: crate::candidate::TransportType,
    /// The data to send.
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
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
    /// The transport.
    pub transport: crate::candidate::TransportType,
    /// The socket source address.
    pub from: crate::Address,
    /// The socket destination address.
    pub to: crate::Address,
}

/// A new pair has been selected for a component.
#[derive(Debug)]
pub struct AgentSelectedPair {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The ICE component id within the stream.
    pub component_id: usize,
    /// The local candidate that has been selected.
    pub local: crate::candidate::Candidate,
    /// The remote candidate that has been selected.
    pub remote: crate::candidate::Candidate,
    /// The selected local candidate TURN connection (if any).
    pub turn: Option<SelectedTurn>,
}

/// The selected TURN server socket parameters.
#[derive(Debug)]
pub struct SelectedTurn {
    /// The transport.
    pub transport: TransportType,
    /// The local address.
    pub local_addr: crate::Address,
    /// The remote address.
    pub remote_addr: crate::Address,
}

/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct AgentComponentStateChange {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
    /// The new state of the component.
    pub state: crate::component::ComponentConnectionState,
}

/// A [`Component`](crate::component::Component) has gathered a candidate.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheredCandidate {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The gathered candidate.
    pub gathered: crate::stream::GatheredCandidate,
}

/// A [`Component`](crate::component::Component) has completed gathering.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheringComplete {
    /// The ICE stream id.
    pub stream_id: usize,
    /// The ICE component id.
    pub component_id: usize,
}

/// Errors that can be returned as a result of agent operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum AgentError {
    /// The operation failed for an unspecified reason.
    Failed = crate::ffi::RICE_ERROR_FAILED,
    /// A required resource was not found.
    ResourceNotFound = crate::ffi::RICE_ERROR_RESOURCE_NOT_FOUND,
    /// The operation is already in progress.
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
