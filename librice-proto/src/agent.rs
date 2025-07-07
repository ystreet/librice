// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ICE Agent implementation as specified in RFC 8445

use std::error::Error;
use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use rand::prelude::*;
use stun_proto::types::data::Data;

use crate::candidate::{ParseCandidateError, TransportType};
use crate::component::ComponentConnectionState;
use crate::conncheck::{CheckListSetPollRet, ConnCheckEvent, ConnCheckListSet, SelectedPair};
use crate::gathering::{GatherPoll, GatheredCandidate};
use crate::stream::{Stream, StreamMut, StreamState};
use stun_proto::agent::{StunError, Transmit};
use stun_proto::types::message::StunParseError;

pub use turn_client_proto::types::TurnCredentials;

/// Errors that can be returned as a result of agent operations.
#[derive(Debug)]
pub enum AgentError {
    Failed,
    /// The specified resource already exists and cannot be added.
    AlreadyExists,
    /// The operation is already in progress.
    AlreadyInProgress,
    /// The operation is not in progress.
    NotInProgress,
    /// Could not find the specified resource.
    ResourceNotFound,
    /// Too little data provided.
    NotEnoughData,
    InvalidSize,
    Malformed,
    NotStun,
    WrongImplementation,
    TooBig,
    ConnectionClosed,
    IntegrityCheckFailed,
    Aborted,
    TimedOut,
    StunParse,
    StunWrite,
    /// Parsing the candidate failed.
    CandidateParse(ParseCandidateError),
    /// Data was received that does not match the protocol specifications.
    ProtocolViolation,
}

impl Error for AgentError {}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<ParseCandidateError> for AgentError {
    fn from(e: ParseCandidateError) -> Self {
        Self::CandidateParse(e)
    }
}

impl From<StunError> for AgentError {
    fn from(e: StunError) -> Self {
        match e {
            StunError::ResourceNotFound => AgentError::ResourceNotFound,
            StunError::TimedOut => AgentError::TimedOut,
            StunError::ProtocolViolation => AgentError::ProtocolViolation,
            StunError::ParseError(_) => AgentError::StunParse,
            StunError::WriteError(_) => AgentError::StunWrite,
            StunError::Aborted => AgentError::Aborted,
            StunError::AlreadyInProgress => AgentError::AlreadyInProgress,
        }
    }
}

impl From<StunParseError> for AgentError {
    fn from(_e: StunParseError) -> Self {
        Self::StunParse
    }
}

/// An ICE agent as specified in RFC 8445
#[derive(Debug)]
pub struct Agent {
    id: usize,
    pub(crate) checklistset: ConnCheckListSet,
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
    pub(crate) turn_servers: Vec<(TransportType, SocketAddr, TurnCredentials)>,
    streams: Vec<StreamState>,
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
        let id = AGENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut rnd = rand::rng();
        let tie_breaker = rnd.random::<u64>();
        let controlling = self.controlling;
        Agent {
            id,
            checklistset: ConnCheckListSet::builder(tie_breaker, controlling)
                .trickle_ice(self.trickle_ice)
                .build(),
            stun_servers: vec![],
            turn_servers: vec![],
            streams: vec![],
        }
    }
}

static AGENT_COUNT: AtomicUsize = AtomicUsize::new(0);

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

    /// The identifier for this [`Agent`]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Add a new `Stream` to this agent
    ///
    /// # Examples
    ///
    /// Add a `Stream`
    ///
    /// ```
    /// # use librice_proto::agent::Agent;
    /// let mut agent = Agent::default();
    /// let s = agent.add_stream();
    /// ```
    #[tracing::instrument(
        name = "ice_add_stream",
        skip(self),
        fields(
            ice.id = self.id
        )
    )]
    pub fn add_stream(&mut self) -> usize {
        let checklist_id = self.checklistset.new_list();
        let id = self.streams.len();
        let stream = crate::stream::StreamState::new(id, checklist_id);
        self.streams.push(stream);
        id
    }

    /// Close the agent loop.  Applications should wait for [`Agent::poll`] to return
    /// [`AgentPoll::Closed`] after calling this function.
    #[tracing::instrument(
        name = "ice_close",
        skip(self),
        fields(
            ice.id = self.id
        )
    )]
    pub fn close(&mut self, now: Instant) {
        info!("closing agent");
        self.checklistset.close(now);
    }

    /// The controlling state of this ICE agent.  This value may change throughout the ICE
    /// negotiation process.
    pub fn controlling(&self) -> bool {
        self.checklistset.controlling()
    }

    /// Add a STUN server by address and transport to use for gathering potential candidates
    #[tracing::instrument(
        name = "ice_add_stun_server",
        skip(self)
        fields(ice.id = self.id)
    )]
    pub fn add_stun_server(&mut self, transport: TransportType, addr: SocketAddr) {
        info!("Adding stun server");
        self.stun_servers.push((transport, addr));
        // TODO: propagate towards the gatherer as required
    }

    /// The current list of STUN servers used by this [`Agent`]
    pub fn stun_servers(&self) -> &Vec<(TransportType, SocketAddr)> {
        &self.stun_servers
    }

    #[tracing::instrument(
        name = "ice_add_turn_server",
        skip(self)
        fields(ice.id = self.id)
    )]
    pub fn add_turn_server(
        &mut self,
        transport: TransportType,
        addr: SocketAddr,
        credentials: TurnCredentials,
    ) {
        info!("Adding turn server");
        self.turn_servers.push((transport, addr, credentials));
        // TODO: propagate towards the gatherer as required
    }

    /// The current list of STUN servers used by this [`Agent`]
    pub fn turn_servers(&self) -> &Vec<(TransportType, SocketAddr, TurnCredentials)> {
        &self.turn_servers
    }

    /// Get a [`Stream`] by id.  If the stream does not exist, then `None` will be returned.
    pub fn stream(&self, id: usize) -> Option<crate::stream::Stream<'_>> {
        if self.streams.get(id).is_some() {
            Some(Stream::from_agent(self, id))
        } else {
            None
        }
    }

    pub(crate) fn stream_state(&self, id: usize) -> Option<&crate::stream::StreamState> {
        self.streams.get(id)
    }

    /// Get a [`StreamMut`] by id.  If the stream does not exist, then `None` will be returned.
    pub fn mut_stream(&mut self, id: usize) -> Option<StreamMut> {
        if self.streams.get_mut(id).is_some() {
            Some(StreamMut::from_agent(self, id))
        } else {
            None
        }
    }

    pub(crate) fn mut_stream_state(
        &mut self,
        id: usize,
    ) -> Option<&mut crate::stream::StreamState> {
        self.streams.get_mut(id)
    }

    /// Poll the [`Agent`] for further progress to be made.  The returned value indicates what the
    /// application needs to do.
    #[tracing::instrument(
        name = "agent_poll",
        ret
        skip(self)
        fields(
            id = self.id,
        )
    )]
    pub fn poll(&mut self, now: Instant) -> AgentPoll {
        let mut lowest_wait = None;

        for stream in self.streams.iter_mut() {
            let stream_id = stream.id();
            match stream.poll_gather(now) {
                GatherPoll::AllocateSocket {
                    component_id,
                    transport,
                    local_addr,
                    remote_addr,
                } => {
                    return AgentPoll::AllocateSocket(AgentSocket {
                        stream_id,
                        component_id,
                        transport,
                        from: local_addr,
                        to: remote_addr,
                    })
                }
                GatherPoll::WaitUntil(earliest_wait) => {
                    if let Some(check_wait) = lowest_wait {
                        if earliest_wait < check_wait {
                            lowest_wait = Some(earliest_wait);
                        }
                    } else {
                        lowest_wait = Some(earliest_wait);
                    }
                }
                GatherPoll::NewCandidate(candidate) => {
                    return AgentPoll::GatheredCandidate(AgentGatheredCandidate {
                        stream_id,
                        gathered: candidate,
                    })
                }
                GatherPoll::Complete(component_id) => {
                    return AgentPoll::GatheringComplete(AgentGatheringComplete {
                        stream_id,
                        component_id,
                    })
                }
                GatherPoll::Finished => (),
            }
        }

        loop {
            match self.checklistset.poll(now) {
                CheckListSetPollRet::Closed => return AgentPoll::Closed,
                CheckListSetPollRet::Completed => continue,
                CheckListSetPollRet::WaitUntil(earliest_wait) => {
                    if let Some(check_wait) = lowest_wait {
                        if earliest_wait < check_wait {
                            lowest_wait = Some(earliest_wait);
                        }
                    } else {
                        lowest_wait = Some(earliest_wait);
                    }
                    break;
                }
                CheckListSetPollRet::AllocateSocket {
                    checklist_id,
                    component_id: cid,
                    transport,
                    local_addr: from,
                    remote_addr: to,
                } => {
                    if let Some(stream) =
                        self.streams.iter().find(|s| s.checklist_id == checklist_id)
                    {
                        return AgentPoll::AllocateSocket(AgentSocket {
                            stream_id: stream.id(),
                            component_id: cid,
                            transport,
                            from,
                            to,
                        });
                    } else {
                        warn!("did not find stream for allocate socket {from:?} -> {to:?}");
                    }
                }
                CheckListSetPollRet::RemoveSocket {
                    checklist_id,
                    component_id: cid,
                    transport,
                    local_addr: from,
                    remote_addr: to,
                } => {
                    if let Some(stream) =
                        self.streams.iter().find(|s| s.checklist_id == checklist_id)
                    {
                        return AgentPoll::RemoveSocket(AgentSocket {
                            stream_id: stream.id(),
                            component_id: cid,
                            transport,
                            from,
                            to,
                        });
                    } else {
                        warn!("did not find stream for remove socket {from:?} -> {to:?}");
                    }
                }
                CheckListSetPollRet::Event {
                    checklist_id,
                    event: ConnCheckEvent::ComponentState(cid, state),
                } => {
                    if let Some(stream) = self
                        .streams
                        .iter_mut()
                        .find(|s| s.checklist_id == checklist_id)
                    {
                        if let Some(component) = stream.mut_component_state(cid) {
                            if component.set_state(state) {
                                return AgentPoll::ComponentStateChange(
                                    AgentComponentStateChange {
                                        stream_id: stream.id(),
                                        component_id: cid,
                                        state,
                                    },
                                );
                            }
                        }
                    }
                }
                CheckListSetPollRet::Event {
                    checklist_id,
                    event: ConnCheckEvent::SelectedPair(cid, selected),
                } => {
                    if let Some(stream) =
                        self.streams.iter().find(|s| s.checklist_id == checklist_id)
                    {
                        if stream.component_state(cid).is_some() {
                            return AgentPoll::SelectedPair(AgentSelectedPair {
                                stream_id: stream.id(),
                                component_id: cid,
                                selected,
                            });
                        }
                    }
                }
            }
        }

        AgentPoll::WaitUntil(lowest_wait.unwrap_or_else(|| now + Duration::from_secs(600)))
    }

    pub fn poll_transmit(&mut self, now: Instant) -> Option<AgentTransmit> {
        for stream in self.streams.iter_mut() {
            let stream_id = stream.id();
            if let Some((_component_id, transmit)) = stream.poll_gather_transmit(now) {
                return Some(AgentTransmit {
                    stream_id,
                    transmit: transmit.into_owned(),
                });
            }
        }
        let transmit = self.checklistset.poll_transmit(now)?;
        if let Some(stream) = self
            .streams
            .iter()
            .find(|s| s.checklist_id == transmit.checklist_id)
        {
            Some(AgentTransmit {
                stream_id: stream.id(),
                transmit: transmit.transmit,
            })
        } else {
            warn!(
                "did not find stream for transmit {:?} -> {:?}",
                transmit.transmit.from, transmit.transmit.to
            );
            None
        }
    }
}

/// Indicates what the caller should do after calling [`Agent::poll`]
#[derive(Debug)]
pub enum AgentPoll {
    /// The Agent is closed.  No further progress will be made.
    Closed,
    /// Wait until the specified `Instant` has been reached (or an external event)
    WaitUntil(Instant),
    /// Connect using the specified 5-tuple.  Reply (success or failure)
    /// should be notified using [`StreamMut::allocated_socket`] with the same parameters.
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

/// Transmit the data using the specified 5-tuple.
#[derive(Debug)]
pub struct AgentTransmit {
    pub stream_id: usize,
    pub transmit: Transmit<Data<'static>>,
}

/// A socket with the specified network 5-tuple.
#[derive(Debug)]
pub struct AgentSocket {
    pub stream_id: usize,
    pub component_id: usize,
    pub transport: TransportType,
    pub from: SocketAddr,
    pub to: SocketAddr,
}

/// A new pair has been selected for a component.
#[derive(Debug)]
pub struct AgentSelectedPair {
    pub stream_id: usize,
    pub component_id: usize,
    pub selected: Box<SelectedPair>,
}

/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct AgentComponentStateChange {
    pub stream_id: usize,
    pub component_id: usize,
    pub state: ComponentConnectionState,
}

/// A [`Component`](crate::component::Component) has gathered a candidate.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheredCandidate {
    pub stream_id: usize,
    pub gathered: GatheredCandidate,
}

/// A [`Component`](crate::component::Component) has completed gathering.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheringComplete {
    pub stream_id: usize,
    pub component_id: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlling() {
        let _log = crate::tests::test_init_log();
        let agent = Agent::builder().controlling(true).build();
        assert!(agent.controlling());
        let agent = Agent::builder().controlling(false).build();
        assert!(!agent.controlling());
    }
}
