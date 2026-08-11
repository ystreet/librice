// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICE Agent implementation as specified in RFC 8445

use alloc::boxed::Box;
use alloc::vec::Vec;

use core::error::Error;
use core::fmt::Display;
use core::net::SocketAddr;
use core::sync::atomic::AtomicU64;
use core::time::Duration;

use stun_proto::Instant;
use stun_proto::types::data::Data;

use crate::candidate::{ParseCandidateError, TransportType};
use crate::component::ComponentConnectionState;
use crate::conncheck::{
    CheckListSetPollRet, ConnCheckEvent, ConnCheckListSet, RequestRto, SelectedPair,
};
use crate::consent::{self, ConsentFreshness, ConsentFreshnessPoll};
use crate::gathering::{GatherPoll, GatheredCandidate};
use crate::rand::rand_u64;
use crate::stream::{RestartStreamConfig, Stream, StreamMut, StreamState};
use crate::turn::TurnConfig;
use stun_proto::agent::{StunError, Transmit};
use stun_proto::types::message::StunParseError;

use tracing::{info, warn};

pub use crate::restart::{RestartConfig, RoleChange};

/// Errors that can be returned as a result of agent operations.
#[derive(Debug)]
pub enum AgentError {
    /// Failed for an unspecified reason.
    Failed,
    /// The specified resource already exists and cannot be added.
    AlreadyExists,
    /// The operation is already in progress.
    AlreadyInProgress,
    /// The operation is not in progress.
    NotInProgress,
    /// Could not find the specified resource.
    ResourceNotFound,
    /// The data provided was not in the correct format.
    Malformed,
    /// This data is not handled by this implementation.
    WrongImplementation,
    /// The connection to the remote has been closed.
    ConnectionClosed,
    /// Parsing the STUN message failed.
    StunParse,
    /// Writing the STUN message failed.
    StunWrite,
    /// Parsing the candidate failed.
    CandidateParse(ParseCandidateError),
    /// Data was received that does not match the protocol specifications.
    ProtocolViolation,
}

impl Error for AgentError {}

impl Display for AgentError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self:?}")
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
            StunError::ProtocolViolation => AgentError::ProtocolViolation,
            StunError::ParseError(_) => AgentError::StunParse,
            StunError::WriteError(_) => AgentError::StunWrite,
            StunError::AlreadyInProgress => AgentError::AlreadyInProgress,
            _ => AgentError::Failed,
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
    id: u64,
    pub(crate) checklistset: ConnCheckListSet,
    pub(crate) stun_servers: Vec<(TransportType, SocketAddr)>,
    pub(crate) turn_servers: Vec<TurnConfig>,
    streams: Vec<StreamState>,
    pub(crate) rto: Option<RequestRto>,
    pub(crate) consent_freshness: Option<ConsentFreshness>,
    pub(crate) consent_freshness_cfg: consent::Config,
}

/// A builder for an [`Agent`]
#[derive(Debug)]
pub struct AgentBuilder {
    trickle_ice: bool,
    controlling: bool,
    timing_advance: Duration,
    rto: Option<RequestRto>,
    ice_lite: bool,
    consent_freshness: bool,
    consent_freshness_config: consent::Config,
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self {
            trickle_ice: false,
            controlling: false,
            timing_advance: crate::conncheck::DEFAULT_MINIMUM_SET_TICK,
            rto: None,
            ice_lite: false,
            consent_freshness: true,
            consent_freshness_config: consent::Config::default(),
        }
    }
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

    /// Set the minimum amount of time between subsequent STUN requests sent.
    ///
    /// This is known as the Ta value in the ICE specification.
    ///
    /// The default value is 50ms.
    pub fn timing_advance(mut self, ta: Duration) -> Self {
        self.timing_advance = ta;
        self
    }

    /// Configure the default timeouts and retransmissions for each STUN request.
    ///
    /// - `initial` - the initial time between consecutive transmissions. If 0, or 1, then only a
    ///   single request will be performed.
    /// - `max` - the maximum amount of time between consecutive retransmits.
    /// - `retransmits` - the total number of transmissions of the request.
    /// - `final_retransmit_timeout` - the amount of time after the final transmission to wait
    ///   for a response before considering the request as having timed out.
    ///
    /// As specified in RFC 8489, `initial_rto` should be >= 500ms (unless specific information is
    /// available on the RTT, `max` is `Duration::MAX`, `retransmits` has a default value of 7,
    /// and `last_retransmit_timeout` should be `16 * initial_rto`.
    ///
    /// STUN transactions over TCP will only send a single request and have a timeout of the sum of
    /// the timeouts of a UDP transaction.
    pub fn set_request_retransmits(
        mut self,
        initial: Duration,
        max: Duration,
        retransmits: u32,
        final_retransmit_timeout: Duration,
    ) -> Self {
        self.rto = Some(RequestRto::from_parts(
            initial,
            max,
            retransmits,
            final_retransmit_timeout,
        ));
        self
    }

    /// Configure the agent for ICE-lite usage.
    ///
    /// ICE-lite has the following limitations:
    ///  - A single host candidate is gathered per network interface and component id
    ///  - Connectivity checks are never initiated from the ICE-lite peer.
    ///  - Always in the controlled mode.
    pub fn ice_lite(mut self, ice_lite: bool) -> Self {
        self.ice_lite = ice_lite;
        self
    }

    /// Whether consent freshness is enabled for this agent.
    ///
    /// Consent freshness is enabled by default but can be disabled using
    /// this method. ICE-lite agents always skip consent freshness regardless
    /// of this setting.
    pub fn consent_freshness(mut self, consent_freshness: bool) -> Self {
        self.consent_freshness = consent_freshness;
        self
    }

    /// Configure the consent freshness interval and timeout.
    ///
    /// - `interval`: the period between Binding Requests (default 5 s).
    /// - `timeout`: the period without traffic before consent is considered
    ///   revoked (default 30 s).
    pub fn consent_freshness_config(mut self, config: consent::Config) -> Self {
        self.consent_freshness_config = config;
        self
    }

    /// Construct a new [`Agent`]
    pub fn build(self) -> Agent {
        turn_client_proto::types::debug_init();
        rice_stun_types::debug_init();

        let id = AGENT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        let tie_breaker = rand_u64();
        let controlling = self.controlling && !self.ice_lite;
        let mut checklistset = ConnCheckListSet::builder(tie_breaker, controlling)
            .trickle_ice(self.trickle_ice)
            .timing_advance(self.timing_advance)
            .ice_lite(self.ice_lite)
            .build();
        if let Some(rto) = self.rto.clone() {
            checklistset.set_request_retransmits(rto);
        }

        let consent_freshness = self
            .consent_freshness
            .then(|| ConsentFreshness::new(self.consent_freshness_config.clone()));

        Agent {
            id,
            checklistset,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            streams: Vec::new(),
            rto: self.rto,
            consent_freshness,
            consent_freshness_cfg: self.consent_freshness_config,
        }
    }
}

static AGENT_COUNT: AtomicU64 = AtomicU64::new(0);

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
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The minimum amount of time between subsequent STUN requests sent.
    ///
    /// This is known as the Ta value in the ICE specification.
    ///
    /// The default value is 50ms.
    pub fn timing_advance(&self) -> Duration {
        self.checklistset.timing_advance()
    }

    /// Set the minimum amount of time between subsequent STUN requests sent.
    ///
    /// This is known as the Ta value in the ICE specification.
    ///
    /// The default value is 50ms.
    pub fn set_timing_advance(&mut self, ta: Duration) {
        self.checklistset.set_timing_advance(ta)
    }

    /// Retrieve whether the agent is configured for ICE-lite usage.
    ///
    /// ICE-lite has the following limitations:
    ///  - A single host candidate is gathered per network interface and component id
    ///  - Connectivity checks are never initiated from the ICE-lite peer.
    pub fn ice_lite(&self) -> bool {
        self.checklistset.ice_lite()
    }

    /// Configure the default timeouts and retransmissions for each STUN request.
    ///
    /// - `initial` - the initial time between consecutive transmissions. If 0, or 1, then only a
    ///   single request will be performed.
    /// - `max` - the maximum amount of time between consecutive retransmits.
    /// - `retransmits` - the total number of transmissions of the request.
    /// - `final_retransmit_timeout` - the amount of time after the final transmission to wait
    ///   for a response before considering the request as having timed out.
    ///
    /// As specified in RFC 8489, `initial_rto` should be >= 500ms (unless specific information is
    /// available on the RTT, `max` is `Duration::MAX`, `retransmits` has a default value of 7,
    /// and `last_retransmit_timeout` should be `16 * initial_rto`.
    ///
    /// STUN transactions over TCP will only send a single request and have a timeout of the sum of
    /// the timeouts of a UDP transaction.
    pub fn set_request_retransmits(
        &mut self,
        initial: Duration,
        max: Duration,
        retransmits: u32,
        final_retransmit_timeout: Duration,
    ) {
        let rto = RequestRto::from_parts(initial, max, retransmits, final_retransmit_timeout);
        for stream in self.streams.iter_mut() {
            stream.set_request_retransmits(rto.clone());
        }
        self.checklistset.set_request_retransmits(rto);
    }

    /// Perform an ICE-restart.
    pub fn restart(&mut self, config: &RestartConfig, now: Instant) {
        match config.local_role_change {
            RoleChange::None => (),
            RoleChange::Lite => self.checklistset.set_ice_lite(true),
            RoleChange::Full => self.checklistset.set_ice_lite(false),
        }

        let stream_config = RestartStreamConfig::new()
            .set_remove_local_candidates(config.remove_local_candidates());
        for stream in self.streams.iter_mut() {
            if config.local_remove_candidates {
                stream.restart_gather();
            }
            let checklist_id = stream.checklist_id;
            Self::restart_stream(&mut self.checklistset, checklist_id, &stream_config, now);
        }
    }

    pub(crate) fn restart_stream(
        checklistset: &mut ConnCheckListSet,
        checklist_id: usize,
        config: &RestartStreamConfig,
        now: Instant,
    ) {
        let checklist = checklistset.mut_list(checklist_id).unwrap();
        let checks = checklist.restart(config);
        checklistset.remove_checks(checklist_id, checks, now);
    }

    /// Update the controlling state of the agent based on external factors.
    pub fn set_controlling(&mut self, controlling: bool) {
        self.checklistset.set_controlling(controlling);
    }

    /// Configure the [`Agent`] to be in ICE-lite mode.
    ///
    /// ICE-lite has the following limitations:
    ///  - A single host candidate is gathered per network interface and component id
    ///  - Connectivity checks are never initiated from the ICE-lite peer.
    ///  - Always in the controlled mode.
    pub fn set_ice_lite(&mut self, ice_lite: bool) {
        self.checklistset.set_ice_lite(ice_lite);
    }

    /// Add a new `Stream` to this agent
    ///
    /// # Examples
    ///
    /// Add a `Stream`
    ///
    /// ```
    /// # use rice_proto::agent::Agent;
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

        if let Some(cf) = &mut self.consent_freshness {
            cf.close();
        }
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
    pub fn stun_servers(&self) -> &[(TransportType, SocketAddr)] {
        &self.stun_servers
    }

    /// Add a TURN server by address, transport, and credentials to use for gathering potential
    /// candidates.
    #[tracing::instrument(
        name = "ice_add_turn_server",
        skip(self)
        fields(ice.id = self.id)
    )]
    pub fn add_turn_server(&mut self, config: TurnConfig) {
        info!("Adding turn server");
        self.turn_servers.push(config);
        // TODO: propagate towards the gatherer as required
    }

    /// The current list of TURN servers used by this [`Agent`]
    pub fn turn_servers(&self) -> &[TurnConfig] {
        &self.turn_servers
    }

    /// Get a [`Stream`] by id.
    ///
    /// If the stream does not exist, then `None` will be returned.
    pub fn stream(&self, id: usize) -> Option<crate::stream::Stream<'_>> {
        if let Some(stream) = self.streams.get(id) {
            let checklist_id = stream.checklist_id;
            Some(Stream::from_agent(self, id, checklist_id))
        } else {
            None
        }
    }

    pub(crate) fn stream_state(&self, id: usize) -> Option<&crate::stream::StreamState> {
        self.streams.get(id)
    }

    /// Get a [`StreamMut`] by id.  If the stream does not exist, then `None` will be returned.
    pub fn mut_stream(&mut self, id: usize) -> Option<StreamMut<'_>> {
        if let Some(stream) = self.streams.get_mut(id) {
            let checklist_id = stream.checklist_id;
            Some(StreamMut::from_agent(self, id, checklist_id))
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
                    });
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
                    });
                }
                GatherPoll::Complete(component_id) => {
                    return AgentPoll::GatheringComplete(AgentGatheringComplete {
                        stream_id,
                        component_id,
                    });
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
                            if !self.checklistset.ice_lite() {
                                if let Some(checklist) = self.checklistset.list(checklist_id) {
                                    if let Some(cf) = &mut self.consent_freshness {
                                        if let Some(remote_credentials) =
                                            checklist.remote_credentials()
                                        {
                                            let pair = selected.candidate_pair();

                                            cf.start(
                                                stream.id(),
                                                cid,
                                                pair.local.clone(),
                                                pair.remote.address,
                                                checklist.local_credentials().clone(),
                                                remote_credentials.clone(),
                                                self.checklistset.controlling(),
                                                self.checklistset.tie_breaker(),
                                                now,
                                            );
                                        }
                                    }
                                }
                            }

                            return AgentPoll::SelectedPair(AgentSelectedPair {
                                stream_id: stream.id(),
                                component_id: cid,
                                selected,
                            });
                        }
                    }
                }
                CheckListSetPollRet::Event {
                    checklist_id,
                    event: ConnCheckEvent::ConsentResponseReceived(cid, revoked),
                } => {
                    if let Some(stream) =
                        self.streams.iter().find(|s| s.checklist_id == checklist_id)
                    {
                        if let Some(cf) = &mut self.consent_freshness {
                            cf.on_response(cid, now);

                            if revoked {
                                cf.on_revoked(stream.id(), cid);
                            }
                        }
                    }
                }
            }
        }

        // Poll consent freshness for timeout or expiry events.
        if let Some(cf) = &mut self.consent_freshness {
            loop {
                match cf.poll(now) {
                    ConsentFreshnessPoll::SendCheck {
                        stream_id,
                        component_id,
                    } => {
                        // Build the Binding Request and route it through
                        // the conncheck's StunAgent for shared TID pool,
                        // authentication, and RTT statistics.
                        if let Some(check) = cf.build_consent_check(stream_id, component_id, now) {
                            let checklist_id = self
                                .streams
                                .iter()
                                .find(|s| s.id() == stream_id)
                                .map(|s| s.checklist_id);

                            if let Some(cl_id) = checklist_id {
                                self.checklistset.add_consent_check(
                                    check.local.clone(),
                                    cl_id,
                                    component_id,
                                    check.msg,
                                    check.to,
                                );

                                // Make poll_transmit pick up the newly
                                // queued consent request.
                                lowest_wait = Some(now);
                            }
                        }
                        continue;
                    }
                    ConsentFreshnessPoll::ConsentExpired {
                        stream_id,
                        component_id,
                    }
                    | ConsentFreshnessPoll::ConsentRevoked {
                        stream_id,
                        component_id,
                    } => {
                        cf.stop(stream_id, component_id);

                        if let Some(component) = self
                            .streams
                            .iter_mut()
                            .find(|s| s.id() == stream_id)
                            .and_then(|stream| stream.mut_component_state(component_id))
                        {
                            if component.set_state(ComponentConnectionState::Failed) {
                                return AgentPoll::ComponentStateChange(
                                    AgentComponentStateChange {
                                        stream_id,
                                        component_id,
                                        state: ComponentConnectionState::Failed,
                                    },
                                );
                            }
                        }
                    }
                    ConsentFreshnessPoll::WaitUntil(wait) => {
                        if let Some(check_wait) = lowest_wait {
                            if wait < check_wait {
                                lowest_wait = Some(wait);
                            }
                        } else {
                            lowest_wait = Some(wait);
                        }
                        break;
                    }
                }
            }
        }

        AgentPoll::WaitUntil(lowest_wait.unwrap_or_else(|| now + Duration::from_secs(600)))
    }

    /// Poll for a transmission to be performed.
    ///
    /// If not-None, then the provided data must be sent to the peer from the provided socket
    /// address.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<AgentTransmit> {
        for stream in self.streams.iter_mut() {
            let stream_id = stream.id();
            if let Some((_component_id, transmit)) = stream.poll_gather_transmit(now) {
                return Some(AgentTransmit::from_data(stream_id, transmit));
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

    /// If consent freshness is enabled for this [`Agent`]
    pub fn is_consent_freshness_enabled(&self) -> bool {
        self.consent_freshness.is_some()
    }

    /// Enable consent freshness for this [`Agent`]
    pub fn enable_consent_freshness(&mut self) {
        if self.consent_freshness.is_none() {
            self.consent_freshness =
                Some(ConsentFreshness::new(self.consent_freshness_cfg.clone()));
        }
    }

    /// Disable consent freshness for this [`Agent`]
    pub fn disable_consent_freshness(&mut self) {
        self.consent_freshness = None;
    }

    /// Retrieve consent freshness configuration for this [`Agent`]
    pub fn consent_freshness_config(&self) -> Option<consent::Config> {
        self.consent_freshness
            .as_ref()
            .map(|cf| cf.config().clone())
            .or_else(|| Some(self.consent_freshness_cfg.clone()))
    }

    /// Set consent freshness configuration for this [`Agent`]
    pub fn set_consent_freshness_config(&mut self, config: consent::Config) {
        self.consent_freshness_cfg = config.clone();
        if let Some(cf) = &mut self.consent_freshness {
            cf.set_config(config);
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
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The network 5-tuple and data to send.
    pub transmit: Transmit<Box<[u8]>>,
}

impl AgentTransmit {
    fn from_data(stream_id: usize, transmit: Transmit<Data<'_>>) -> Self {
        Self {
            stream_id,
            transmit: transmit.reinterpret_data(|data| {
                let Data::Owned(owned) = data.into_owned() else {
                    unreachable!();
                };
                owned.take()
            }),
        }
    }
}

/// A socket with the specified network 5-tuple.
#[derive(Debug)]
pub struct AgentSocket {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The ICE component id within the stream.
    pub component_id: usize,
    /// The transport for the socket.
    pub transport: TransportType,
    /// The source address of the socket.
    pub from: SocketAddr,
    /// The destination address of the socket.
    pub to: SocketAddr,
}

/// A new pair has been selected for a component.
#[derive(Debug)]
pub struct AgentSelectedPair {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The ICE component id within the stream.
    pub component_id: usize,
    /// The selceted pair.
    pub selected: Box<SelectedPair>,
}

/// A [`Component`](crate::component::Component) has changed state.
#[derive(Debug)]
#[repr(C)]
pub struct AgentComponentStateChange {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The ICE component id within the stream.
    pub component_id: usize,
    /// The new state of the component.
    pub state: ComponentConnectionState,
}

/// A [`Component`](crate::component::Component) has gathered a candidate.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheredCandidate {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The gathered candidate.
    pub gathered: GatheredCandidate,
}

/// A [`Component`](crate::component::Component) has completed gathering.
#[derive(Debug)]
#[repr(C)]
pub struct AgentGatheringComplete {
    /// The ICE stream id within the agent.
    pub stream_id: usize,
    /// The ICE component id within the stream.
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

    #[test]
    fn timing_advance() {
        let _log = crate::tests::test_init_log();
        let ta = Duration::from_secs(1);
        let default_ta = Duration::from_millis(50);
        let mut agent = Agent::default();
        assert_eq!(agent.timing_advance(), default_ta);
        agent.set_timing_advance(ta);
        assert_eq!(agent.timing_advance(), ta);
        let agent = Agent::builder().timing_advance(ta).build();
        assert_eq!(agent.timing_advance(), ta);
    }

    #[test]
    fn consent_expiry_sets_component_failed() {
        use crate::candidate::{Candidate, CandidateType, TransportType};
        use crate::conncheck::Credentials;

        let _log = crate::tests::test_init_log();

        let timeout = Duration::from_secs(5);
        let config = consent::Config {
            interval: Duration::from_secs(5),
            timeout,
        };
        let mut agent = Agent::builder()
            .controlling(true)
            .consent_freshness_config(config)
            .build();

        let stream_id = agent.add_stream();
        let _ = agent.streams[stream_id].add_component();
        let component_id = 1;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            component_id,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        let local_creds = Credentials {
            ufrag: "lufrag".into(),
            passwd: "lpwd".into(),
        };
        let remote_creds = Credentials {
            ufrag: "rufrag".into(),
            passwd: "rpwd".into(),
        };

        let now = Instant::ZERO;
        agent.consent_freshness.as_mut().unwrap().start(
            stream_id,
            component_id,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds,
            remote_creds,
            true,
            42,
            now,
        );

        match agent.poll(now + Duration::from_secs(1)) {
            AgentPoll::WaitUntil(_) => {}
            other => panic!("expected WaitUntil before expiry, got {other:?}"),
        }

        let after_expiry = now + timeout + Duration::from_secs(1);
        match agent.poll(after_expiry) {
            AgentPoll::ComponentStateChange(ev) => {
                assert_eq!(ev.stream_id, stream_id);
                assert_eq!(ev.component_id, component_id);
                assert_eq!(ev.state, ComponentConnectionState::Failed);
            }
            other => panic!("expected ComponentStateChange(Failed) after expiry, got {other:?}"),
        }

        let component = agent.streams[stream_id]
            .component_state(component_id)
            .unwrap();
        assert_eq!(component.state(), ComponentConnectionState::Failed);
    }

    #[test]
    fn consent_revocation_sets_component_failed() {
        use crate::candidate::{Candidate, CandidateType, TransportType};
        use crate::conncheck::Credentials;

        let _log = crate::tests::test_init_log();

        let timeout = Duration::from_secs(30);
        let config = consent::Config {
            interval: Duration::from_secs(5),
            timeout,
        };
        let mut agent = Agent::builder()
            .controlling(true)
            .consent_freshness_config(config)
            .build();

        let stream_id = agent.add_stream();
        let _ = agent.streams[stream_id].add_component();
        let component_id = 1;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            component_id,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        let local_creds = Credentials {
            ufrag: "lufrag".into(),
            passwd: "lpwd".into(),
        };
        let remote_creds = Credentials {
            ufrag: "rufrag".into(),
            passwd: "rpwd".into(),
        };

        let now = Instant::ZERO;
        agent.consent_freshness.as_mut().unwrap().start(
            stream_id,
            component_id,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds,
            remote_creds,
            true,
            42,
            now,
        );

        agent
            .consent_freshness
            .as_mut()
            .unwrap()
            .on_revoked(stream_id, component_id);

        match agent.poll(now) {
            AgentPoll::ComponentStateChange(ev) => {
                assert_eq!(ev.stream_id, stream_id);
                assert_eq!(ev.component_id, component_id);
                assert_eq!(ev.state, ComponentConnectionState::Failed);
            }
            other => panic!("expected ComponentStateChange(Failed) on revocation, got {other:?}"),
        }

        let component = agent.streams[stream_id]
            .component_state(component_id)
            .unwrap();
        assert_eq!(component.state(), ComponentConnectionState::Failed);
    }

    #[test]
    fn revoke_consent_sets_local_flag() {
        use crate::candidate::{Candidate, CandidateType, TransportType};
        use crate::conncheck::Credentials;

        let _log = crate::tests::test_init_log();

        let config = consent::Config {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(30),
        };
        let mut agent = Agent::builder()
            .controlling(true)
            .consent_freshness_config(config.clone())
            .build();

        let stream_id = agent.add_stream();
        let _ = agent.streams[stream_id].add_component();
        let component_id = 1;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            component_id,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        let local_creds = Credentials {
            ufrag: "lufrag".into(),
            passwd: "lpwd".into(),
        };
        let remote_creds = Credentials {
            ufrag: "rufrag".into(),
            passwd: "rpwd".into(),
        };

        let now = Instant::ZERO;
        agent.consent_freshness.as_mut().unwrap().start(
            stream_id,
            component_id,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds,
            remote_creds,
            true,
            42,
            now,
        );

        let checklist_id = agent.streams[stream_id].checklist_id;
        agent
            .mut_stream(stream_id)
            .unwrap()
            .mut_component(component_id)
            .unwrap()
            .revoke_consent();

        assert!(
            agent
                .checklistset
                .is_local_consent_revoked(checklist_id, component_id)
        );

        // Verify consent freshness (remote consent tracking) is unaffected.
        // After starting consent tracking, poll() should still produce a
        // SendCheck.
        match agent.poll(now + Duration::from_secs(1)) {
            AgentPoll::WaitUntil(_) | AgentPoll::ComponentStateChange(_) => {}
            other => panic!(
                "expected WaitUntil or ComponentStateChange after revoke_consent, got {other:?}"
            ),
        }

        // Verify that consent expiry still works (remote consent tracking unaffected).
        let t_expire = now + config.timeout + Duration::from_secs(1);
        match agent.poll(t_expire) {
            AgentPoll::ComponentStateChange(ev) => {
                assert_eq!(ev.state, ComponentConnectionState::Failed);
            }
            other => {
                panic!("expected ComponentStateChange(Failed) after expiry, got {other:?}")
            }
        }
    }

    #[test]
    fn consent_freshness_enable_disable() {
        let _log = crate::tests::test_init_log();

        let mut agent = Agent::builder().consent_freshness(false).build();
        assert!(!agent.is_consent_freshness_enabled());

        agent.enable_consent_freshness();
        assert!(agent.is_consent_freshness_enabled());

        agent.disable_consent_freshness();
        assert!(!agent.is_consent_freshness_enabled());
    }

    #[test]
    fn consent_freshness_config_get_set() {
        let _log = crate::tests::test_init_log();

        let mut agent = Agent::builder().build();

        let cfg = agent.consent_freshness_config().unwrap();
        assert_eq!(cfg.interval, consent::Config::default().interval);
        assert_eq!(cfg.timeout, consent::Config::default().timeout);

        let new_cfg = consent::Config {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(60),
        };
        agent.set_consent_freshness_config(new_cfg.clone());

        let read_cfg = agent.consent_freshness_config().unwrap();
        assert_eq!(read_cfg.interval, Duration::from_secs(10));
        assert_eq!(read_cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn consent_freshness_close() {
        let _log = crate::tests::test_init_log();

        let mut agent = Agent::builder().build();
        assert!(agent.is_consent_freshness_enabled());

        let now = Instant::ZERO;
        agent.close(now);
    }
}
