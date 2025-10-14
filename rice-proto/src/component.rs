// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A [`Component`] in an ICE [`Stream`](crate::stream::Stream)

use alloc::boxed::Box;
use core::net::SocketAddr;

use stun_proto::agent::Transmit;
use stun_proto::types::message::{Message, MessageWriteVec, BINDING};
use stun_proto::types::prelude::MessageWrite;
use stun_proto::Instant;
use turn_client_proto::api::TurnClientApi;
use turn_client_proto::types::prelude::DelayedTransmitBuild;

use crate::candidate::{CandidatePair, CandidateType, TransportType};

use crate::agent::{Agent, AgentError};
use crate::conncheck::transmit_send;
pub use crate::conncheck::SelectedPair;
use crate::gathering::StunGatherer;
use crate::turn::TurnConfig;

use tracing::{debug, trace};

/// The component id for RTP streaming (and general data).
pub const RTP: usize = 1;
/// The component id for RTCP streaming (if rtcp-mux is not in use).
pub const RTCP: usize = 2;

/// A [`Component`] in an ICE [`Stream`](crate::stream::Stream)
#[derive(Debug)]
#[repr(C)]
pub struct Component<'a> {
    agent: &'a Agent,
    stream_id: usize,
    component_id: usize,
}

impl<'a> Component<'a> {
    pub(crate) fn from_stream(agent: &'a Agent, stream_id: usize, component_id: usize) -> Self {
        Self {
            agent,
            stream_id,
            component_id,
        }
    }

    /// The component identifier within a particular ICE [`Stream`](crate::stream::Stream)
    pub fn id(&self) -> usize {
        self.component_id
    }

    /// Retrieve the current state of a `Component`
    ///
    /// # Examples
    ///
    /// The initial state is `ComponentState::New`
    ///
    /// ```
    /// # use rice_proto::component::{Component, ComponentConnectionState};
    /// # use rice_proto::agent::Agent;
    /// # use rice_proto::stream::Stream;
    /// let mut agent = Agent::default();
    /// let stream_id = agent.add_stream();
    /// let mut stream = agent.mut_stream(stream_id).unwrap();
    /// let component_id = stream.add_component().unwrap();
    /// let component = stream.component(component_id).unwrap();
    /// assert_eq!(component.state(), ComponentConnectionState::New);
    /// ```
    pub fn state(&self) -> ComponentConnectionState {
        let stream = self.agent.stream_state(self.stream_id).unwrap();
        let component = stream.component_state(self.component_id).unwrap();
        component.state
    }

    /// The [`CandidatePair`] this component has selected to send/receive data with.  This will not
    /// be valid until the [`Component`] has reached [`ComponentConnectionState::Connected`]
    pub fn selected_pair(&self) -> Option<&CandidatePair> {
        let stream = self.agent.stream_state(self.stream_id).unwrap();
        let component = stream.component_state(self.component_id).unwrap();
        component
            .selected_pair
            .as_ref()
            .map(|pair| pair.candidate_pair())
    }
}

/// A mutable component in an ICE [`Stream`](crate::stream::Stream)
#[derive(Debug)]
#[repr(C)]
pub struct ComponentMut<'a> {
    agent: &'a mut Agent,
    stream_id: usize,
    component_id: usize,
}

impl<'a> core::ops::Deref for ComponentMut<'a> {
    type Target = Component<'a>;

    fn deref(&self) -> &Self::Target {
        unsafe { core::mem::transmute(self) }
    }
}

impl<'a> ComponentMut<'a> {
    pub(crate) fn from_stream(agent: &'a mut Agent, stream_id: usize, component_id: usize) -> Self {
        Self {
            agent,
            stream_id,
            component_id,
        }
    }

    /// Start gathering candidates for this component.  The parent
    /// [`Agent::poll`](crate::agent::Agent::poll) is used to progress
    /// the gathering.
    pub fn gather_candidates(
        &mut self,
        sockets: &[(TransportType, SocketAddr)],
        stun_servers: &[(TransportType, SocketAddr)],
        turn_servers: &[(SocketAddr, &TurnConfig)],
    ) -> Result<(), AgentError> {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let component = stream.mut_component_state(self.component_id).unwrap();
        component.gather_candidates(sockets, stun_servers, turn_servers)
    }

    /// Set the pair that will be used to send/receive data.  This will override the ICE
    /// negotiation chosen value.
    pub fn set_selected_pair(&mut self, selected: CandidatePair) -> Result<(), AgentError> {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let checklist_id = stream.checklist_id;
        let checklist = self
            .agent
            .checklistset
            .mut_list(checklist_id)
            .ok_or(AgentError::ResourceNotFound)?;
        let (agent_id, agent) = if let Some((agent_id, agent)) = checklist.mut_agent_for_5tuple(
            selected.local.transport_type,
            selected.local.base_address,
            selected.remote.address,
        ) {
            (agent_id, agent)
        } else {
            let agent_id = checklist
                .add_agent_for_5tuple(
                    selected.local.transport_type,
                    selected.local.base_address,
                    selected.remote.address,
                )
                .0;
            let agent = checklist.mut_agent_by_id(agent_id).unwrap();
            (agent_id, agent)
        };
        if !agent.is_validated_peer(selected.remote.address) {
            // ensure that we can receive from the provided remote address.
            let transmit = agent
                .send_request(
                    Message::builder_request(BINDING, MessageWriteVec::new()).finish(),
                    selected.remote.address,
                    Instant::ZERO,
                )
                .unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            let response = Message::builder_success(&msg, MessageWriteVec::new()).finish();
            let response = Message::from_bytes(&response).unwrap();
            agent.handle_stun(response, selected.remote.address);
        }

        // TODO: handle TURN
        let selected_pair = SelectedPair::new(selected, agent_id, None);
        self.set_selected_pair_with_agent(selected_pair);
        Ok(())
    }

    pub(crate) fn set_selected_pair_with_agent(&mut self, selected: SelectedPair) {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let component = stream.mut_component_state(self.component_id).unwrap();
        component.selected_pair = Some(selected);
    }

    /// Send data to the peer using the selected pair.  This will not succeed until the
    /// [`Component`] has reached [`ComponentConnectionState::Connected`]
    pub fn send<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        data: T,
        now: Instant,
    ) -> Result<Transmit<Box<[u8]>>, AgentError> {
        // TODO: store statistics about bytes/packets sent
        let stream = self.agent.stream_state(self.stream_id).unwrap();
        let checklist_id = stream.checklist_id;
        let component = stream.component_state(self.component_id).unwrap();
        let selected_pair = component
            .selected_pair
            .as_ref()
            .ok_or(AgentError::ResourceNotFound)?;
        let pair = selected_pair.candidate_pair();
        let local_candidate_type = pair.local.candidate_type;
        let local_transport = pair.local.transport_type;
        let local_addr = pair.local.address;
        let remote_addr = pair.remote.address;
        let stun_agent_id = selected_pair.stun_agent_id();

        let data_len = data.as_ref().len();

        let checklist = self.agent.checklistset.mut_list(checklist_id).unwrap();
        if local_candidate_type == CandidateType::Relayed {
            let turn_client = checklist
                .mut_turn_client_by_allocated_address(local_transport, local_addr)
                .ok_or(AgentError::ResourceNotFound)?
                .1;
            let transmit = turn_client
                .send_to(local_transport, remote_addr, data, now)
                .map_err(|_| AgentError::ResourceNotFound)?
                .unwrap();
            trace!(
                "sending {} bytes from {} {} through TURN server {} with allocation {local_transport} {local_addr} to {remote_addr}",
                data_len, transmit.transport, transmit.from, transmit.to,
            );
            Ok(Transmit::new(
                transmit.data.build().into_boxed_slice(),
                transmit.transport,
                transmit.from,
                transmit.to,
            ))
        } else {
            let stun_agent = checklist
                .agent_by_id(stun_agent_id)
                .ok_or(AgentError::ResourceNotFound)?;
            trace!(
                "sending {} bytes directly over {local_transport} {local_addr} -> {remote_addr}",
                data_len
            );
            let transmit = stun_agent.send_data(data, remote_addr);
            let transport = transmit.transport;
            Ok(transmit.reinterpret_data(|data| transmit_send(transport, data.as_ref())))
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum GatherProgress {
    #[default]
    New,
    InProgress,
    Completed,
}

/// The state of a component
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum ComponentConnectionState {
    /// Component is in initial state and no connectivity checks are in progress.
    New,
    /// Connectivity checks are in progress for this candidate
    Connecting,
    /// A [`CandidatePair`](crate::candidate::CandidatePair`) has been selected for this component
    Connected,
    /// No connection could be found for this Component
    Failed,
}

#[derive(Debug)]
pub(crate) struct ComponentState {
    pub(crate) id: usize,
    state: ComponentConnectionState,
    selected_pair: Option<SelectedPair>,
    pub(crate) gather_state: GatherProgress,
    pub(crate) gatherer: Option<StunGatherer>,
}

impl ComponentState {
    pub(crate) fn new(id: usize) -> Self {
        Self {
            id,
            state: ComponentConnectionState::New,
            selected_pair: None,
            gather_state: GatherProgress::New,
            gatherer: None,
        }
    }

    pub(crate) fn gather_candidates(
        &mut self,
        sockets: &[(TransportType, SocketAddr)],
        stun_servers: &[(TransportType, SocketAddr)],
        turn_servers: &[(SocketAddr, &TurnConfig)],
    ) -> Result<(), AgentError> {
        if self.gather_state != GatherProgress::New {
            return Err(AgentError::AlreadyInProgress);
        }

        self.gatherer = Some(StunGatherer::new(
            self.id,
            sockets,
            stun_servers,
            turn_servers,
        ));
        self.gather_state = GatherProgress::InProgress;

        Ok(())
    }

    #[tracing::instrument(name = "set_component_state", level = "debug", skip(self, state))]
    pub(crate) fn set_state(&mut self, state: ComponentConnectionState) -> bool {
        if self.state != state {
            debug!(old_state = ?self.state, new_state = ?state, "setting");
            self.state = state;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::candidate::Candidate;
    use alloc::vec;

    #[test]
    fn initial_state_new() {
        let _log = crate::tests::test_init_log();
        let mut agent = Agent::builder().build();
        let sid = agent.add_stream();
        let mut s = agent.mut_stream(sid).unwrap();
        let cid = s.add_component().unwrap();
        let c = s.component(cid).unwrap();
        assert_eq!(c.state(), ComponentConnectionState::New);
    }

    #[test]
    fn send_recv() {
        let _log = crate::tests::test_init_log();
        let mut agent = Agent::builder().controlling(false).build();
        let stream_id = agent.add_stream();
        let mut stream = agent.mut_stream(stream_id).unwrap();
        let send_id = stream.add_component().unwrap();
        let local_addr = "127.0.0.1:1000".parse().unwrap();
        let remote_addr = "127.0.0.1:2000".parse().unwrap();
        let now = Instant::ZERO;

        let local_cand = Candidate::builder(
            send_id,
            CandidateType::Host,
            TransportType::Udp,
            "0",
            local_addr,
        )
        .build();
        let remote_cand = Candidate::builder(
            send_id,
            CandidateType::Host,
            TransportType::Udp,
            "0",
            remote_addr,
        )
        .build();
        let candidate_pair = CandidatePair::new(local_cand, remote_cand);

        let mut send = stream.mut_component(send_id).unwrap();
        send.set_selected_pair(candidate_pair.clone()).unwrap();
        assert_eq!(send.selected_pair().unwrap(), &candidate_pair);

        let data = vec![3; 4];
        let transmit = send.send(&data, now).unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, local_addr);
        assert_eq!(transmit.to, remote_addr);
        assert_eq!(transmit.data.as_ref(), data.as_slice());

        let recved_data = vec![7; 6];
        let ret = stream.handle_incoming_data(
            send_id,
            Transmit::new(
                recved_data.clone(),
                TransportType::Udp,
                remote_addr,
                local_addr,
            ),
            now,
        );
        assert_eq!(recved_data.as_slice(), ret.data.unwrap().as_ref());
        assert!(!ret.handled);
        assert!(!ret.have_more_data);

        // Unknown remote is ignored
        let recved_data2 = vec![9; 12];
        let ret = stream.handle_incoming_data(
            send_id,
            Transmit::new(recved_data2, TransportType::Udp, local_addr, local_addr),
            now,
        );
        assert!(ret.data.is_none());
        assert!(!ret.handled);
        assert!(!ret.have_more_data);
    }
}
