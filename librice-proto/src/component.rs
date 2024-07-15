// Copyright (C) 2024 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A [`Component`] in an ICE [`Stream`](crate::stream::Stream)

use std::net::SocketAddr;

use crate::candidate::{CandidatePair, TransportType};

use crate::agent::{Agent, AgentError};
pub use crate::conncheck::SelectedPair;
use crate::gathering::StunGatherer;

pub const RTP: usize = 1;
pub const RTCP: usize = 2;

/// A [`Component`] in an ICE [`Stream`](crate::stream::Stream)
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
    /// # use librice_proto::component::{Component, ComponentConnectionState};
    /// # use librice_proto::agent::Agent;
    /// # use librice_proto::stream::Stream;
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
pub struct ComponentMut<'a> {
    agent: &'a mut Agent,
    stream_id: usize,
    component_id: usize,
}

impl<'a> ComponentMut<'a> {
    pub(crate) fn from_stream(agent: &'a mut Agent, stream_id: usize, component_id: usize) -> Self {
        Self {
            agent,
            stream_id,
            component_id,
        }
    }

    #[tracing::instrument(name = "set_component_state", level = "debug", skip(self, state))]
    pub(crate) fn set_state(&mut self, state: ComponentConnectionState) -> bool {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let component = stream.mut_component_state(self.component_id).unwrap();
        if component.state != state {
            debug!(old_state = ?component.state, new_state = ?state, "setting");
            component.state = state;
            true
        } else {
            false
        }
    }

    /// Start gathering candidates for this component.  The parent
    /// [`StreamMut::poll_gather`](crate::stream::StreamMut::poll_gather) is used to progress
    /// the gathering.
    pub fn gather_candidates(
        &mut self,
        sockets: Vec<(TransportType, SocketAddr)>,
        stun_servers: Vec<(TransportType, SocketAddr)>,
    ) -> Result<(), AgentError> {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let component = stream.mut_component_state(self.component_id).unwrap();
        component.gather_candidates(sockets, stun_servers)
    }

    pub(crate) fn set_selected_pair(&mut self, selected: SelectedPair) {
        let stream = self.agent.mut_stream_state(self.stream_id).unwrap();
        let component = stream.mut_component_state(self.component_id).unwrap();
        component.selected_pair = Some(selected);
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
        sockets: Vec<(TransportType, SocketAddr)>,
        stun_servers: Vec<(TransportType, SocketAddr)>,
    ) -> Result<(), AgentError> {
        if self.gather_state != GatherProgress::New {
            return Err(AgentError::AlreadyInProgress);
        }

        self.gatherer = Some(StunGatherer::new(self.id, sockets, stun_servers.clone()));
        self.gather_state = GatherProgress::InProgress;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;

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
}
