// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures::prelude::*;

use crate::agent::{AgentError, AgentInner, AgentMessage};
use crate::component::{Component, ComponentState};
use crate::conncheck::*;

use crate::candidate::Candidate;
use crate::stun::message::*;
use crate::utils::ChannelBroadcast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub ufrag: String,
    pub passwd: String,
}

impl From<Credentials> for ShortTermCredentials {
    fn from(cred: Credentials) -> Self {
        ShortTermCredentials {
            password: cred.passwd,
        }
    }
}

impl Credentials {
    pub fn new(username: String, password: String) -> Self {
        // TODO: validate contents
        Self {
            ufrag: username,
            passwd: password,
        }
    }
}

static STREAM_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct Stream {
    id: usize,
    agent: Weak<Mutex<AgentInner>>,
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    pub(crate) state: Arc<Mutex<StreamState>>,
    pub(super) checklist: Arc<ConnCheckList>,
}

#[derive(Debug)]
pub(crate) struct StreamState {
    id: usize,
    gathering: bool,
    components: Vec<Option<Arc<Component>>>,
    local_credentials: Option<Credentials>,
    remote_credentials: Option<Credentials>,
}

impl Stream {
    pub(crate) fn new(
        agent: Weak<Mutex<AgentInner>>,
        broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    ) -> Self {
        let id = STREAM_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            agent,
            broadcast,
            state: Arc::new(Mutex::new(StreamState::new(id))),
            checklist: Arc::new(ConnCheckList::new()),
        }
    }

    /// Add a `Component` to this stream.
    ///
    /// # Examples
    ///
    /// Add a `Component`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id, component::RTP);
    /// ```
    pub fn add_component(&self) -> Result<Arc<Component>, AgentError> {
        let mut state = self.state.lock().unwrap();
        let index = state
            .components
            .iter()
            .enumerate()
            .find(|c| c.1.is_none())
            .or_else(|| Some((state.components.len(), &None)))
            .unwrap()
            .0;
        info!("stream {} adding component {}", self.id, index);
        if state.components.get(index).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        while state.components.len() <= index {
            state.components.push(None);
        }
        let component = Arc::new(Component::new(index + 1, self.broadcast.clone()));
        state.components[index] = Some(component.clone());
        info!("Added component at index {}", index);
        Ok(component)
    }

    /// Remove a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, an error is returned
    ///
    /// # Examples
    ///
    /// Remove a `Component`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id, component::RTP);
    /// assert!(stream.remove_component(component::RTP).is_ok());
    /// ```
    ///
    /// Removing a `Component` that was never added will return an error
    ///
    /// ```
    /// # use librice::agent::{Agent, AgentError};
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// assert!(matches!(stream.remove_component(component::RTP), Err(AgentError::ResourceNotFound)));
    /// ```
    // Should this really be public API?
    pub fn remove_component(&self, component_id: usize) -> Result<(), AgentError> {
        let mut state = self.state.lock().unwrap();
        if component_id < 1 {
            return Err(AgentError::ResourceNotFound);
        }
        let index = component_id - 1;
        state
            .components
            .get(index)
            .ok_or(AgentError::ResourceNotFound)?
            .as_ref()
            .ok_or(AgentError::ResourceNotFound)?;
        state.components[index] = None;
        Ok(())
    }

    /// Retrieve a `Component` from this stream.  If the index doesn't exist or a component is not
    /// available at that index, an error is returned
    ///
    /// # Examples
    ///
    /// Remove a `Component`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.id, component::RTP);
    /// assert!(stream.get_component(component::RTP).is_some());
    /// ```
    ///
    /// Retrieving a `Component` that doesn't exist will return `None`
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::component;
    /// # use librice::component::Component;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// assert!(stream.get_component(component::RTP).is_none());
    /// ```
    pub fn get_component(&self, index: usize) -> Option<Arc<Component>> {
        let state = self.state.lock().unwrap();
        if index < 1 {
            return None;
        }
        state
            .components
            .get(index - 1)
            .unwrap_or(&None)
            .as_ref()
            .cloned()
    }

    /// Set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials);
    /// ```
    pub fn set_local_credentials(&self, credentials: Credentials) {
        info!(
            "stream {} setting local credentials {:?}",
            self.id, credentials
        );
        let mut state = self.state.lock().unwrap();
        state.local_credentials = Some(credentials);
    }

    /// Retreive the previouly set local ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_local_credentials(credentials.clone());
    /// assert_eq!(stream.get_local_credentials(), Some(credentials));
    /// ```
    pub fn get_local_credentials(&self) -> Option<Credentials> {
        let state = self.state.lock().unwrap();
        state.local_credentials.clone()
    }

    /// Set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use std::sync::Arc;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials);
    /// ```
    pub fn set_remote_credentials(&self, credentials: Credentials) {
        info!(
            "stream {} setting remote credentials {:?}",
            self.id, credentials
        );
        let mut state = self.state.lock().unwrap();
        state.remote_credentials = Some(credentials);
    }

    /// Retreive the previouly set remote ICE credentials for this `Stream`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let credentials = Credentials {ufrag: "1".to_owned(), passwd: "2".to_owned()};
    /// stream.set_remote_credentials(credentials.clone());
    /// assert_eq!(stream.get_remote_credentials(), Some(credentials));
    /// ```
    pub fn get_remote_credentials(&self) -> Option<Credentials> {
        let state = self.state.lock().unwrap();
        state.remote_credentials.clone()
    }

    /// Add a remote candidate for connection checks for use with this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::candidate::*;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// let addr = "127.0.0.1:9999".parse().unwrap();
    /// let candidate = Candidate::new(
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     0,
    ///     addr,
    ///     addr,
    ///     None
    /// );
    /// stream.add_remote_candidate(component.id, candidate).unwrap();
    /// ```
    pub fn add_remote_candidate(
        &self,
        component_id: usize,
        cand: Candidate,
    ) -> Result<(), AgentError> {
        info!(
            "stream {} component {} adding remote candidate {:?}",
            self.id, component_id, cand
        );
        // TODO: error if component doesn't exist
        self.checklist.add_remote_candidate(component_id, cand);
        Ok(())
    }

    /// Start gathering local candidates.  Credentials must have been set before this function can
    /// be called.
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use librice::candidate::*;
    /// # use async_std::task;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let local_credentials = Credentials {ufrag: "luser".to_owned(), passwd: "lpass".to_owned()};
    /// stream.set_local_credentials(local_credentials);
    /// let remote_credentials = Credentials {ufrag: "ruser".to_owned(), passwd: "rpass".to_owned()};
    /// stream.set_remote_credentials(remote_credentials);
    /// let component = stream.add_component().unwrap();
    /// task::block_on(async move {
    ///     stream.gather_candidates().await.unwrap();
    /// });
    /// ```
    pub async fn gather_candidates(&self) -> Result<(), AgentError> {
        let (components, local_credentials, remote_credentials) = {
            let mut state = self.state.lock().unwrap();
            if state.gathering {
                return Err(AgentError::AlreadyInProgress);
            }
            state.gathering = true;

            (
                state.components.clone(),
                state
                    .local_stun_credentials()
                    .ok_or(AgentError::ResourceNotFound)?,
                state
                    .remote_stun_credentials()
                    .ok_or(AgentError::ResourceNotFound)?,
            )
        };

        // TODO: parallelize
        for component in components.iter().cloned().filter_map(|c| c) {
            component.set_state(ComponentState::Connecting).await;
            let s = component
                .gather_stream(local_credentials.clone(), remote_credentials.clone())
                .await?;
            futures::pin_mut!(s);
            while let Some((cand, agent)) = s.next().await {
                self.checklist
                    .add_local_candidate(&component, cand.clone(), agent)
                    .await;
                self.broadcast
                    .broadcast(AgentMessage::NewLocalCandidate(component.clone(), cand))
                    .await;
            }
            debug!(
                "gathering completed for stream {} component {}",
                self.id, component.id
            );
            self.broadcast
                .broadcast(AgentMessage::GatheringCompleted(component.clone()))
                .await;
        }
        // TODO: find STUN/TURN reflexive candidates
        Ok(())
    }

    /// Retrieve previously gathered local candidates
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::stream::Credentials;
    /// # use librice::candidate::*;
    /// # use async_std::task;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let local_credentials = Credentials {ufrag: "luser".to_owned(), passwd: "lpass".to_owned()};
    /// stream.set_local_credentials(local_credentials);
    /// let remote_credentials = Credentials {ufrag: "ruser".to_owned(), passwd: "rpass".to_owned()};
    /// stream.set_remote_credentials(remote_credentials);
    /// let component = stream.add_component().unwrap();
    /// task::block_on(async move {
    ///     stream.gather_candidates().await.unwrap();
    ///     let local_candidates = stream.get_local_candidates();
    /// });
    /// ```
    pub fn get_local_candidates(&self) -> Vec<Candidate> {
        self.checklist.get_local_candidates()
    }

    /// Retrieve previously set remote candidates for connection checks from this stream
    ///
    /// # Examples
    ///
    /// ```
    /// # use librice::agent::Agent;
    /// # use librice::candidate::*;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// let addr = "127.0.0.1:9999".parse().unwrap();
    /// let candidate = Candidate::new(
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     0,
    ///     addr,
    ///     addr,
    ///     None
    /// );
    /// stream.add_remote_candidate(component.id, candidate.clone()).unwrap();
    /// let remote_cands = stream.get_remote_candidates();
    /// assert_eq!(remote_cands.len(), 1);
    /// assert_eq!(remote_cands[0], candidate);
    /// ```
    pub fn get_remote_candidates(&self) -> Vec<Candidate> {
        self.checklist.get_remote_candidates()
    }
}

impl StreamState {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            gathering: false,
            components: vec![],
            local_credentials: None,
            remote_credentials: None,
        }
    }

    pub fn local_stun_credentials(&self) -> Option<MessageIntegrityCredentials> {
        self.local_credentials
            .clone()
            .map(|credentials| MessageIntegrityCredentials::ShortTerm(credentials.into()))
    }

    pub fn remote_stun_credentials(&self) -> Option<MessageIntegrityCredentials> {
        self.remote_credentials
            .clone()
            .map(|credentials| MessageIntegrityCredentials::ShortTerm(credentials.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn gather_candidates() {
        init();
        let agent = Arc::new(Agent::default());
        let s = agent.add_stream();
        s.set_local_credentials(Credentials::new("luser".into(), "lpass".into()));
        s.set_remote_credentials(Credentials::new("ruser".into(), "rpass".into()));
        let _c = s.add_component().unwrap();
        async_std::task::block_on(async move {
            s.gather_candidates().await.unwrap();
            let local_cands = s.get_local_candidates();
            info!("gathered local candidates {:?}", local_cands);
            assert!(!local_cands.is_empty());
            assert!(matches!(
                s.gather_candidates().await,
                Err(AgentError::AlreadyInProgress)
            ));
        });
    }

    #[test]
    fn getters_setters() {
        init();
        let lcreds = Credentials::new("luser".into(), "lpass".into());
        let rcreds = Credentials::new("ruser".into(), "rpass".into());

        async_std::task::block_on(async move {
            let agent = Arc::new(Agent::default());
            let stream = agent.add_stream();
            assert!(stream.get_component(0).is_none());
            let comp = stream.add_component().unwrap();
            assert_eq!(comp.id, stream.get_component(comp.id).unwrap().id);

            stream.set_local_credentials(lcreds.clone());
            assert_eq!(stream.get_local_credentials().unwrap(), lcreds);
            stream.set_remote_credentials(rcreds.clone());
            assert_eq!(stream.get_remote_credentials().unwrap(), rcreds);
        });
    }

    #[test]
    fn send_component() {
        init();
        let lcreds = Credentials::new("luser".into(), "lpass".into());
        let rcreds = Credentials::new("ruser".into(), "rpass".into());

        async_std::task::block_on(async move {
            let lagent = Arc::new(Agent::default());
            let ls = lagent.add_stream();
            ls.set_local_credentials(lcreds.clone());
            ls.set_remote_credentials(rcreds.clone());
            let _lc = ls.add_component().unwrap();

            let ragent = Arc::new(Agent::default());
            let rs = ragent.add_stream();
            rs.set_local_credentials(rcreds.clone());
            rs.set_remote_credentials(lcreds.clone());
            let _rc = rs.add_component().unwrap();

            ls.gather_candidates().await.unwrap();
            let local_cands = ls.get_local_candidates();
            info!("gathered local candidates {:?}", local_cands);
            assert!(!local_cands.is_empty());
            rs.gather_candidates().await.unwrap();
            let remote_cands = rs.get_local_candidates();

            for cand in local_cands.into_iter() {
                rs.add_remote_candidate(1, cand).unwrap();
            }
            for cand in remote_cands.into_iter() {
                ls.add_remote_candidate(1, cand).unwrap();
            }

            lagent.start().unwrap();
            ragent.start().unwrap();

            // TODO: send data. Needs selected-pair handling

            lagent.close().await.unwrap();
            ragent.close().await.unwrap();
        });
    }
}
