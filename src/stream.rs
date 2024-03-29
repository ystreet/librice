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
use tracing_futures::Instrument;

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
    gathering: bool,
    components: Vec<Option<Component>>,
    local_credentials: Option<Credentials>,
    remote_credentials: Option<Credentials>,
}

impl Stream {
    pub(crate) fn new(
        agent: Weak<Mutex<AgentInner>>,
        broadcast: Arc<ChannelBroadcast<AgentMessage>>,
        checklist: ConnCheckList,
    ) -> Self {
        let id = STREAM_COUNT.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            agent,
            broadcast,
            state: Arc::new(Mutex::new(StreamState::new())),
            checklist: Arc::new(checklist),
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
    pub fn add_component(&self) -> Result<Component, AgentError> {
        let mut state = self.state.lock().unwrap();
        let index = state
            .components
            .iter()
            .enumerate()
            .find(|c| c.1.is_none())
            .unwrap_or((state.components.len(), &None))
            .0;
        info!("stream {} adding component {}", self.id, index + 1);
        if state.components.get(index).is_some() {
            return Err(AgentError::AlreadyExists);
        }
        while state.components.len() <= index {
            state.components.push(None);
        }
        let component = Component::new(index + 1, self.broadcast.clone());
        state.components[index] = Some(component.clone());
        self.checklist.add_component(&component);
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
        let component = state
            .components
            .get(index)
            .ok_or(AgentError::ResourceNotFound)?
            .as_ref()
            .ok_or(AgentError::ResourceNotFound)?;
        self.checklist.remove_component(component);
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
    /// assert!(stream.component(component::RTP).is_some());
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
    /// assert!(stream.component(component::RTP).is_none());
    /// ```
    pub fn component(&self, index: usize) -> Option<Component> {
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
    #[tracing::instrument(
        skip(self),
        fields(
            stream_id = self.id
        )
    )]
    pub fn set_local_credentials(&self, credentials: Credentials) {
        info!("setting");
        let mut state = self.state.lock().unwrap();
        state.local_credentials = Some(credentials.clone());
        self.checklist.set_local_credentials(credentials);
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
    /// assert_eq!(stream.local_credentials(), Some(credentials));
    /// ```
    pub fn local_credentials(&self) -> Option<Credentials> {
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
    #[tracing::instrument(
        skip(self),
        fields(
            stream_id = self.id
        )
    )]
    pub fn set_remote_credentials(&self, credentials: Credentials) {
        info!("setting");
        let mut state = self.state.lock().unwrap();
        state.remote_credentials = Some(credentials.clone());
        self.checklist.set_remote_credentials(credentials);
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
    /// assert_eq!(stream.remote_credentials(), Some(credentials));
    /// ```
    pub fn remote_credentials(&self) -> Option<Credentials> {
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
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     addr
    /// )
    /// .build();
    /// stream.add_remote_candidate(component.id, candidate).unwrap();
    /// ```
    #[tracing::instrument(
        skip(self, cand),
        fields(
            stream_id = self.id
        )
    )]
    pub fn add_remote_candidate(
        &self,
        component_id: usize,
        cand: Candidate,
    ) -> Result<(), AgentError> {
        info!("adding remote candidate {:?}", cand);
        // TODO: error if component doesn't exist
        self.checklist.add_remote_candidate(cand);
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
    #[tracing::instrument(
        name = "gather_stream",
        skip(self),
        fields(
            stream_id = ?self.id
        )
    )]
    pub async fn gather_candidates(&self) -> Result<(), AgentError> {
        let stun_servers = {
            let agent = Weak::upgrade(&self.agent).ok_or(AgentError::ResourceNotFound)?;
            let inner = agent.lock().unwrap();
            inner.stun_servers.clone()
        };

        let components = {
            let mut state = self.state.lock().unwrap();
            if state.gathering {
                return Err(AgentError::AlreadyInProgress);
            }
            state.gathering = true;

            state.components.clone()
        };

        let mut gather = futures::stream::select_all(vec![]);
        for component in components.iter().filter_map(|c| c.as_ref()) {
            component.set_state(ComponentState::Connecting).await;
            let cstream = Box::pin(
                component
                    .gather_stream(stun_servers.clone())
                    .await?
                    .map(move |(cand, socket)| (cand, socket, component)),
            );

            // make a stream that notifies after completing
            let stream = futures::stream::unfold(cstream, move |cstream| {
                let span = debug_span!("gather_component", component.id);
                async move {
                    let (f, cstream) = cstream.into_future().await;
                    match f {
                        Some(v) => Some((v, cstream)),
                        None => {
                            info!("gathering completed");
                            self.checklist.local_end_of_candidates(component);
                            self.broadcast
                                .broadcast(AgentMessage::GatheringCompleted(component.clone()))
                                .await;
                            None
                        }
                    }
                }
                .instrument(span.or_current())
            });
            gather.push(Box::pin(stream));
        }

        futures::pin_mut!(gather);
        while let Some((cand, socket, component)) = gather.next().await {
            self.checklist
                .add_local_candidate(cand.clone(), socket)
                .await;
            self.broadcast
                .broadcast(AgentMessage::NewLocalCandidate(component.clone(), cand))
                .await;
        }

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
    ///     let local_candidates = stream.local_candidates();
    /// });
    /// ```
    pub fn local_candidates(&self) -> Vec<Candidate> {
        self.checklist.local_candidates()
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
    /// let candidate = Candidate::builder(
    ///     0,
    ///     CandidateType::Host,
    ///     TransportType::Udp,
    ///     "0",
    ///     addr
    /// )
    /// .build();
    /// stream.add_remote_candidate(component.id, candidate.clone()).unwrap();
    /// let remote_cands = stream.remote_candidates();
    /// assert_eq!(remote_cands.len(), 1);
    /// assert_eq!(remote_cands[0], candidate);
    /// ```
    pub fn remote_candidates(&self) -> Vec<Candidate> {
        self.checklist.remote_candidates()
    }

    /// Indicate that no more candidates are expected from the peer.  This may allow the ICE
    /// process to fully complete.
    #[tracing::instrument(
        skip(self),
        fields(
            component.id = self.id,
        )
    )]
    pub fn end_of_candidates(&self) {
        // FIXME: how to deal with ice restarts?
        let components: Vec<_> = {
            let state = self.state.lock().unwrap();
            state
                .components
                .iter()
                .filter_map(|comp| comp.clone())
                .collect()
        };
        for comp in components {
            self.checklist.remote_end_of_candidates(&comp);
        }
    }
}

impl StreamState {
    fn new() -> Self {
        Self {
            gathering: false,
            components: vec![],
            local_credentials: None,
            remote_credentials: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;

    fn init() {
        crate::tests::test_init_log();
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
            let local_cands = s.local_candidates();
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
            assert!(stream.component(0).is_none());
            let comp = stream.add_component().unwrap();
            assert_eq!(comp.id, stream.component(comp.id).unwrap().id);

            stream.set_local_credentials(lcreds.clone());
            assert_eq!(stream.local_credentials().unwrap(), lcreds);
            stream.set_remote_credentials(rcreds.clone());
            assert_eq!(stream.remote_credentials().unwrap(), rcreds);
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
            let local_cands = ls.local_candidates();
            info!("gathered local candidates {:?}", local_cands);
            assert!(!local_cands.is_empty());
            rs.gather_candidates().await.unwrap();
            let remote_cands = rs.local_candidates();

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
