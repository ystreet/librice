// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A [`Component`] in an ICE [`Stream`](crate::stream::Stream)

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use std::task::{Poll, Waker};

use librice_proto::candidate::CandidatePair;

pub use librice_proto::component::ComponentConnectionState;

use crate::agent::AgentError;
use crate::socket::StunChannel;

use futures::prelude::*;

pub const RTP: usize = 1;
pub const RTCP: usize = 2;

/// A [`Component`] within an ICE [`Stream`](crate::stream::Stream`)
#[derive(Debug, Clone)]
pub struct Component {
    weak_agent: Weak<Mutex<librice_proto::agent::Agent>>,
    stream_id: usize,
    pub(crate) id: usize,
    pub(crate) inner: Arc<Mutex<ComponentInner>>,
}

impl Component {
    pub(crate) fn new(
        weak_agent: Weak<Mutex<librice_proto::agent::Agent>>,
        stream_id: usize,
        id: usize,
    ) -> Self {
        Self {
            weak_agent,
            stream_id,
            id,
            inner: Arc::new(Mutex::new(ComponentInner::new(id))),
        }
    }

    /// The component identifier within a particular ICE [`Stream`]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Retrieve the current state of a `Component`
    ///
    /// # Examples
    ///
    /// The initial state is `ComponentState::New`
    ///
    /// ```
    /// # use librice::component::{Component, ComponentConnectionState};
    /// # use librice::agent::Agent;
    /// # use librice::stream::Stream;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.state(), ComponentConnectionState::New);
    /// ```
    pub fn state(&self) -> ComponentConnectionState {
        let Some(agent) = self.weak_agent.upgrade() else {
            return ComponentConnectionState::Failed;
        };
        let agent = agent.lock().unwrap();
        if let Some(stream) = agent.stream(self.stream_id) {
            stream
                .component(self.id)
                .map(|component| component.state())
                .unwrap_or(ComponentConnectionState::Failed)
        } else {
            ComponentConnectionState::Failed
        }
    }

    /// Send data to the peer using the established communication channel.  This will not succeed
    /// until the component is in the [`Connected`](ComponentConnectionState::Connected) state.
    pub async fn send(&self, data: &[u8]) -> Result<(), AgentError> {
        let (local_agent, channel, to) = {
            let inner = self.inner.lock().unwrap();
            let selected_pair = inner.selected_pair.as_ref().ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No selected pair",
            ))?;
            let local_agent = selected_pair.proto.stun_agent().clone();
            let to = selected_pair.proto.candidate_pair().remote.address;
            trace!("sending {} bytes to {}", data.len(), to);
            (local_agent, selected_pair.socket.clone(), to)
        };
        let transmit = local_agent.send_data(data, to);

        channel.send_to(&transmit.data, transmit.to).await?;

        Ok(())
    }

    /// A stream that provides the data that has been sent from the peer to this component.
    pub fn recv(&self) -> impl Stream<Item = Vec<u8>> {
        ComponentRecv {
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn set_selected_pair(&self, selected: SelectedPair) {
        self.inner.lock().unwrap().set_selected_pair(selected)
    }

    /// The pair that has been selected for communication.  Will not provide a useful value until
    /// ICE negotiation has completed successfully.
    pub fn selected_pair(&self) -> Option<CandidatePair> {
        self.inner
            .lock()
            .unwrap()
            .selected_pair
            .clone()
            .map(|selected| selected.proto.candidate_pair().clone())
    }
}

#[derive(Debug)]
pub(crate) struct ComponentInner {
    id: usize,
    selected_pair: Option<SelectedPair>,
    received_data: VecDeque<Vec<u8>>,
    recv_waker: Option<Waker>,
}

impl ComponentInner {
    fn new(id: usize) -> Self {
        Self {
            id,
            selected_pair: None,
            received_data: VecDeque::default(),
            recv_waker: None,
        }
    }

    #[tracing::instrument(
        skip(self),
        fields(
            component_id = self.id
        )
    )]
    fn set_selected_pair(&mut self, selected: SelectedPair) {
        debug!("setting");
        self.selected_pair = Some(selected);
    }

    #[tracing::instrument(
        name = "component_incoming_data"
        skip(self, data)
        fields(
            data.len = data.len()
        )
    )]
    pub(crate) fn handle_incoming_data(&mut self, data: Vec<u8>) {
        self.received_data.push_back(data);
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }
}

#[doc(hidden)]
pub struct ComponentRecv {
    inner: Arc<Mutex<ComponentInner>>,
}

impl futures::Stream for ComponentRecv {
    type Item = Vec<u8>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(data) = inner.received_data.pop_front() {
            return Poll::Ready(Some(data));
        }
        inner.recv_waker = Some(cx.waker().clone());
        std::task::Poll::Pending
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedPair {
    proto: librice_proto::component::SelectedPair,
    socket: StunChannel,
}

impl SelectedPair {
    pub(crate) fn new(pair: librice_proto::component::SelectedPair, socket: StunChannel) -> Self {
        Self {
            proto: pair,
            socket,
        }
    }
}

#[cfg(test)]
mod tests {
    use async_std::net::UdpSocket;
    use librice_proto::candidate::{Candidate, CandidateType};
    use stun_proto::agent::StunAgent;
    use stun_proto::types::TransportType;

    use super::*;
    use crate::{agent::Agent, socket::UdpSocketChannel};

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn initial_state_new() {
        init();
        let agent = Agent::builder().build();
        let s = agent.add_stream();
        let c = s.add_component().unwrap();
        assert_eq!(c.state(), ComponentConnectionState::New);
    }

    #[test]
    fn send_recv() {
        init();
        async_std::task::block_on(async move {
            let agent = Agent::builder().controlling(false).build();
            let s = agent.add_stream();
            let send = s.add_component().unwrap();
            let local_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local_addr = local_socket.local_addr().unwrap();
            let remote_addr = remote_socket.local_addr().unwrap();
            let local_channel = StunChannel::Udp(UdpSocketChannel::new(local_socket));

            let local_agent = StunAgent::builder(TransportType::Udp, local_addr).build();

            let local_cand =
                Candidate::builder(0, CandidateType::Host, TransportType::Udp, "0", local_addr)
                    .build();
            let remote_cand =
                Candidate::builder(0, CandidateType::Host, TransportType::Udp, "0", remote_addr)
                    .build();
            let candidate_pair = CandidatePair::new(local_cand, remote_cand);
            let selected_pair = SelectedPair {
                proto: librice_proto::component::SelectedPair::new(candidate_pair, local_agent),
                socket: local_channel,
            };

            send.set_selected_pair(selected_pair.clone());
            assert_eq!(
                selected_pair.proto.candidate_pair(),
                &send.selected_pair().unwrap()
            );

            let data = vec![3; 4];
            send.send(&data).await.unwrap();
            let mut recved = vec![0; 16];
            let (len, from) = remote_socket.recv_from(&mut recved).await.unwrap();
            let recved = &recved[..len];
            assert_eq!(from, local_addr);
            assert_eq!(recved, data);
        });
    }
}
