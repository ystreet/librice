// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A [`Component`] in an ICE [`Stream`](crate::stream::Stream)

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use std::task::{Poll, Waker};

use rice_c::Instant;
use rice_c::candidate::CandidatePair;
use rice_c::prelude::*;

pub use rice_c::component::ComponentConnectionState;
use rice_c::stream::RecvData as CRecvData;
use tracing::trace;

use crate::agent::AgentError;
use crate::socket::StunChannel;

use futures::prelude::*;

/// The component id for RTP streaming (and general data).
pub const RTP: usize = 1;
/// The component id for RTCP streaming (if rtcp-mux is not in use).
pub const RTCP: usize = 2;

/// A [`Component`] within an ICE [`Stream`](crate::stream::Stream`)
#[derive(Debug, Clone)]
pub struct Component {
    base_instant: std::time::Instant,
    proto: rice_c::component::Component,
    #[allow(dead_code)]
    stream_id: usize,
    pub(crate) id: usize,
    pub(crate) inner: Arc<Mutex<ComponentInner>>,
    weak_stream: Weak<crate::stream::StreamState>,
}

impl Component {
    pub(crate) fn new(
        stream_id: usize,
        proto: rice_c::component::Component,
        base_instant: std::time::Instant,
        weak_stream: Weak<crate::stream::StreamState>,
    ) -> Self {
        Self {
            stream_id,
            id: proto.id(),
            proto,
            inner: Arc::new(Mutex::new(ComponentInner::new())),
            base_instant,
            weak_stream,
        }
    }

    /// The component identifier within a particular ICE [`Stream`]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Retrieve the [`Stream`](crate::stream::Stream) for this component.
    pub fn stream(&self) -> crate::stream::Stream {
        crate::stream::Stream::from_state(self.weak_stream.upgrade().unwrap())
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
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let runtime = tokio::runtime::Builder::new_current_thread()
    /// #     .enable_all()
    /// #     .build()
    /// #     .unwrap();
    /// # #[cfg(feature = "runtime-tokio")]
    /// # let _runtime = runtime.enter();
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.state(), ComponentConnectionState::New);
    /// ```
    pub fn state(&self) -> ComponentConnectionState {
        self.proto.state()
    }

    /// Send data to the peer using the established communication channel.  This will not succeed
    /// until the component is in the [`Connected`](ComponentConnectionState::Connected) state.
    pub async fn send(&self, data: &[u8]) -> Result<(), AgentError> {
        let transmit;
        let (mut channel, to) = {
            let inner = self.inner.lock().unwrap();
            let selected_pair = inner.selected_pair.as_ref().ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No selected pair",
            ))?;
            let to = selected_pair.pair.remote.address();
            (selected_pair.socket.clone(), to)
        };

        transmit = self
            .proto
            .send(data, Instant::from_std(self.base_instant))?;

        trace!("sending {} bytes to {:?}", data.len(), to);
        channel
            .send_to(transmit.data, transmit.to.as_socket())
            .await?;

        Ok(())
    }

    /// A stream that provides the data that has been sent from the peer to this component.
    pub fn recv(&self) -> impl Stream<Item = RecvData> + '_ {
        ComponentRecv {
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn set_selected_pair(&self, selected: SelectedPair) -> Result<(), AgentError> {
        let mut inner = self.inner.lock().unwrap();
        tracing::info!("set selected pair {selected:?}");
        self.proto.set_selected_pair(selected.pair.clone())?;
        inner.selected_pair = Some(selected);

        Ok(())
    }

    /// The pair that has been selected for communication.  Will not provide a useful value until
    /// ICE negotiation has completed successfully.
    pub fn selected_pair(&self) -> Option<CandidatePair> {
        self.inner
            .lock()
            .unwrap()
            .selected_pair
            .clone()
            .map(|selected| selected.pair.clone())
    }
}

#[derive(Debug)]
pub(crate) struct ComponentInner {
    selected_pair: Option<SelectedPair>,
    received_data: VecDeque<RecvData>,
    recv_waker: Option<Waker>,
}

impl ComponentInner {
    fn new() -> Self {
        Self {
            selected_pair: None,
            received_data: VecDeque::default(),
            recv_waker: None,
        }
    }

    #[tracing::instrument(
        name = "component_incoming_data"
        skip(self, data)
        fields(
            data.len = data.len()
        )
    )]
    pub(crate) fn handle_incoming_data(&mut self, data: RecvData) {
        self.received_data.push_back(data);
        if let Some(waker) = self.recv_waker.take() {
            waker.wake();
        }
    }
}

/// Data that has been received from a peer.
#[derive(Debug)]
pub enum RecvData {
    /// Rust allocated Vec.
    Vec(Vec<u8>),
    /// C allocated data.
    Proto(CRecvData),
}

impl From<Vec<u8>> for RecvData {
    fn from(value: Vec<u8>) -> Self {
        Self::Vec(value)
    }
}

impl From<CRecvData> for RecvData {
    fn from(value: CRecvData) -> Self {
        Self::Proto(value)
    }
}

impl core::ops::Deref for RecvData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Vec(vec) => vec,
            Self::Proto(proto) => proto.deref(),
        }
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ComponentRecv {
    inner: Arc<Mutex<ComponentInner>>,
}

impl futures::Stream for ComponentRecv {
    type Item = RecvData;

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
    pair: rice_c::candidate::CandidatePair,
    socket: StunChannel,
}

impl SelectedPair {
    pub(crate) fn new(pair: rice_c::candidate::CandidatePair, socket: StunChannel) -> Self {
        Self { pair, socket }
    }
}

#[cfg(test)]
mod tests {
    use rice_c::candidate::{Candidate, CandidateType, TransportType};

    use super::*;
    use crate::{agent::Agent, socket::UdpSocketChannel};

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn initial_state_new() {
        #[cfg(feature = "runtime-tokio")]
        let _runtime = crate::tests::tokio_runtime().enter();
        init();
        let agent = Agent::builder().build();
        let s = agent.add_stream();
        let c = s.add_component().unwrap();
        assert_eq!(c.state(), ComponentConnectionState::New);
    }

    #[cfg(feature = "runtime-smol")]
    #[test]
    fn smol_send_recv() {
        smol::block_on(send_recv());
    }

    #[cfg(feature = "runtime-tokio")]
    #[test]
    fn tokio_send_recv() {
        crate::tests::tokio_runtime().block_on(send_recv());
    }

    async fn send_recv() {
        init();
        let runtime = crate::runtime::default_runtime().unwrap();
        let agent = Agent::builder().controlling(false).build();
        let stream = agent.add_stream();
        let send = stream.add_component().unwrap();
        let local_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = local_socket.local_addr().unwrap();
        let remote_addr = remote_socket.local_addr().unwrap();
        let local_channel = StunChannel::Udp(UdpSocketChannel::new(
            runtime.wrap_udp_socket(local_socket).unwrap(),
        ));

        let local_cand = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "0",
            local_addr.into(),
        )
        .build();
        let remote_cand = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "0",
            remote_addr.into(),
        )
        .build();
        let candidate_pair = CandidatePair::new(local_cand.to_owned(), remote_cand.to_owned());
        let selected_pair = SelectedPair::new(candidate_pair, local_channel);

        send.set_selected_pair(selected_pair.clone()).unwrap();
        assert_eq!(selected_pair.pair, send.selected_pair().unwrap());

        let data = vec![3; 4];
        send.send(&data).await.unwrap();
        let mut recved = vec![0; 16];
        let (len, from) = remote_socket.recv_from(&mut recved).unwrap();
        let recved = &recved[..len];
        assert_eq!(from, local_addr);
        assert_eq!(recved, data);
    }
}
