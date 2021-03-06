// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::{Arc, Mutex};

use async_std::net::SocketAddr;

use futures::channel::oneshot;
use futures::future::AbortHandle;
use futures::prelude::*;
use futures::Stream;

use crate::agent::{AgentError, AgentMessage};
use crate::candidate::{Candidate, CandidatePair};

use crate::socket::{SocketChannel, UdpConnectionChannel};

use crate::stun::agent::StunAgent;
use crate::stun::message::MessageIntegrityCredentials;

use crate::utils::ChannelBroadcast;

pub const RTP: usize = 1;
pub const RTCP: usize = 2;

#[derive(Debug, Clone)]
pub struct Component {
    pub id: usize,
    broadcast: Arc<ChannelBroadcast<AgentMessage>>,
    inner: Arc<Mutex<ComponentInner>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComponentState {
    New,
    Connecting,
    Connected,
    Failed,
}

impl Component {
    pub(crate) fn new(id: usize, broadcast: Arc<ChannelBroadcast<AgentMessage>>) -> Self {
        Self {
            id,
            broadcast,
            inner: Arc::new(Mutex::new(ComponentInner::new(id))),
        }
    }

    /// Retreive the current state of a `Component`
    ///
    /// # Examples
    ///
    /// The initial state is `ComponentState::New`
    ///
    /// ```
    /// # use librice::component::{Component, ComponentState};
    /// # use librice::agent::Agent;
    /// # use librice::stream::Stream;
    /// let agent = Agent::default();
    /// let stream = agent.add_stream();
    /// let component = stream.add_component().unwrap();
    /// assert_eq!(component.state(), ComponentState::New);
    /// ```
    pub fn state(&self) -> ComponentState {
        let inner = self.inner.lock().unwrap();
        inner.state
    }

    pub(crate) async fn set_state(self: &Arc<Self>, state: ComponentState) {
        if let Some(new_state) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.state != state {
                info!(
                    "Component {} changing state from {:?} to {:?}",
                    self.id, inner.state, state
                );
                inner.state = state;
                Some(state)
            } else {
                None
            }
        } {
            self.broadcast
                .broadcast(AgentMessage::ComponentStateChange(self.clone(), new_state))
                .await;
        }
    }

    /// Retrieve a Stream that produces data sent to this component from a peer
    pub fn receive_stream(&self) -> impl Stream<Item = Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        // TODO: this probably may need to be multiplexed from multiple sources on e.g. candidate
        // changes
        inner.receive_receive_channel.clone()
    }

    /// Send data to the peer using the established communication channel
    pub async fn send(&self, data: &[u8]) -> Result<(), AgentError> {
        let channel = {
            let inner = self.inner.lock().unwrap();
            inner.channel.clone().ok_or(AgentError::ResourceNotFound)?
        };
        channel.send(data).await?;
        Ok(())
    }

    pub(crate) async fn gather_stream(
        &self,
        local_credentials: MessageIntegrityCredentials,
        remote_credentials: MessageIntegrityCredentials,
    ) -> Result<impl Stream<Item = (Candidate, StunAgent)>, AgentError> {
        let stun_servers = {
            let inner = self.inner.lock().unwrap();
            inner.stun_servers.clone()
        };
        let schannels = crate::gathering::iface_udp_sockets()?
            .filter_map(move |s| async move { s.ok() })
            .collect::<Vec<_>>()
            .await;

        let agents: Vec<_> = schannels
            .iter()
            .map(|channel| {
                let agent = StunAgent::new(channel.clone());
                agent.set_local_credentials(local_credentials.clone());
                agent.set_remote_credentials(remote_credentials.clone());
                agent
            })
            .collect();

        info!("retreived sockets");
        Ok(
            crate::gathering::gather_component(self.id, schannels, stun_servers)?.map(
                move |(cand, channel)| {
                    (
                        cand,
                        agents
                            .iter()
                            .find(|agent| {
                                agent.inner.channel.local_addr().ok() == channel.local_addr().ok()
                            })
                            .unwrap()
                            .clone(),
                    )
                },
            ),
        )
    }

    pub(crate) async fn add_recv_agent(&self, agent: StunAgent) -> AbortHandle {
        let sender = self.inner.lock().unwrap().receive_send_channel.clone();
        let (ready_send, ready_recv) = oneshot::channel();

        debug!("Component {} adding agent for receive", self.id);
        let (abortable, abort_handle) = futures::future::abortable(async move {
            let mut data_recv_stream = agent.data_receive_stream();
            if ready_send.send(()).is_err() {
                return;
            }
            while let Some(data) = data_recv_stream.next().await {
                if let Err(e) = sender.send(data.0).await {
                    warn!("error receiving {:?}", e);
                }
            }
            debug!("receive loop exited");
        });

        async_std::task::spawn(abortable);

        ready_recv.await.unwrap();

        abort_handle
    }

    pub(crate) fn set_selected_pair(&self, selected: SelectedPair) {
        self.inner.lock().unwrap().set_selected_pair(selected)
    }

    pub fn selected_pair(&self) -> Option<CandidatePair> {
        self.inner
            .lock()
            .unwrap()
            .selected_pair
            .clone()
            .map(|selected| selected.candidate_pair)
    }
}

#[derive(Debug, Clone)]
struct ComponentInner {
    id: usize,
    state: ComponentState,
    selected_pair: Option<SelectedPair>,
    channel: Option<Arc<SocketChannel>>,
    receive_send_channel: async_channel::Sender<Vec<u8>>,
    receive_receive_channel: async_channel::Receiver<Vec<u8>>,
    stun_servers: Vec<SocketAddr>,
    turn_servers: Vec<SocketAddr>,
}

impl ComponentInner {
    fn new(id: usize) -> Self {
        let (recv_s, recv_r) = async_channel::bounded(16);
        Self {
            id,
            state: ComponentState::New,
            selected_pair: None,
            channel: None,
            receive_send_channel: recv_s,
            receive_receive_channel: recv_r,
            stun_servers: vec![],
            turn_servers: vec![],
        }
    }

    fn set_selected_pair(&mut self, selected: SelectedPair) {
        let remote_addr = selected.candidate_pair.remote.address;
        let local_channel = selected.local_stun_agent.inner.channel.clone();
        debug!(
            "Component {} selecting pair {:?}",
            self.id, selected.candidate_pair
        );
        self.selected_pair = Some(selected);
        self.channel = Some(Arc::new(SocketChannel::Udp(UdpConnectionChannel::new(
            local_channel,
            remote_addr,
        ))));
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedPair {
    candidate_pair: CandidatePair,
    local_stun_agent: StunAgent,
}
impl SelectedPair {
    pub(crate) fn new(candidate_pair: CandidatePair, local_stun_agent: StunAgent) -> Self {
        Self {
            candidate_pair,
            local_stun_agent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::candidate::*;
    use crate::socket::*;
    use crate::stun::message::*;
    use async_std::net::UdpSocket;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn initial_state_new() {
        init();
        let a = Agent::default();
        let s = a.add_stream();
        let c = s.add_component().unwrap();
        assert_eq!(c.state(), ComponentState::New);
    }

    #[test]
    fn set_state_broadcast() {
        init();
        async_std::task::block_on(async move {
            let a = Arc::new(Agent::default());
            let s = a.add_stream();
            let c = s.add_component().unwrap();
            let mut msg_channel = a.message_channel();

            let loop_task = async_std::task::spawn({
                let a = a.clone();
                async move {
                    a.run_loop().await.unwrap();
                }
            });
            assert_eq!(c.state(), ComponentState::New);
            c.set_state(ComponentState::Connecting).await;
            while let Some(AgentMessage::ComponentStateChange(_, state)) = msg_channel.next().await
            {
                assert_eq!(state, ComponentState::Connecting);
                break;
            }
            // duplicate states ignored
            c.set_state(ComponentState::Connecting).await;
            c.set_state(ComponentState::Connected).await;
            while let Some(AgentMessage::ComponentStateChange(_, state)) = msg_channel.next().await
            {
                assert_eq!(state, ComponentState::Connected);
                break;
            }

            a.close().await.unwrap();
            loop_task.await;
        });
    }

    #[test]
    fn send_recv() {
        init();
        async_std::task::block_on(async move {
            let a = Agent::default();
            let s = a.add_stream();
            let send = s.add_component().unwrap();

            let local_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let remote_channel = UdpSocketChannel::new(remote_socket);
            let local_agent = StunAgent::new(Arc::new(UdpSocketChannel::new(local_socket)));

            let local_cand = Candidate::new(
                CandidateType::Host,
                TransportType::Udp,
                "0",
                0,
                local_agent.inner.channel.local_addr().unwrap(),
                local_agent.inner.channel.local_addr().unwrap(),
                None,
            );
            let remote_cand = Candidate::new(
                CandidateType::Host,
                TransportType::Udp,
                "0",
                0,
                remote_channel.local_addr().unwrap(),
                remote_channel.local_addr().unwrap(),
                None,
            );
            let candidate_pair = CandidatePair::new(send.id, local_cand, remote_cand);
            let selected_pair = SelectedPair::new(candidate_pair, local_agent);

            send.set_selected_pair(selected_pair.clone());
            assert_eq!(selected_pair.candidate_pair, send.selected_pair().unwrap());

            let data = vec![3; 4];
            let recv_stream = remote_channel.receive_stream();
            futures::pin_mut!(recv_stream);
            send.send(&data).await.unwrap();
            let res = recv_stream.next().await.unwrap();
            assert_eq!(data, res.0);
        });
    }

    #[test]
    fn muxing_recv() {
        // given two sockets ensure sending to either of them produces the same data
        init();
        async_std::task::block_on(async move {
            let a = Agent::default();
            let s = a.add_stream();
            let send = s.add_component().unwrap();

            let socket1 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .await
                .unwrap();
            let addr1 = socket1.local_addr().unwrap();
            let channel1 = Arc::new(UdpSocketChannel::new(socket1));
            let stun = StunAgent::new(channel1.clone());
            send.add_recv_agent(stun).await;

            let socket2 = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .await
                .unwrap();
            let addr2 = socket2.local_addr().unwrap();
            let channel2 = Arc::new(UdpSocketChannel::new(socket2));
            let stun = StunAgent::new(channel2.clone());
            send.add_recv_agent(stun).await;

            let mut recv_stream = send.receive_stream();
            let buf = vec![0, 1];
            channel1.send_to(&buf, addr2).await.unwrap();
            assert_eq!(&recv_stream.next().await.unwrap(), &buf);
            let buf = vec![2, 3];
            channel2.send_to(&buf, addr1).await.unwrap();
            assert_eq!(&recv_stream.next().await.unwrap(), &buf);
        });
    }

    #[test]
    fn gather() {
        init();
        async_std::task::block_on(async move {
            // attempt to gather some candidates
            // assumes we have non-localhost networking available
            let send_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "send".into(),
            });
            let recv_credentials = MessageIntegrityCredentials::ShortTerm(ShortTermCredentials {
                password: "recv".into(),
            });
            let a = Agent::default();
            let s = a.add_stream();
            let send = s.add_component().unwrap();
            // assumes the first candidate works
            let send_stream = send
                .gather_stream(send_credentials.clone(), recv_credentials.clone())
                .await
                .unwrap();
            futures::pin_mut!(send_stream);
            let (send_cand, send_agent) = send_stream.next().await.unwrap();

            // XXX: not technically valid usage but works for now
            let recv = s.add_component().unwrap();
            let recv_stream = recv
                .gather_stream(recv_credentials, send_credentials)
                .await
                .unwrap();
            futures::pin_mut!(recv_stream);
            // assumes the first candidate works
            let (recv_cand, recv_agent) = recv_stream.next().await.unwrap();

            let send_candidate_pair =
                CandidatePair::new(send.id, send_cand.clone(), recv_cand.clone());
            let send_selected_pair = SelectedPair::new(send_candidate_pair, send_agent.clone());
            send.add_recv_agent(send_agent).await;
            send.set_selected_pair(send_selected_pair.clone());
            assert_eq!(
                send_selected_pair.candidate_pair,
                send.selected_pair().unwrap()
            );

            let recv_candidate_pair = CandidatePair::new(recv.id, recv_cand, send_cand);
            let recv_selected_pair = SelectedPair::new(recv_candidate_pair, recv_agent.clone());
            recv.add_recv_agent(recv_agent).await;
            recv.set_selected_pair(recv_selected_pair.clone());
            assert_eq!(
                recv_selected_pair.candidate_pair,
                recv.selected_pair().unwrap()
            );

            // two-way connection has been setup
            let data = vec![3; 4];
            let recv_recv_stream = recv.receive_stream();
            futures::pin_mut!(recv_recv_stream);
            send.send(&data).await.unwrap();
            let res = recv_recv_stream.next().await.unwrap();
            assert_eq!(data, res);

            let data = vec![2; 4];
            let send_recv_stream = send.receive_stream();
            futures::pin_mut!(send_recv_stream);
            recv.send(&data).await.unwrap();
            let res = send_recv_stream.next().await.unwrap();
            assert_eq!(data, res);
        });
    }
}
