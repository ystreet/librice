// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::net::SocketAddr;

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use rice_c::candidate::CandidateType;
use rice_c::stream::GatheredCandidate;
use rice_c::turn::TurnConfig;
use smol::net::{TcpListener, UdpSocket};

use futures::future::{AbortHandle, Abortable, Aborted};
use futures::{SinkExt, StreamExt};

use rice_c::{prelude::*, AddressFamily};

use librice::agent::{Agent, AgentMessage};
use librice::candidate::TransportType;
use librice::component::ComponentConnectionState;
use librice::stream::Credentials;

#[macro_use]
extern crate tracing;

mod common;
mod turn_server;

use turn_server::TurnServer;

struct DebugWrapper<T> {
    inner: T,
}

impl<T> DebugWrapper<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> core::fmt::Debug for DebugWrapper<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("...")
    }
}

impl<T> core::ops::Deref for DebugWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> core::ops::DerefMut for DebugWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug)]
struct AgentConfig {
    controlling: bool,
    trickle_ice: bool,
    transports: Vec<TransportType>,
    candidate_filter: DebugWrapper<Box<dyn Fn(&GatheredCandidate) -> bool + core::marker::Send>>,
    turn_servers: Vec<TurnConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            controlling: false,
            trickle_ice: false,
            transports: vec![],
            candidate_filter: DebugWrapper::new(Box::new(candidate_filter_accept_all)),
            turn_servers: vec![],
        }
    }
}

impl AgentConfig {
    fn controlling(mut self, controlling: bool) -> Self {
        self.controlling = controlling;
        self
    }
    fn trickle_ice(mut self, trickle_ice: bool) -> Self {
        self.trickle_ice = trickle_ice;
        self
    }
    fn transports(mut self, transports: &[TransportType]) -> Self {
        self.transports = transports.to_vec();
        self
    }
    fn turn_servers(mut self, turn_servers: Vec<TurnConfig>) -> Self {
        self.turn_servers = turn_servers;
        self
    }
    fn candidate_filter(
        mut self,
        candidate_filter: Box<dyn Fn(&GatheredCandidate) -> bool + core::marker::Send>,
    ) -> Self {
        self.candidate_filter.inner = candidate_filter;
        self
    }
}

#[derive(Debug)]
struct AgentStaticTestConfig {
    local: AgentConfig,
    remote: AgentConfig,
}

#[tracing::instrument(name = "agent_static_connection")]
async fn agent_static_connection_test(config: AgentStaticTestConfig) {
    let udp_stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_stun_addr = udp_stun_socket.local_addr().unwrap();
    let (udp_abort_handle, abort_registration) = AbortHandle::new_pair();
    let udp_stun_server = Abortable::new(common::stund_udp(udp_stun_socket), abort_registration);
    let udp_stun_server = smol::spawn(udp_stun_server);

    let tcp_stun_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_stun_addr = tcp_stun_socket.local_addr().unwrap();
    let (tcp_abort_handle, abort_registration) = AbortHandle::new_pair();
    let tcp_stun_server = Abortable::new(common::stund_tcp(tcp_stun_socket), abort_registration);
    let tcp_stun_server = smol::spawn(tcp_stun_server);

    let lagent = Arc::new(
        Agent::builder()
            .controlling(config.local.controlling)
            .trickle_ice(config.local.trickle_ice)
            .build(),
    );
    if config.local.transports.contains(&TransportType::Udp) {
        lagent.add_stun_server(TransportType::Udp, udp_stun_addr);
    }
    if config.local.transports.contains(&TransportType::Tcp) {
        lagent.add_stun_server(TransportType::Tcp, tcp_stun_addr);
    }

    for turn in config.local.turn_servers {
        lagent.add_turn_server(turn);
    }

    let ragent = Arc::new(
        Agent::builder()
            .controlling(config.remote.controlling)
            .trickle_ice(config.remote.trickle_ice)
            .build(),
    );
    if config.remote.transports.contains(&TransportType::Udp) {
        ragent.add_stun_server(TransportType::Udp, udp_stun_addr);
    }
    if config.remote.transports.contains(&TransportType::Tcp) {
        ragent.add_stun_server(TransportType::Tcp, tcp_stun_addr);
    }

    for turn in config.remote.turn_servers {
        ragent.add_turn_server(turn);
    }

    let lcreds = Credentials::new("luser", "lpass");
    let rcreds = Credentials::new("ruser", "rpass");

    let lstream = lagent.add_stream();
    lstream.set_local_credentials(&lcreds);
    lstream.set_remote_credentials(&rcreds);
    let lcomp = lstream.add_component().unwrap();

    let rstream = ragent.add_stream();
    rstream.set_local_credentials(&rcreds);
    rstream.set_remote_credentials(&lcreds);
    let rcomp = rstream.add_component().unwrap();

    lstream.gather_candidates().await.unwrap();
    rstream.gather_candidates().await.unwrap();

    let n_completed = Arc::new(AtomicUsize::new(0));
    let (complete_send, mut completed) = futures::channel::mpsc::channel(1);
    let mut lmessages = lagent.messages();
    let mut rmessages = ragent.messages();
    let (lgath_send, mut lgathered) = futures::channel::mpsc::channel(1);
    let lloop = smol::spawn({
        let n_completed = n_completed.clone();
        let complete_send = complete_send.clone();
        let lgath_send = lgath_send.clone();
        let lstream = lstream.clone();
        let rstream = rstream.clone();
        async move {
            while let Some(msg) = lmessages.next().await {
                match msg {
                    AgentMessage::GatheredCandidate(_stream, gathered) => {
                        if config.local.candidate_filter.as_ref()(&gathered) {
                            let candidate = gathered.candidate();
                            lstream.add_local_gathered_candidates(gathered);
                            rstream.add_remote_candidate(&candidate);
                        }
                    }
                    AgentMessage::GatheringComplete(_component) => {
                        rstream.end_of_remote_candidates();
                        let _ = lgath_send.clone().send(()).await;
                    }
                    AgentMessage::ComponentStateChange(_component, state) => {
                        if state == ComponentConnectionState::Connected
                            && 1 == n_completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        {
                            let _ = complete_send.clone().send(()).await;
                        }
                    }
                }
            }
        }
    });

    let (rgath_send, mut rgathered) = futures::channel::mpsc::channel(1);
    let rloop = smol::spawn({
        let rgath_send = rgath_send.clone();
        let n_completed = n_completed.clone();
        async move {
            while let Some(msg) = rmessages.next().await {
                match msg {
                    AgentMessage::GatheredCandidate(_stream, gathered) => {
                        if config.remote.candidate_filter.as_ref()(&gathered) {
                            let candidate = gathered.candidate();
                            rstream.add_local_gathered_candidates(gathered);
                            lstream.add_remote_candidate(&candidate);
                        }
                    }
                    AgentMessage::GatheringComplete(_component) => {
                        lstream.end_of_remote_candidates();
                        let _ = rgath_send.clone().send(()).await;
                    }
                    AgentMessage::ComponentStateChange(_component, state) => {
                        if state == ComponentConnectionState::Connected
                            && 1 == n_completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        {
                            let _ = complete_send.clone().send(()).await;
                        }
                    }
                }
            }
        }
    });

    if !config.local.trickle_ice {
        let _ = lgathered.next().await;
    }
    if !config.remote.trickle_ice {
        let _ = rgathered.next().await;
    }
    drop(lgathered);
    drop(rgathered);
    trace!("gathered");

    completed.next().await.unwrap();
    drop(completed);

    assert_eq!(lcomp.state(), ComponentConnectionState::Connected);
    assert_eq!(rcomp.state(), ComponentConnectionState::Connected);
    trace!("connected");

    let rcomp_recv_stream = rcomp.recv();
    let data = vec![5; 8];
    lcomp.send(&data).await.unwrap();
    trace!("local sent");
    futures::pin_mut!(rcomp_recv_stream);
    let received = rcomp_recv_stream.next().await.unwrap();
    assert_eq!(&data, &*received);
    trace!("local sent remote received");

    let lcomp_recv_stream = lcomp.recv();
    let data = vec![3; 8];
    rcomp.send(&data).await.unwrap();
    trace!("remote sent");
    futures::pin_mut!(lcomp_recv_stream);
    let received = lcomp_recv_stream.next().await.unwrap();
    assert_eq!(&data, &*received);
    trace!("remote sent local received");

    lagent.close();
    ragent.close();
    trace!("agents closed");

    udp_abort_handle.abort();
    tcp_abort_handle.abort();
    trace!("agents aborted");
    assert!(matches!(udp_stun_server.await, Err(Aborted)));
    assert!(matches!(tcp_stun_server.await, Err(Aborted)));

    let _ = lloop.await;
    let _ = rloop.await;
    trace!("done");
}

fn candidate_filter_accept_all(_gathered: &GatheredCandidate) -> bool {
    true
}

fn candidate_filter_accept_transport(
    gathered: &GatheredCandidate,
    transports: &[TransportType],
) -> bool {
    transports.contains(&gathered.candidate().transport())
}

#[test]
fn agent_static_connection_none_controlling_udp() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_both_controlling_udp() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .controlling(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .controlling(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_remote_controlling_udp() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .controlling(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .controlling(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp_both_trickle() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .controlling(true)
            .trickle_ice(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .trickle_ice(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp_local_trickle() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .controlling(true)
            .trickle_ice(true)
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        remote: AgentConfig::default()
            .transports(&[TransportType::Udp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
    }));
}

#[test]
fn agent_static_connection_local_controlling_tcp() {
    common::debug_init();
    smol::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig::default()
            .controlling(true)
            .transports(&[TransportType::Tcp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Tcp])
            })),
        remote: AgentConfig::default()
            .transports(&[TransportType::Tcp])
            .candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Tcp])
            })),
    }));
}

fn candidate_filter_relay_only(gathered: &GatheredCandidate) -> bool {
    gathered.candidate().candidate_type() == CandidateType::Relayed
}

fn turn_credentials() -> Credentials {
    Credentials::new("tuser", "tpass")
}

async fn turn_server_localhost_ipv4() -> (TurnServer, TurnConfig) {
    let listen_addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
    let relay_addr = listen_addr.ip();
    let server = TurnServer::new(listen_addr, "realm".to_string(), relay_addr).await;
    server.add_user("tuser", "tpass");
    let listen_addr = server.listen_address();
    (
        server,
        TurnConfig::new(
            TransportType::Udp,
            listen_addr.into(),
            turn_credentials(),
            &[AddressFamily::IPV4],
            None,
        ),
    )
}

#[test]
fn agent_static_connection_local_controlling_udp_turn_server() {
    common::debug_init();
    smol::block_on(async move {
        let local_turn = turn_server_localhost_ipv4().await;
        agent_static_connection_test(AgentStaticTestConfig {
            local: AgentConfig::default()
                .controlling(true)
                .candidate_filter(Box::new(candidate_filter_relay_only))
                .turn_servers(vec![local_turn.1]),
            remote: AgentConfig::default().candidate_filter(Box::new(move |candidate| {
                candidate_filter_accept_transport(candidate, &[TransportType::Udp])
            })),
        })
        .await
    });
}
