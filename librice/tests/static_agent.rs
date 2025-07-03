// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use async_std::net::{TcpListener, UdpSocket};

use futures::future::{AbortHandle, Abortable, Aborted};
use futures::{SinkExt, StreamExt};

use librice::agent::{Agent, AgentMessage};
use librice::candidate::TransportType;
use librice::stream::Credentials;
use librice_proto::component::ComponentConnectionState;

#[macro_use]
extern crate tracing;

mod common;

#[derive(Debug)]
struct AgentConfig {
    controlling: bool,
    trickle_ice: bool,
    transports: Vec<TransportType>,
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
    let udp_stun_server = async_std::task::spawn(udp_stun_server);

    let tcp_stun_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_stun_addr = tcp_stun_socket.local_addr().unwrap();
    let (tcp_abort_handle, abort_registration) = AbortHandle::new_pair();
    let tcp_stun_server = Abortable::new(common::stund_tcp(tcp_stun_socket), abort_registration);
    let tcp_stun_server = async_std::task::spawn(tcp_stun_server);

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

    let lcreds = Credentials::new("luser".into(), "lpass".into());
    let rcreds = Credentials::new("ruser".into(), "rpass".into());

    let lstream = lagent.add_stream();
    lstream.set_local_credentials(lcreds.clone());
    lstream.set_remote_credentials(rcreds.clone());
    let lcomp = lstream.add_component().unwrap();

    let rstream = ragent.add_stream();
    rstream.set_local_credentials(rcreds);
    rstream.set_remote_credentials(lcreds);
    let rcomp = rstream.add_component().unwrap();

    lstream.gather_candidates().await.unwrap();
    rstream.gather_candidates().await.unwrap();

    let n_completed = Arc::new(AtomicUsize::new(0));
    let (complete_send, mut completed) = futures::channel::mpsc::channel(1);
    let mut lmessages = lagent.messages();
    let mut rmessages = ragent.messages();
    let (lgath_send, mut lgathered) = futures::channel::mpsc::channel(1);
    let lloop = async_std::task::spawn({
        let n_completed = n_completed.clone();
        let complete_send = complete_send.clone();
        let lgath_send = lgath_send.clone();
        async move {
            while let Some(msg) = lmessages.next().await {
                match msg {
                    AgentMessage::GatheredCandidate(_stream, candidate) => {
                        if config.remote.transports.contains(&candidate.transport_type) {
                            rstream.add_remote_candidate(candidate).unwrap();
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
    let rloop = async_std::task::spawn({
        let rgath_send = rgath_send.clone();
        let n_completed = n_completed.clone();
        async move {
            while let Some(msg) = rmessages.next().await {
                match msg {
                    AgentMessage::GatheredCandidate(_stream, candidate) => {
                        if config.local.transports.contains(&candidate.transport_type) {
                            lstream.add_remote_candidate(candidate).unwrap();
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
    assert_eq!(data, received);
    trace!("local sent remote received");

    let lcomp_recv_stream = lcomp.recv();
    let data = vec![3; 8];
    rcomp.send(&data).await.unwrap();
    trace!("remote sent");
    futures::pin_mut!(lcomp_recv_stream);
    let received = lcomp_recv_stream.next().await.unwrap();
    assert_eq!(data, received);
    trace!("remote sent local received");

    lagent.close().unwrap();
    ragent.close().unwrap();
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

#[test]
fn agent_static_connection_none_controlling_udp() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_both_controlling_udp() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: true,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_remote_controlling_udp() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: true,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp_both_trickle() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: true,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: true,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling_udp_local_trickle() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: true,
            transports: vec![TransportType::Udp],
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Udp],
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling_tcp() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: false,
            transports: vec![TransportType::Tcp],
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
            transports: vec![TransportType::Tcp],
        },
    }));
}
