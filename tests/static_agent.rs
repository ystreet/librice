// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::Arc;

use async_std::net::{TcpListener, UdpSocket};

use futures::future::{AbortHandle, Abortable, Aborted};
use futures::StreamExt;

use librice::agent::{Agent, AgentMessage};
use librice::candidate::TransportType;
use librice::component::ComponentState;
use librice::stream::Credentials;

#[macro_use]
extern crate tracing;

mod common;

#[derive(Debug)]
struct AgentConfig {
    controlling: bool,
    trickle_ice: bool,
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
    lagent.add_stun_server(TransportType::Udp, udp_stun_addr);
    lagent.add_stun_server(TransportType::Tcp, tcp_stun_addr);

    let ragent = Arc::new(
        Agent::builder()
            .controlling(config.remote.controlling)
            .trickle_ice(config.remote.trickle_ice)
            .build(),
    );
    ragent.add_stun_server(TransportType::Udp, udp_stun_addr);
    ragent.add_stun_server(TransportType::Tcp, tcp_stun_addr);

    let lcreds = Credentials::new("luser".into(), "lpass".into());
    let rcreds = Credentials::new("ruser".into(), "rpass".into());

    let mut l_msg_s = lagent.message_channel();
    let lstream = lagent.add_stream();
    lstream.set_local_credentials(lcreds.clone());
    lstream.set_remote_credentials(rcreds.clone());
    let lcomp = lstream.add_component().unwrap();
    // XXX: currently must be after stream creation as dynamically adding streams is not currently
    // supported
    if config.local.trickle_ice {
        lagent.start().unwrap();
    }

    let mut r_msg_s = ragent.message_channel();
    let rstream = ragent.add_stream();
    rstream.set_local_credentials(rcreds);
    rstream.set_remote_credentials(lcreds);
    let rcomp = rstream.add_component().unwrap();
    if config.remote.trickle_ice {
        ragent.start().unwrap();
    }

    // poor-man's async semaphore
    let (lgatherdone_send, lgatherdone_recv) = async_channel::bounded::<i32>(1);
    let lgather = async_std::task::spawn({
        let rstream = rstream.clone();
        async move {
            while let Some(msg) = l_msg_s.next().await {
                match msg {
                    AgentMessage::NewLocalCandidate(comp, cand) => {
                        rstream.add_remote_candidate(comp.id, cand).unwrap()
                    }
                    AgentMessage::GatheringCompleted(_comp) => {
                        let _ = lgatherdone_send.send(0).await;
                    }
                    AgentMessage::ComponentStateChange(_comp, state) => {
                        if state == ComponentState::Connected || state == ComponentState::Failed {
                            break;
                        }
                    }
                }
            }
        }
    });
    let (rgatherdone_send, rgatherdone_recv) = async_channel::bounded::<i32>(1);
    let rgather = async_std::task::spawn({
        let lstream = lstream.clone();
        async move {
            while let Some(msg) = r_msg_s.next().await {
                match msg {
                    AgentMessage::NewLocalCandidate(comp, cand) => {
                        lstream.add_remote_candidate(comp.id, cand).unwrap()
                    }
                    AgentMessage::GatheringCompleted(_comp) => {
                        let _ = rgatherdone_send.send(0).await;
                    }
                    AgentMessage::ComponentStateChange(_comp, state) => {
                        if state == ComponentState::Connected || state == ComponentState::Failed {
                            break;
                        }
                    }
                }
            }
        }
    });

    futures::try_join!(lstream.gather_candidates(), rstream.gather_candidates()).unwrap();
    if config.local.trickle_ice {
        lgatherdone_recv.recv().await.unwrap();
    }
    drop(lgatherdone_recv);
    if config.remote.trickle_ice {
        rgatherdone_recv.recv().await.unwrap();
    }
    drop(rgatherdone_recv);
    trace!("gathered");

    if !config.local.trickle_ice {
        lagent.start().unwrap();
    }
    if !config.remote.trickle_ice {
        ragent.start().unwrap();
    }

    futures::join!(lgather, rgather);
    trace!("connected");

    let rcomp_recv_stream = rcomp.receive_stream();
    let data = vec![5; 8];
    lcomp.send(&data).await.unwrap();
    trace!("local sent");
    futures::pin_mut!(rcomp_recv_stream);
    let received = rcomp_recv_stream.next().await.unwrap();
    assert_eq!(data, received);
    trace!("local sent remote received");

    let lcomp_recv_stream = lcomp.receive_stream();
    let data = vec![3; 8];
    rcomp.send(&data).await.unwrap();
    trace!("remote sent");
    futures::pin_mut!(lcomp_recv_stream);
    let received = lcomp_recv_stream.next().await.unwrap();
    assert_eq!(data, received);
    trace!("remote sent local received");

    futures::try_join!(lagent.close(), ragent.close()).unwrap();
    trace!("agents closed");

    udp_abort_handle.abort();
    tcp_abort_handle.abort();
    trace!("agents aborted");
    assert!(matches!(udp_stun_server.await, Err(Aborted)));
    assert!(matches!(tcp_stun_server.await, Err(Aborted)));
    trace!("done");
}

#[test]
fn agent_static_connection_none_controlling() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: false,
            trickle_ice: false,
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
        },
    }));
}

#[test]
fn agent_static_connection_both_controlling() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: false,
        },
        remote: AgentConfig {
            controlling: true,
            trickle_ice: false,
        },
    }));
}

#[test]
fn agent_static_connection_remote_controlling() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: false,
            trickle_ice: false,
        },
        remote: AgentConfig {
            controlling: true,
            trickle_ice: false,
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: false,
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: false,
        },
    }));
}

#[test]
fn agent_static_connection_local_controlling_both_trickle() {
    common::debug_init();
    async_std::task::block_on(agent_static_connection_test(AgentStaticTestConfig {
        local: AgentConfig {
            controlling: true,
            trickle_ice: true,
        },
        remote: AgentConfig {
            controlling: false,
            trickle_ice: true,
        },
    }));
}
