// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use librice::agent::{Agent, AgentMessage, TurnConfig, TurnCredentials};

use std::io;

use futures::prelude::*;

use librice::candidate::TransportType;

fn init_logs() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let level_filter = std::env::var("RICE_LOG")
        .ok()
        .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
        .unwrap_or(tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR));
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_target(false)
            .with_test_writer()
            .with_filter(level_filter),
    );
    tracing::subscriber::set_global_default(registry).unwrap();
}

fn main() -> io::Result<()> {
    init_logs();
    smol::block_on(async move {
        // non-existent
        //let stun_servers = ["192.168.1.200:3000".parse().unwrap()].to_vec();
        let stun_servers = ["127.0.0.1:3478".parse().unwrap()];
        //let stun_servers = ["172.253.56.127:19302".parse().unwrap()].to_vec();

        let credentials = TurnCredentials::new("coturn", "password");

        let agent = Agent::builder().build();
        for ss in stun_servers {
            agent.add_stun_server(TransportType::Udp, ss);
            agent.add_stun_server(TransportType::Tcp, ss);
            let turn_cfg = TurnConfig::new(TransportType::Udp, ss.into(), credentials.clone());
            agent.add_turn_server(turn_cfg);
        }
        let stream = agent.add_stream();
        let _comp = stream.add_component();

        stream.gather_candidates().await.unwrap();
        let mut messages = agent.messages();
        while let Some(msg) = messages.next().await {
            match msg {
                AgentMessage::GatheredCandidate(_stream, candidate) => println! {"{:?}", candidate},
                AgentMessage::GatheringComplete(_component) => break,
                _ => (),
            }
        }
        Ok(())
    })
}
