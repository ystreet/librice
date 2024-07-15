// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use librice::agent::Agent;

use async_std::task;

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
    task::block_on(async move {
        // non-existent
        //let stun_servers = ["192.168.1.200:3000".parse().unwrap()].to_vec();
        let stun_servers = ["192.168.20.28:3478".parse().unwrap()];
        //let stun_servers = ["172.253.56.127:19302".parse().unwrap()].to_vec();

        let agent = Agent::builder().build();
        for ss in stun_servers {
            agent.add_stun_server(TransportType::Udp, ss);
            agent.add_stun_server(TransportType::Tcp, ss);
        }
        let stream = agent.add_stream();
        let _comp = stream.add_component();

        let gather_stream = stream.gather_candidates().await.unwrap();
        futures::pin_mut!(gather_stream);
        while let Some(candidate) = gather_stream.next().await {
            println! {"{:?}", candidate};
        }
        Ok(())
    })
}
