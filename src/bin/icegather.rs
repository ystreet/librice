// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate tracing;

use librice::socket::StunChannel;
use tracing_subscriber::EnvFilter;

use async_std::task;

use std::io;

use futures::prelude::*;

use librice::stun::agent::StunAgent;
use librice::stun::TransportType;

fn main() -> io::Result<()> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    task::block_on(async move {
        // non-existent
        //let stun_servers = ["192.168.1.200:3000".parse().unwrap()].to_vec();
        let stun_servers = [(TransportType::Udp, "127.0.0.1:3478".parse().unwrap())].to_vec();
        //let stun_servers = ["172.253.56.127:19302".parse().unwrap()].to_vec();

        let agents = librice::gathering::iface_udp_sockets()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?
            .filter_map(|channel| async move {
                channel.ok().map(|c| StunAgent::new(StunChannel::UdpAny(c)))
            })
            .collect::<Vec<_>>()
            .await;

        info!("retreived sockets");
        let gather_stream = librice::gathering::gather_component(1, agents, stun_servers);
        futures::pin_mut!(gather_stream);
        while let Some(candidate) = gather_stream.next().await {
            println! {"{:?}", candidate};
        }
        Ok(())
    })
}
