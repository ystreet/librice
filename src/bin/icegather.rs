// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use]
extern crate log;
use env_logger;

use async_std::task;

use std::io;

use futures::prelude::*;

fn main() -> io::Result<()> {
    env_logger::init();
    task::block_on(async move {
        let stun_servers = ["127.0.0.1:3478".parse().unwrap()].to_vec();

        let schannels = librice::gathering::iface_udp_sockets().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                e,
            )
        })?.filter_map(move |s| async move { s.ok() })
        .collect::<Vec<_>>()
        .await;

        info!("retreived sockets");
        let gather_stream = librice::gathering::gather_component(1, schannels, stun_servers).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                e,
            )
        })?;
        futures::pin_mut!(gather_stream);
        while let Some(candidate) = gather_stream.next().await {
            println!{"{:?}", candidate};
        }
        Ok(())
    })
}
