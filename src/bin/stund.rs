// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use async_std::io;
use async_std::net::UdpSocket;
use async_std::sync::Arc;
use async_std::task;

#[macro_use]
extern crate log;
use env_logger;

use futures::StreamExt;

use librice::socket::UdpSocketChannel;
use librice::stun::agent::*;

fn main() -> io::Result<()> {
    env_logger::init();

    task::block_on(async move {
        let socket = UdpSocket::bind("127.0.0.1:3478").await?;
        let channel = Arc::new(UdpSocketChannel::new(socket));
        let stun_agent = StunAgent::new(channel);

        let mut data_stream = stun_agent.data_receive_stream();
        let tj = task::spawn(async move {
            while let Some((data, from)) = data_stream.next().await {
                info!("received from {} data: {:?}", from, data);
            }
        });

        let mut stun_stream = stun_agent.stun_receive_stream();
        while let Some((msg, from)) = stun_stream.next().await {
            info!("received from {}: {:?}", from, msg);
        }
        tj.await;
        Ok(())
    })
}
