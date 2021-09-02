// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Display;
use std::net::SocketAddr;

use async_std::io;
use async_std::net::UdpSocket;
use async_std::task;

#[macro_use]
extern crate log;

use futures::StreamExt;

use librice::agent::*;
use librice::socket::{SocketChannel, UdpSocketChannel};
use librice::stun::agent::*;
use librice::stun::attribute::*;
use librice::stun::message::*;

fn warn_on_err<T, E>(res: Result<T, E>, default: T) -> T
where
    E: Display,
{
    match res {
        Ok(v) => v,
        Err(e) => {
            warn!("{}", e);
            default
        }
    }
}

fn handle_binding_request(msg: &Message, from: SocketAddr) -> Result<Message, AgentError> {
    if let Some(error_msg) = Message::check_attribute_types(msg, &[FINGERPRINT], &[]) {
        return Ok(error_msg);
    }

    let mut response = Message::new_success(msg);
    response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
    response.add_fingerprint()?;
    Ok(response)
}

fn main() -> io::Result<()> {
    env_logger::init();

    task::block_on(async move {
        let socket = UdpSocket::bind("127.0.0.1:3478").await?;
        let channel = SocketChannel::Udp(UdpSocketChannel::new(socket));
        let stun_agent = StunAgent::new(channel);

        let mut receive_stream = stun_agent.receive_stream();
        while let Some(stun_or_data) = receive_stream.next().await {
            match stun_or_data {
                StunOrData::Data(data, from) => info!("received from {} data: {:?}", from, data),
                StunOrData::Stun(msg, _data, from) => {
                    info!("received from {}: {}", from, msg);
                    if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                        match handle_binding_request(&msg, from) {
                            Ok(response) => {
                                info!("sending response to {}: {}", from, response);
                                warn_on_err(stun_agent.send_to(response, from).await, ())
                            }
                            Err(err) => warn!("error: {}", err),
                        }
                    }
                }
            }
        }
        Ok(())
    })
}
