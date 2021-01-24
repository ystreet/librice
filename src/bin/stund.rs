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
use async_std::sync::Arc;
use async_std::task;

#[macro_use]
extern crate log;

use futures::StreamExt;

use librice::agent::*;
use librice::socket::UdpSocketChannel;
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
    response.add_attribute(XorMappedAddress::new(from, msg.transaction_id())?.to_raw())?;
    response.add_fingerprint()?;
    Ok(response)
}

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
        while let Some((msg, _msg_data, from)) = stun_stream.next().await {
            info!("received from {}: {}", from, msg);
            if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                match handle_binding_request(&msg, from) {
                    Ok(response) => {
                        info!("sending response to {}: {}", from, response);
                        warn_on_err(stun_agent.send(response, from).await, ())
                    }
                    Err(err) => warn!("error: {}", err),
                }
            }
        }
        tj.await;
        Ok(())
    })
}
