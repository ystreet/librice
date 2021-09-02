// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Display;
use std::net::SocketAddr;

use async_std::net::{UdpSocket, TcpListener};

use futures::StreamExt;

use librice::agent::*;
use librice::socket::{SocketChannel, UdpSocketChannel, TcpChannel};
use librice::stun::agent::*;
use librice::stun::attribute::*;
use librice::stun::message::*;

pub fn debug_init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

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

pub async fn handle_stun(stun_agent: StunAgent) -> std::io::Result<()> {
    let mut receive_stream = stun_agent.receive_stream();

    let channel = stun_agent.channel();
    let addr = channel.local_addr()?;

    debug!("starting stun server at {}", addr);
    while let Some(stun_or_data) = receive_stream.next().await {
        match stun_or_data {
            StunOrData::Data(data, from) => info!("received from {} data: {:?}", from, data),
            StunOrData::Stun(msg, _data, from) => {
                info!("received from {}: {}", from, msg);
                if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                    match handle_binding_request(&msg, from) {
                        Ok(response) => {
                            info!("sending response to {}: {}", from, response);
                            /* XXX: probably want a explicity vfunc/check for this rather than relying on
                             * th error */
                            match channel.remote_addr() {
                                Ok(_) => warn_on_err(stun_agent.send(response).await, ()),
                                Err(_) => warn_on_err(stun_agent.send_to(response, from).await, ()),
                            }
                        }
                        Err(err) => warn!("error: {}", err),
                    }
                }
            },
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn stund_udp(socket: UdpSocket) -> std::io::Result<()> {
    let addr = socket.local_addr()?;
    let channel = SocketChannel::Udp(UdpSocketChannel::new(socket));
    let stun_agent = StunAgent::new(channel);

    handle_stun(stun_agent).await.unwrap();
    debug!("stopping stun server at {}", addr);
    Ok(())
}

#[allow(dead_code)]
pub async fn stund_tcp(listener: TcpListener) -> std::io::Result<()> {
    let mut incoming = listener.incoming();
    let addr = listener.local_addr()?;
    while let Some(Ok(stream)) = incoming.next().await {
        async_std::task::spawn(async move {
            let channel = SocketChannel::Tcp(TcpChannel::new(stream));
            let stun_agent = StunAgent::new(channel);
            handle_stun(stun_agent).await.unwrap();
        });
    }
    debug!("stopping stun server at {}", addr);
    Ok(())
}
