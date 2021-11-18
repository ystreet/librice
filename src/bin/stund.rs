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
use async_std::net::{TcpListener, UdpSocket};
use async_std::task;

#[macro_use]
extern crate tracing;

use futures::StreamExt;
use tracing_subscriber::EnvFilter;

use librice::agent::*;
use librice::socket::*;
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

fn handle_stun_or_data(stun_or_data: StunOrData) -> Option<(Message, SocketAddr)> {
    match stun_or_data {
        StunOrData::Data(data, from) => info!("received from {} data: {:?}", from, data),
        StunOrData::Stun(msg, _data, from) => {
            info!("received from {}: {}", from, msg);
            if msg.has_class(MessageClass::Request) && msg.has_method(BINDING) {
                match handle_binding_request(&msg, from) {
                    Ok(response) => {
                        info!("sending response to {}: {}", from, response);
                        return Some((response, from));
                    }
                    Err(err) => warn!("error: {}", err),
                }
            } else {
                let mut response = Message::new_error(&msg);
                response
                    .add_attribute(ErrorCode::new(400, "Bad Request").unwrap())
                    .unwrap();
                return Some((response, from));
            }
        }
    }
    None
}

fn main() -> io::Result<()> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    task::block_on(async move {
        let udp_socket = UdpSocket::bind("127.0.0.1:3478").await?;
        let udp_channel = StunChannel::UdpAny(UdpSocketChannel::new(udp_socket));
        let udp_stun_agent = StunAgent::new(udp_channel);
        let mut receive_stream = udp_stun_agent.receive_stream();

        task::spawn(async move {
            while let Some(stun_or_data) = receive_stream.next().await {
                if let Some((response, to)) = handle_stun_or_data(stun_or_data) {
                    warn_on_err(udp_stun_agent.send_to(response, to).await, ());
                }
            }
        });

        let tcp_listener = TcpListener::bind("127.0.0.1:3478").await?;
        let mut incoming = tcp_listener.incoming();
        while let Some(Ok(stream)) = incoming.next().await {
            let tcp_channel = StunChannel::Tcp(TcpChannel::new(stream));
            let tcp_stun_agent = StunAgent::new(tcp_channel);
            let mut receive_stream = tcp_stun_agent.receive_stream();

            task::spawn(async move {
                while let Some(stun_or_data) = receive_stream.next().await {
                    if let Some((response, _to)) = handle_stun_or_data(stun_or_data) {
                        warn_on_err(tcp_stun_agent.send(response).await, ());
                    }
                }
            });
        }

        Ok(())
    })
}
