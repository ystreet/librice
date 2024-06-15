// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt::Display;
use std::net::SocketAddr;

use async_std::io::{self, WriteExt};
use async_std::net::{TcpListener, UdpSocket};
use async_std::task;

#[macro_use]
extern crate tracing;

use futures::{AsyncReadExt, StreamExt};
use tracing_subscriber::EnvFilter;

use librice::stun::message::*;
use librice::stun::{attribute::*, StunError};

use librice_proto::stun::agent::{HandleStunReply, StunAgent};

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

fn handle_binding_request(msg: &Message, from: SocketAddr) -> Result<Message, StunError> {
    if let Some(error_msg) = Message::check_attribute_types(msg, &[FINGERPRINT], &[]) {
        return Ok(error_msg);
    }

    let mut response = Message::new_success(msg);
    response.add_attribute(XorMappedAddress::new(from, msg.transaction_id()))?;
    response.add_fingerprint()?;
    Ok(response)
}

fn handle_stun_or_data(stun_or_data: HandleStunReply) -> Option<(Message, SocketAddr)> {
    match stun_or_data {
        HandleStunReply::Ignore => None,
        HandleStunReply::Data(data, from) => {
            info!("received from {} data: {:?}", from, data);
            None
        }
        HandleStunReply::Stun(msg, from) => {
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
            None
        }
    }
}

fn main() -> io::Result<()> {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    task::block_on(async move {
        let local_addr = "127.0.0.1:3478".parse().unwrap();
        let udp_task = task::spawn(async move {
            let udp_socket = UdpSocket::bind(local_addr).await.unwrap();
            let udp_stun_agent =
                StunAgent::builder(librice_proto::stun::TransportType::Udp, local_addr).build();

            loop {
                let mut data = vec![0; 1500];
                let (len, from) =
                    warn_on_err(udp_socket.recv_from(&mut data).await, (0, local_addr));
                data.truncate(len);
                let replies = udp_stun_agent.handle_incoming_data(&data, from).unwrap();
                for reply in replies {
                    if let Some((response, to)) = handle_stun_or_data(reply) {
                        warn_on_err(udp_socket.send_to(&response.to_bytes(), to).await, 0);
                    }
                }
            }
        });

        let tcp_listener = TcpListener::bind(local_addr).await?;
        let mut incoming = tcp_listener.incoming();
        while let Some(Ok(mut stream)) = incoming.next().await {
            task::spawn(async move {
                let remote_addr = stream.peer_addr().unwrap();
                let tcp_stun_agent =
                    StunAgent::builder(librice_proto::stun::TransportType::Tcp, local_addr)
                        .remote_addr(remote_addr)
                        .build();
                loop {
                    let mut data = vec![0; 1500];
                    let size = warn_on_err(stream.read(&mut data).await, 0);
                    if size == 0 {
                        debug!("TCP connection with {remote_addr} closed");
                        break;
                    }
                    data.truncate(size);
                    let replies = tcp_stun_agent
                        .handle_incoming_data(&data, remote_addr)
                        .unwrap();
                    for reply in replies {
                        if let Some((response, to)) = handle_stun_or_data(reply) {
                            if let Ok(data) = tcp_stun_agent.send(response, to) {
                                warn_on_err(stream.write_all(&data.data).await, ());
                            }
                        }
                    }
                    // XXX: Assumes that the stun packet arrives in a single packet
                    stream.shutdown(std::net::Shutdown::Read).unwrap();
                }
            });
        }

        udp_task.cancel().await;

        Ok(())
    })
}