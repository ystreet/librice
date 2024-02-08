// Copyright (C) 2023 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A STUN Agent

use std::net::SocketAddr;

use crate::socket::StunChannel;

use librice_proto::stun::TransportType;

pub use librice_proto::stun::agent::StunError;
pub use librice_proto::stun::attribute;
pub use librice_proto::stun::message;

/// A STUN Agent
#[derive(Debug)]
pub struct StunAgent {
    agent: librice_proto::stun::agent::StunAgent,
    channel: StunChannel,
}

impl StunAgent {
    /// Create a new STUN Agent from an existing socket
    pub fn new(channel: StunChannel) -> Result<Self, std::io::Error> {
        let internal = librice_proto::stun::agent::StunAgent::builder(
            channel.transport(),
            channel.local_addr()?,
        )
        .build();
        Ok(Self {
            agent: internal,
            channel,
        })
    }
/*
    pub(crate) async fn stun_request_transaction(
        &self,
        msg: &Message,
        to: SocketAddr,
    ) -> Result<Message, AgentError> {
        let request = self.agent.stun_request_transaction(msg, to)?.build()?;
        let mut now = Instant::now();
        loop {
            match request.tick(now)? {
                StunRequestPollRet::WaitUntil(new_time) => {
                    // need external wakeup when message received
                    async_std::task::sleep(new_time - now).await;
                    now = Instant::now();
                }
                StunRequestPollRet::Cancelled => return Err(AgentError::ConnectionClosed),
                StunRequestPollRet::Response(response) => return Ok(response),
                StunRequestPollRet::SendData(transmit) => {
                    self.channel.send_to(&transmit.data, transmit.to).await?;
                }
            }
        }
    }
*/
    /// The [`TransportType`] of this agent
    pub fn transport(&self) -> TransportType {
        self.channel.transport()
    }

    /// The local address of this agent
    pub fn local_addr(&self) -> SocketAddr {
        self.channel.local_addr().unwrap()
    }

    /// Send data to the specified peer
    pub async fn send_data(&self, data: &[u8], to: SocketAddr) -> Result<(), StunError> {
        let transmit = self.agent.send_data(data, to);
        Ok(self.channel.send_to(&transmit.data, transmit.to).await?)
    }
}
