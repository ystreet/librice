// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;

use crate::stun::attribute::AttributeType;
use crate::stun::message::{Message, MessageType};
use crate::agent::AgentError;

pub mod stun;

pub trait Usage {
    fn supported_message_types(&self) -> &[u16];
    fn supported_attribute_types (&self) -> &[AttributeType];

    fn attribute_valid_for_message(&self, mtype: MessageType, atype: AttributeType) -> bool;

    fn received_data(&mut self, data: &[u8], addr: &SocketAddr) -> Result<Message,AgentError> {
        Message::from_bytes(data)
    }

    fn received_message(&mut self, msg: &Message, addr: &SocketAddr) -> Result<(),AgentError>;

    fn write_message(&mut self, msg: &Message) -> Result<Vec<u8>,AgentError> {
        Ok(msg.to_bytes())
    }

    fn send_message(&mut self, msg: &Message, to: &SocketAddr);
}
