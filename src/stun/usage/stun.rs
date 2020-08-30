// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;

use crate::stun::attribute::{Attribute, AttributeType, UnknownAttributes, ErrorCode, Software};
use crate::stun::attribute::{MAPPED_ADDRESS, USERNAME, MESSAGE_INTEGRITY, ERROR_CODE, UNKNOWN_ATTRIBUTES, REALM, NONCE, XOR_MAPPED_ADDRESS, SOFTWARE, ALTERNATE_SERVER, FINGERPRINT};
use crate::stun::message::{Message, MessageType, MessageClass};
use crate::stun::message::{BINDING};
use crate::agent::AgentError;
use crate::stun::usage::Usage;

#[derive(Debug)]
pub struct StunUsage {
    to_send: Vec<(Message, SocketAddr)>,     // messages that need to be sent
    outstanding_requests: Vec<SentMessage>,      // requests that have been sent but not answered
}

#[derive(Debug)]
struct SentMessage {
    msg: Message,
    to: SocketAddr,
    initial_ts: u64,
    retransmission_count: u64,
    last_transmission_time: u64,
}

impl StunUsage {
    pub fn new() -> Self {
        Self {
            to_send: vec![],
            outstanding_requests: vec![],
        }
    }

    fn take_outstanding_transaction (&mut self, transaction: u128) -> Option<SentMessage> {
        if let Some(pos) = self.outstanding_requests.iter()
                    .position(|sent| sent.msg.transaction_id() == transaction) {
            Some(self.outstanding_requests.swap_remove(pos))
        } else {
            None
        }
    }

    fn handle_request(&mut self, msg: &Message, addr: &SocketAddr) -> Result<(),AgentError> {
        if false {
        } else {
            let mtype = MessageType::from_class_method(
                    MessageClass::Error, msg.get_type().method());
            let mut out = Message::new(mtype, msg.transaction_id());
            out.add_attribute(Software::new("librice v0.1")?.to_raw())?;
            out.add_attribute(ErrorCode::new(400, "Bad Request")?.to_raw())?;
            let attr_types = msg.iter_attributes()
                    .map(|a| a.get_type()).collect::<Vec<_>>();
            if attr_types.len() > 0 {
                 out.add_attribute(UnknownAttributes::new(&attr_types)
                        .to_raw()).unwrap();
            }
            self.to_send.push((out, *addr));
        }
        Ok(())
    }

    fn handle_indication(&mut self, msg: &Message, addr: &SocketAddr) -> Result<(),AgentError> {
        Ok(())
    }

    pub fn take_messages_to_send(&mut self) -> Vec<(Message, SocketAddr)> {
        std::mem::replace(&mut self.to_send, Vec::new())
    }
}

impl Usage for StunUsage {
    fn supported_message_types (&self) -> &[u16] {
        &[BINDING]
    }

    fn supported_attribute_types (&self) -> &[AttributeType] {
        &[MAPPED_ADDRESS, USERNAME, MESSAGE_INTEGRITY, ERROR_CODE, UNKNOWN_ATTRIBUTES, REALM, NONCE, XOR_MAPPED_ADDRESS, SOFTWARE, ALTERNATE_SERVER, FINGERPRINT]
    }

    fn attribute_valid_for_message(&self, mtype: MessageType, atype: AttributeType) -> bool {
        match atype {
            MAPPED_ADDRESS => true,
            XOR_MAPPED_ADDRESS => true,
            USERNAME => true,
            MESSAGE_INTEGRITY => true,
            FINGERPRINT => true,
            ERROR_CODE => mtype.class() == MessageClass::Error,
            REALM => true,
            NONCE => true,
            UNKNOWN_ATTRIBUTES => mtype.class() == MessageClass::Error,
            SOFTWARE => true,
            ALTERNATE_SERVER => true,
            _ => false,
        }
    }

    fn received_message (&mut self, msg: &Message, addr: &SocketAddr) -> Result<(),AgentError> {
        if msg.get_type().class().is_response() {
            if let Some(outstanding) = self.take_outstanding_transaction(msg.transaction_id()) {
            } else {
                /* ok response or return NotStun depending on multiplexing */
                return Err(AgentError::NotStun);
            }
        } else if msg.get_type().class() == MessageClass::Request {
            self.handle_request(msg, addr)?;
        } else if msg.get_type().class() == MessageClass::Indication {
            self.handle_indication(msg, addr)?;
        } else {
            // message class is not known
            return Err(AgentError::Malformed);
        }
        Ok(())
    }

    fn send_message(&mut self, msg: &Message, addr: &SocketAddr) {
        if msg.get_type().class() == MessageClass::Request {
            trace!("Pushing onto outstanding list {:?}", msg);
            self.outstanding_requests.push(SentMessage {
                msg: msg.clone(),
                to: *addr,
                initial_ts: 0,
                retransmission_count: 0,
                last_transmission_time: 0,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn received_response_produced_error() {
        init();
        let mut usage = StunUsage::new();
        let msg = Message::new(MessageType::from_class_method(MessageClass::Request, BINDING), Message::generate_transaction());
        usage.received_message (&msg, &"127.0.0.1:1000".parse().unwrap());
        let sent = usage.take_messages_to_send();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.get_type().class(), MessageClass::Error);
        assert_eq!(sent[0].0.transaction_id(), msg.transaction_id());
    }
}
