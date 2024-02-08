// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;
use std::time::Duration;

use crate::stun::agent::StunAgent;
use crate::stun::agent::StunError;
use crate::stun::attribute::*;
use crate::stun::message::*;
use crate::turn::attribute::*;
use crate::turn::message::*;

#[derive(Debug, Clone)]
pub struct TurnCredentials {
    username: String,
    password: String,
}

impl TurnCredentials {
    fn into_long_term_credentials(self, realm: &str) -> LongTermCredentials {
        LongTermCredentials { username: self.username, password: self.password, realm: realm.to_string() }
    }
}

impl TurnCredentials {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TurnAgent {
    stun_agent: StunAgent,
    relayed_address: SocketAddr,
    lifetime: Duration,
}

impl TurnAgent {
    #[tracing::instrument(
        name = "turn_agent_allocate"
        skip(channel, turn_credentials)
        fields(
            local_addr = ?channel.local_addr(),
            remote_addr = ?channel.remote_addr(),
        )
    )]
    pub async fn allocate(channel: StunChannel, turn_credentials: TurnCredentials) -> Result<Self,StunError> {
        let remote_addr = channel.remote_addr()?;
        let stun_agent = StunAgent::new(channel);
        let mut msg = Message::new_request(ALLOCATE);
        msg.add_attribute(Lifetime::new(3600)).unwrap();
        msg.add_attribute(RequestedTransport::new(RequestedTransport::UDP)).unwrap();
        msg.add_attribute(DontFragment::new()).unwrap();

        let request = stun_agent.stun_request_transaction(&msg.clone(), remote_addr)?.build()?;
        let (response, from) = request.perform().await?;
        if from != remote_addr {
            error!("turn reply from different address than sent");
            return Err(StunError::Failed);
        }
        request.cancel();
        if !response.has_class(MessageClass::Error) {
            return Err(StunError::ProtocolViolation);
        }
        let error_code = response.attribute::<ErrorCode>(ERROR_CODE).ok_or(StunError::ResourceNotFound)?;
        if error_code.code() != ErrorCode::UNAUTHORIZED {
            return Err(StunError::ProtocolViolation);
        }
        let realm = response.attribute::<Realm>(REALM).ok_or(StunError::ResourceNotFound)?;
        let nonce = response.attribute::<Nonce>(NONCE).ok_or(StunError::ResourceNotFound)?;
        let password_algorithms = response.attribute::<PasswordAlgorithms>(PASSWORD_ALGORITHMS).unwrap_or_else(|| PasswordAlgorithms::new(&[PasswordAlgorithmValue::MD5]));

        let mut msg = Message::new_request(ALLOCATE);
        msg.add_attribute(Lifetime::new(3600)).unwrap();
        msg.add_attribute(RequestedTransport::new(RequestedTransport::UDP)).unwrap();
        msg.add_attribute(DontFragment::new()).unwrap();

        msg.add_attribute(Username::new(&turn_credentials.username)?)?;
        let turn_stun_credentials = MessageIntegrityCredentials::LongTerm(turn_credentials.into_long_term_credentials(realm.realm()));
        msg.add_attribute(realm)?;
        // TODO parse nonce for stun feature bits
        msg.add_attribute(nonce)?;
//        let known_supported_algos: Vec<_> = password_algorithms.algorithms().iter().cloned().filter(|&algo| algo == PasswordAlgorithmValue::MD5 || algo == PasswordAlgorithmValue::SHA256).collect();
//        msg.add_attribute(PasswordAlgorithms::new(&known_supported_algos))?;
        msg.add_message_integrity(&turn_stun_credentials, IntegrityAlgorithm::Sha1)?;
//        msg.add_message_integrity(&turn_stun_credentials, IntegrityAlgorithm::Sha256)?;
        msg.add_fingerprint()?;
        stun_agent.set_local_credentials(turn_stun_credentials.clone());
        stun_agent.set_remote_credentials(turn_stun_credentials.clone());

        let request = stun_agent.stun_request_transaction(&msg, remote_addr)?.build()?;
        let (response, from) = request.perform().await?;
        if from != remote_addr {
            error!("turn reply from different address than sent");
            return Err(StunError::Failed);
        }

        if response.has_class(MessageClass::Error) {
            // TODO: some errors are non-fatal
            return Err(StunError::Failed);
        }
        if !response.has_class(MessageClass::Success) {
            // TODO: some errors are non-fatal
            return Err(StunError::Failed);
        }

        let relayed_address = response.attribute::<XorRelayedAddress>(XOR_RELAYED_ADDRESS).ok_or(StunError::ProtocolViolation)?.addr(response.transaction_id());
        let mapped_address = response.attribute::<XorMappedAddress>(XOR_MAPPED_ADDRESS).map(|attr| attr.addr(response.transaction_id()));
        // do things with lifetime
        let lifetime = Duration::from_secs(response.attribute::<Lifetime>(LIFETIME).map(|attr| attr.seconds()).unwrap_or(3600) as u64);

        Ok(Self {
            stun_agent,
            relayed_address,
            lifetime,
        })
    }

    pub fn relayed_address(&self) -> SocketAddr {
        self.relayed_address
    }

    pub async fn send_data_to(&self, bytes: &[u8], to: SocketAddr) -> Result<(), std::io::Error> {
        // TODO: wrap in relevant STUN message
        self.stun_agent.send_data_to(bytes, to).await
    }
}

#[cfg(test)]
mod tests {
/*
    use async_std::net::UdpSocket;

    use crate::stun::socket::{UdpConnectionChannel, UdpSocketChannel};

    use super::*;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn test_turn_allocate() {
        init();
        async_std::task::block_on(async move {
            let credentials = TurnCredentials::new("coturn", "coturn");
            let addr = "127.0.0.1:3478".parse().unwrap();
            let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let socket = UdpSocket::bind(bind_addr).await.unwrap();
            let channel = StunChannel::Udp(UdpConnectionChannel::new(UdpSocketChannel::new(socket), addr));
            let agent = TurnAgent::allocate(channel, credentials).await.unwrap();
            info!("relayed address: {:?}", agent.relayed_address());
        });
    }
*/
}
