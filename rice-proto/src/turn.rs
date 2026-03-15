// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TURN module.

use core::net::SocketAddr;
pub use stun_proto::auth::Feature;
use stun_proto::types::{AddressFamily, message::IntegrityAlgorithm};

use crate::candidate::TransportType;

pub use turn_client_proto::types::TurnCredentials;

/// Configuration for a particular TURN server connection.
#[derive(Debug, Clone)]
pub struct TurnConfig {
    turn_config: turn_client_proto::api::TurnConfig,
    client_transport: TransportType,
    turn_server: SocketAddr,
    tls_config: Option<TurnTlsConfig>,
}

impl TurnConfig {
    /// Create a new [`TurnConfig`] from the provided details.
    ///
    /// # Examples
    /// ```
    /// # use rice_proto::AddressFamily;
    /// # use rice_proto::turn::{TurnConfig, TurnCredentials};
    /// # use rice_proto::candidate::TransportType;
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let server_addr = "127.0.0.1:3478".parse().unwrap();
    /// let families = [AddressFamily::IPV4];
    /// let config = TurnConfig::new(
    ///     TransportType::Udp,
    ///     server_addr,
    ///     credentials.clone(),
    /// );
    /// assert_eq!(config.client_transport(), TransportType::Udp);
    /// assert_eq!(config.addr(), server_addr);
    /// assert_eq!(config.credentials().username(), credentials.username());
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// assert_eq!(config.allocation_transport(), TransportType::Udp);
    /// ```
    pub fn new(
        client_transport: TransportType,
        server_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> Self {
        Self {
            turn_config: turn_client_proto::api::TurnConfig::new(credentials),
            client_transport,
            turn_server: server_addr,
            tls_config: None,
        }
    }

    /// Connect to the TURN server over TLS.
    pub fn with_tls_config(mut self, config: TurnTlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// The TLS configuration to use for connecting to this TURN server.
    pub fn tls_config(&self) -> Option<&TurnTlsConfig> {
        self.tls_config.as_ref()
    }

    /// The TURN server address to connect to.
    pub fn addr(&self) -> SocketAddr {
        self.turn_server
    }

    /// The [`TransportType`] between the client and the TURN server.
    pub fn client_transport(&self) -> TransportType {
        self.client_transport
    }

    /// Set the allocation transport requested.
    pub fn set_allocation_transport(&mut self, allocation_transport: TransportType) {
        self.turn_config
            .set_allocation_transport(allocation_transport);
    }

    /// Retrieve the allocation transport requested.
    pub fn allocation_transport(&self) -> TransportType {
        self.turn_config.allocation_transport()
    }

    /// Add an [`AddressFamily`] that will be requested.
    ///
    /// Duplicate [`AddressFamily`]s are ignored.
    pub fn add_address_family(&mut self, family: AddressFamily) {
        self.turn_config.add_address_family(family);
    }

    /// Set the [`AddressFamily`] that will be requested.
    ///
    pub fn set_address_family(&mut self, family: AddressFamily) {
        self.turn_config.set_address_family(family);
    }

    /// Retrieve the [`AddressFamily`]s that are requested.
    pub fn address_families(&self) -> &[AddressFamily] {
        self.turn_config.address_families()
    }

    /// Retrieve the [`TurnCredentials`] used for authenticating with the TURN server.
    pub fn credentials(&self) -> &TurnCredentials {
        self.turn_config.credentials()
    }

    /// Add a supported integrity algorithm that could be used.
    pub fn add_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        self.turn_config.add_supported_integrity(integrity);
    }

    /// Set the supported integrity algorithm used.
    pub fn set_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        self.turn_config.set_supported_integrity(integrity);
    }

    /// The supported integrity algorithms used.
    pub fn supported_integrity(&self) -> &[IntegrityAlgorithm] {
        self.turn_config.supported_integrity()
    }

    /// Set whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the `Userhash` attribute.
    pub fn set_anonymous_username(&mut self, anon: Feature) {
        self.turn_config.set_anonymous_username(anon);
    }

    /// Whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the `Userhash` attribute.
    pub fn anonymous_username(&self) -> Feature {
        self.turn_config.anonymous_username()
    }

    pub(crate) fn turn_config(&self) -> &turn_client_proto::api::TurnConfig {
        &self.turn_config
    }
}

/// Configuration parameters for TURN use over (D)TLS.
#[derive(Debug, Clone)]
pub enum TurnTlsConfig {
    /// Rustls variant for TLS configuration.
    #[cfg(feature = "rustls")]
    Rustls(RustlsTurnConfig),
    /// Openssl variant for TLS configuration.
    #[cfg(feature = "openssl")]
    Openssl(OpensslTurnConfig),
}

#[cfg(feature = "rustls")]
use alloc::sync::Arc;
#[cfg(feature = "rustls")]
use rustls::{ClientConfig, pki_types::ServerName};

/// Configuration parameters for TURN use over TLS with Rustls.
#[cfg(feature = "rustls")]
#[derive(Debug, Clone)]
pub struct RustlsTurnConfig {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

#[cfg(feature = "rustls")]
impl RustlsTurnConfig {
    /// Create a new [`RustlsTurnConfig`] for TURN over TLS with Rustls.
    pub fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Self {
        Self {
            config,
            server_name,
        }
    }

    /// The Rustls `ClientConfig` for the TURN connection.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        self.config.clone()
    }

    /// The server name to validate the TURN server with.
    pub fn server_name(&self) -> ServerName<'static> {
        self.server_name.clone()
    }
}

#[cfg(feature = "rustls")]
impl From<RustlsTurnConfig> for TurnTlsConfig {
    fn from(value: RustlsTurnConfig) -> Self {
        Self::Rustls(value)
    }
}

/// Configuration parameters for TURN use over TLS with OpenSSL.
#[cfg(feature = "openssl")]
#[derive(Debug, Clone)]
pub struct OpensslTurnConfig {
    ssl: openssl::ssl::SslContext,
}

#[cfg(feature = "openssl")]
impl OpensslTurnConfig {
    /// Create a new [`RustlsTurnConfig`] for TURN over TLS with OpenSSL.
    pub fn new(ssl: openssl::ssl::SslContext) -> Self {
        Self { ssl }
    }

    /// The OpenSSL `SslContext` for the TURN connection.
    pub fn ssl_context(&self) -> &openssl::ssl::SslContext {
        &self.ssl
    }
}

#[cfg(feature = "openssl")]
impl From<OpensslTurnConfig> for TurnTlsConfig {
    fn from(value: OpensslTurnConfig) -> Self {
        Self::Openssl(value)
    }
}
