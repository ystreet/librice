// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TURN module.

use core::net::SocketAddr;
use stun_proto::types::AddressFamily;

use crate::candidate::TransportType;

pub use turn_client_proto::types::TurnCredentials;

/// Configuration for a particular TURN server connection.
#[derive(Debug, Clone)]
pub struct TurnConfig {
    client_transport: TransportType,
    turn_server: SocketAddr,
    credentials: TurnCredentials,
    families: smallvec::SmallVec<[AddressFamily; 2]>,
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
    ///     &families
    /// );
    /// assert_eq!(config.client_transport(), TransportType::Udp);
    /// assert_eq!(config.addr(), server_addr);
    /// assert_eq!(config.credentials().username(), credentials.username());
    /// assert_eq!(config.families(), families);
    /// ```
    pub fn new(
        client_transport: TransportType,
        server_addr: SocketAddr,
        credentials: TurnCredentials,
        families: &[AddressFamily],
    ) -> Self {
        Self {
            client_transport,
            turn_server: server_addr,
            credentials,
            families: families.into(),
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

    /// The credentials for accessing the TURN server.
    pub fn credentials(&self) -> &TurnCredentials {
        &self.credentials
    }

    /// The address family to allocate on the TURN server.
    pub fn families(&self) -> &[AddressFamily] {
        &self.families
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
use rustls::{pki_types::ServerName, ClientConfig};

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
