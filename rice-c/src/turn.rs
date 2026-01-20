// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TURN module.

use crate::candidate::TransportType;
use crate::{AddressFamily, const_override};

pub use crate::stream::Credentials as TurnCredentials;

/// Configuration for a particular TURN server connection.
#[derive(Debug)]
pub struct TurnConfig {
    ffi: *mut crate::ffi::RiceTurnConfig,
}

unsafe impl Send for TurnConfig {}

impl TurnConfig {
    /// Create a new [`TurnConfig`] from the provided details.
    ///
    /// # Examples
    /// ```
    /// # use rice_c::AddressFamily;
    /// # use rice_c::turn::{TurnConfig, TurnCredentials};
    /// # use rice_c::candidate::TransportType;
    /// # use core::net::SocketAddr;
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let server_addr = rice_c::Address::from("127.0.0.1:3478".parse::<SocketAddr>().unwrap());
    /// let config = TurnConfig::new(
    ///     TransportType::Udp,
    ///     server_addr.clone(),
    ///     credentials.clone(),
    ///     TransportType::Udp,
    ///     &[AddressFamily::IPV4],
    ///     None,
    /// );
    /// assert_eq!(config.client_transport(), TransportType::Udp);
    /// assert_eq!(config.addr(), server_addr);
    /// // FIXME
    /// //assert_eq!(config.credentials().username(), credentials.username());
    /// ```
    pub fn new(
        client_transport: TransportType,
        turn_server: crate::Address,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        families: &[AddressFamily],
        tls_config: Option<TurnTlsConfig>,
    ) -> Self {
        unsafe {
            let tls_config = if let Some(tls_config) = tls_config {
                tls_config.into_c_full()
            } else {
                core::ptr::null_mut()
            };
            let families = families
                .iter()
                .map(|&family| family as u32)
                .collect::<Vec<_>>();
            let ffi = crate::ffi::rice_turn_config_new(
                client_transport.into(),
                const_override(turn_server.as_c()),
                credentials.into_c_none(),
                allocation_transport.into(),
                families.len(),
                families.as_ptr(),
                tls_config,
            );
            Self { ffi }
        }
    }

    /// The TLS configuration to use for connecting to this TURN server.
    pub fn tls_config(&self) -> Option<TurnTlsConfig> {
        unsafe {
            let ret = crate::ffi::rice_turn_config_get_tls_config(self.ffi);
            if ret.is_null() {
                None
            } else {
                match crate::ffi::rice_tls_config_variant(ret) {
                    #[cfg(feature = "openssl")]
                    crate::ffi::RICE_TLS_VARIANT_OPENSSL => Some(TurnTlsConfig::Openssl(ret)),
                    #[cfg(feature = "rustls")]
                    crate::ffi::RICE_TLS_VARIANT_RUSTLS => Some(TurnTlsConfig::Rustls(ret)),
                    _ => None,
                }
            }
        }
    }

    /// The TURN server address to connect to.
    pub fn addr(&self) -> crate::Address {
        unsafe { crate::Address::from_c_full(crate::ffi::rice_turn_config_get_addr(self.ffi)) }
    }

    /// The [`TransportType`] between the client and the TURN server.
    pub fn client_transport(&self) -> TransportType {
        unsafe { crate::ffi::rice_turn_config_get_client_transport(self.ffi).into() }
    }

    /// The credentials for accessing the TURN server.
    pub fn credentials(&self) -> TurnCredentials {
        unsafe {
            TurnCredentials::from_c_full(crate::ffi::rice_turn_config_get_credentials(self.ffi))
        }
    }

    pub(crate) fn into_c_full(self) -> *mut crate::ffi::RiceTurnConfig {
        let ret = self.ffi;
        core::mem::forget(self);
        ret
    }
}

impl Clone for TurnConfig {
    fn clone(&self) -> Self {
        unsafe {
            Self {
                ffi: crate::ffi::rice_turn_config_ref(self.ffi),
            }
        }
    }
}

impl Drop for TurnConfig {
    fn drop(&mut self) {
        unsafe {
            crate::ffi::rice_turn_config_unref(self.ffi);
        }
    }
}

/// Configuration parameters for TURN use over (D)TLS.
#[derive(Debug)]
pub enum TurnTlsConfig {
    /// Rustls variant for TLS configuration.
    #[cfg(feature = "rustls")]
    Rustls(*mut crate::ffi::RiceTlsConfig),
    /// Openssl variant for TLS configuration.
    #[cfg(feature = "openssl")]
    Openssl(*mut crate::ffi::RiceTlsConfig),
}

impl Clone for TurnTlsConfig {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "rustls")]
            Self::Rustls(cfg) => unsafe { Self::Rustls(crate::ffi::rice_tls_config_ref(*cfg)) },
            #[cfg(feature = "openssl")]
            Self::Openssl(cfg) => unsafe { Self::Openssl(crate::ffi::rice_tls_config_ref(*cfg)) },
        }
    }
}

impl Drop for TurnTlsConfig {
    fn drop(&mut self) {
        match self {
            #[cfg(feature = "rustls")]
            Self::Rustls(cfg) => unsafe { crate::ffi::rice_tls_config_unref(*cfg) },
            #[cfg(feature = "openssl")]
            Self::Openssl(cfg) => unsafe { crate::ffi::rice_tls_config_unref(*cfg) },
        }
    }
}

impl TurnTlsConfig {
    /// Construct a new client Rustls TLS configuration with the specified server name.
    #[cfg(feature = "rustls")]
    pub fn new_rustls_with_dns(server_name: &str) -> Self {
        let server_str = std::ffi::CString::new(server_name).unwrap();
        unsafe {
            Self::Rustls(crate::ffi::rice_tls_config_new_rustls_with_dns(
                server_str.as_ptr(),
            ))
        }
    }

    /// Construct a new client Rustls TLS configuration with the specified ip.
    #[cfg(feature = "rustls")]
    pub fn new_rustls_with_ip(addr: &crate::Address) -> Self {
        unsafe { Self::Rustls(crate::ffi::rice_tls_config_new_rustls_with_ip(addr.as_c())) }
    }

    /// Construct a new client OpenSSL TLS configuration with the specified transport.
    #[cfg(feature = "openssl")]
    pub fn new_openssl(transport: TransportType) -> Self {
        unsafe { Self::Openssl(crate::ffi::rice_tls_config_new_openssl(transport.into())) }
    }

    pub(crate) fn into_c_full(self) -> *mut crate::ffi::RiceTlsConfig {
        #[allow(unreachable_patterns)]
        let ret = match self {
            #[cfg(feature = "rustls")]
            Self::Rustls(cfg) => cfg,
            #[cfg(feature = "openssl")]
            Self::Openssl(cfg) => cfg,
            _ => core::ptr::null_mut(),
        };
        core::mem::forget(self);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::net::SocketAddr;

    fn turn_server_address() -> crate::Address {
        "127.0.0.1:3478".parse::<SocketAddr>().unwrap().into()
    }

    fn turn_credentials() -> TurnCredentials {
        TurnCredentials::new("tuser", "tpass")
    }

    #[test]
    fn test_config_getter() {
        let cfg = TurnConfig::new(
            TransportType::Udp,
            turn_server_address(),
            turn_credentials(),
            TransportType::Udp,
            &[AddressFamily::IPV4],
            None,
        );
        assert_eq!(cfg.addr(), turn_server_address());
        assert_eq!(cfg.client_transport(), TransportType::Udp);
        // TODO credentials
        //assert_eq!(cfg.credentials().username(), turn_credentials().username());
        assert!(cfg.tls_config().is_none());
    }

    #[cfg(feature = "rustls")]
    mod rustls {
        use super::*;
        #[test]
        fn test_rustls_roundtrip() {
            let dns = "turn.example.com";
            let cfg = TurnTlsConfig::new_rustls_with_dns(dns);
            drop(cfg);
            let addr = "127.0.0.1:3478".parse::<SocketAddr>().unwrap();
            let _cfg = TurnTlsConfig::new_rustls_with_ip(&addr.into());
        }

        #[test]
        fn test_rustls_getter() {
            let dns = "turn.example.com";
            let tls = TurnTlsConfig::new_rustls_with_dns(dns);
            let cfg = TurnConfig::new(
                TransportType::Tcp,
                turn_server_address(),
                turn_credentials(),
                TransportType::Udp,
                &[AddressFamily::IPV4],
                Some(tls.clone()),
            );
            let retrieved = cfg.tls_config().unwrap();
            assert!(matches!(retrieved, TurnTlsConfig::Rustls(_)));
        }
    }

    #[cfg(feature = "openssl")]
    mod openssl {
        use super::*;
        #[test]
        fn test_openssl_roundtrip() {
            let _cfg = TurnTlsConfig::new_openssl(TransportType::Udp);
        }

        #[test]
        fn test_openssl_getter() {
            let tls = TurnTlsConfig::new_openssl(TransportType::Udp);
            let cfg = TurnConfig::new(
                TransportType::Udp,
                turn_server_address(),
                turn_credentials(),
                TransportType::Udp,
                &[AddressFamily::IPV4],
                Some(tls),
            );
            let retrieved = cfg.tls_config().unwrap();
            assert!(matches!(retrieved, TurnTlsConfig::Openssl(_)));
        }
    }
}
