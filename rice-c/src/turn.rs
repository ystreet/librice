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

use crate::candidate::TransportType;
use crate::{AddressFamily, Feature, IntegrityAlgorithm, const_override};

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
    ) -> Self {
        unsafe {
            let ffi = crate::ffi::rice_turn_config_new(
                client_transport.into(),
                const_override(turn_server.as_c()),
                credentials.into_c_none(),
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

    /// The TLS configuration to use for connecting to this TURN server.
    pub fn set_tls_config(&mut self, tls_config: TurnTlsConfig) {
        unsafe {
            crate::ffi::rice_turn_config_set_tls_config(self.ffi, tls_config.as_c());
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

    /// Set the allocation transport requested from the TURN server.
    pub fn set_allocation_transport(&mut self, allocation_transport: TransportType) {
        unsafe {
            crate::ffi::rice_turn_config_set_allocation_transport(
                self.ffi,
                allocation_transport.into(),
            );
        }
    }

    /// Retrieve the allocation transport requested.
    pub fn allocation_transport(&self) -> TransportType {
        unsafe { crate::ffi::rice_turn_config_get_allocation_transport(self.ffi).into() }
    }

    /// Add an [`AddressFamily`] that will be requested.
    ///
    /// Duplicate [`AddressFamily`]s are ignored.
    pub fn add_address_family(&mut self, family: AddressFamily) {
        unsafe {
            crate::ffi::rice_turn_config_add_address_family(self.ffi, family.into());
        }
    }

    /// Set the [`AddressFamily`] that will be requested.
    ///
    /// This will override all previously set [`AddressFamily`]s.
    pub fn set_address_family(&mut self, family: AddressFamily) {
        unsafe {
            crate::ffi::rice_turn_config_set_address_family(self.ffi, family.into());
        }
    }

    /// Retrieve the [`AddressFamily`]s that are requested.
    pub fn address_families(&self) -> Vec<AddressFamily> {
        unsafe {
            let mut len = 0;
            crate::ffi::rice_turn_config_get_address_families(
                self.ffi,
                &mut len,
                core::ptr::null_mut(),
            );
            let mut ret = vec![AddressFamily::IPV4; len];
            crate::ffi::rice_turn_config_get_address_families(
                self.ffi,
                &mut len,
                ret.as_mut_ptr() as _,
            );
            ret.resize(len, AddressFamily::IPV4);
            ret
        }
    }

    /// The credentials for accessing the TURN server.
    pub fn credentials(&self) -> TurnCredentials {
        unsafe {
            TurnCredentials::from_c_full(crate::ffi::rice_turn_config_get_credentials(self.ffi))
        }
    }

    /// Add a supported integrity algorithm that could be used.
    pub fn add_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        unsafe {
            crate::ffi::rice_turn_config_add_supported_integrity(self.ffi, integrity.into());
        }
    }

    /// Set the supported integrity algorithm used.
    pub fn set_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        unsafe {
            crate::ffi::rice_turn_config_set_supported_integrity(self.ffi, integrity.into());
        }
    }

    /// The supported integrity algorithms used.
    pub fn supported_integrity(&self) -> Vec<IntegrityAlgorithm> {
        unsafe {
            let mut len = 0;
            crate::ffi::rice_turn_config_get_supported_integrity(
                self.ffi,
                &mut len,
                core::ptr::null_mut(),
            );
            let mut ret = vec![IntegrityAlgorithm::Sha1; len];
            crate::ffi::rice_turn_config_get_supported_integrity(
                self.ffi,
                &mut len,
                ret.as_mut_ptr() as _,
            );
            ret.resize(len, IntegrityAlgorithm::Sha1);
            ret
        }
    }

    /// Set whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the `Userhash` attribute.
    pub fn set_anonymous_username(&mut self, anon: Feature) {
        unsafe {
            crate::ffi::rice_turn_config_set_anonymous_username(self.ffi, anon as _);
        }
    }

    /// Whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the `Userhash` attribute.
    pub fn anonymous_username(&self) -> Feature {
        unsafe { crate::ffi::rice_turn_config_get_anonymous_username(self.ffi).into() }
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
                ffi: crate::ffi::rice_turn_config_copy(self.ffi),
            }
        }
    }
}

impl Drop for TurnConfig {
    fn drop(&mut self) {
        unsafe {
            crate::ffi::rice_turn_config_free(self.ffi);
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

    pub(crate) fn as_c(&self) -> *mut crate::ffi::RiceTlsConfig {
        #[allow(unreachable_patterns)]
        let ret = match self {
            #[cfg(feature = "rustls")]
            Self::Rustls(cfg) => *cfg,
            #[cfg(feature = "openssl")]
            Self::Openssl(cfg) => *cfg,
            _ => core::ptr::null_mut(),
        };
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
        let mut cfg = TurnConfig::new(
            TransportType::Udp,
            turn_server_address(),
            turn_credentials(),
        );
        assert_eq!(cfg.addr(), turn_server_address());
        assert_eq!(cfg.client_transport(), TransportType::Udp);
        // TODO credentials
        //assert_eq!(cfg.credentials().username(), turn_credentials().username());
        assert_eq!(&cfg.address_families(), &[AddressFamily::IPV4]);
        assert_eq!(cfg.allocation_transport(), TransportType::Udp);
        assert_eq!(&cfg.supported_integrity(), &[IntegrityAlgorithm::Sha1]);
        assert_eq!(cfg.anonymous_username(), Feature::Auto);
        assert!(cfg.tls_config().is_none());

        for transport in [TransportType::Udp, TransportType::Tcp] {
            cfg.set_allocation_transport(transport);
            assert_eq!(cfg.allocation_transport(), transport);
        }

        cfg.add_address_family(AddressFamily::IPV6);
        assert_eq!(
            &cfg.address_families(),
            &[AddressFamily::IPV4, AddressFamily::IPV6]
        );
        cfg.set_address_family(AddressFamily::IPV6);
        assert_eq!(&cfg.address_families(), &[AddressFamily::IPV6]);

        cfg.add_supported_integrity(IntegrityAlgorithm::Sha256);
        assert_eq!(
            &cfg.supported_integrity(),
            &[IntegrityAlgorithm::Sha1, IntegrityAlgorithm::Sha256]
        );
        cfg.set_supported_integrity(IntegrityAlgorithm::Sha256);
        assert_eq!(&cfg.supported_integrity(), &[IntegrityAlgorithm::Sha256]);

        for feat in [Feature::Disabled, Feature::Auto, Feature::Required] {
            cfg.set_anonymous_username(feat);
            assert_eq!(cfg.anonymous_username(), feat);
        }
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
            let mut cfg = TurnConfig::new(
                TransportType::Tcp,
                turn_server_address(),
                turn_credentials(),
            );
            cfg.set_tls_config(tls.clone());
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
            let mut cfg = TurnConfig::new(
                TransportType::Udp,
                turn_server_address(),
                turn_credentials(),
            );
            cfg.set_tls_config(tls.clone());
            let retrieved = cfg.tls_config().unwrap();
            assert!(matches!(retrieved, TurnTlsConfig::Openssl(_)));
        }
    }
}
