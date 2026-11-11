// Copyright (C) 2026 Sanchayan Maity <sanchayan@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Implementation of Consent Freshness as per RFC 7675.

use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use stun_proto::Instant;
use stun_proto::types::prelude::MessageWrite;
use stun_proto::types::prelude::MessageWriteExt;

use crate::candidate::Candidate;
use crate::conncheck::{self, Credentials};
use crate::rand::rand_f64;

/// Default interval between consent checks. The specification recommends
/// values between >= 4 seconds.
pub const DEFAULT_CONSENT_FRESHNESS_INTERVAL: Duration = Duration::from_secs(5);

/// Default consent freshness timeout. If no traffic is received within
/// this window, consent is revoked.
pub const DEFAULT_CONSENT_FRESHNESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum interval for consent checks (RFC 7675 §5.1).
pub const MINIMUM_CONSENT_INTERVAL: Duration = Duration::from_secs(4);

/// Configuration for `ConsentFreshness`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The interval between periodic Binding Requests.
    pub interval: Duration,
    /// The timeout after which consent expires.
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: DEFAULT_CONSENT_FRESHNESS_INTERVAL,
            timeout: DEFAULT_CONSENT_FRESHNESS_TIMEOUT,
        }
    }
}

/// Return value from [`ConsentFreshness::poll()`].
#[derive(Debug)]
pub(crate) enum ConsentFreshnessPoll {
    /// No consent-freshness events to process. Call `poll()` again at the
    /// given `Instant`.
    WaitUntil(Instant),
    /// A consent check should be sent to the peer. The caller must call
    /// [`build_consent_check()`](ConsentFreshness::build_consent_check)
    /// to produce the STUN request, then route it through the conncheck.
    SendCheck {
        /// The ICE stream id.
        stream_id: usize,
        /// The ICE component id.
        component_id: usize,
    },
    /// The described component has not received any traffic within
    /// [`Config::timeout`]. The caller should treat the component's
    /// connection as failed.
    ConsentExpired {
        /// The ICE stream id.
        stream_id: usize,
        /// The ICE component id.
        component_id: usize,
    },
    /// A 403 Forbidden error response was received for the component. The
    /// remote has explicitly revoked consent. The caller should treat the
    /// component as failed.
    ConsentRevoked {
        /// The ICE stream id.
        stream_id: usize,
        /// The ICE component id.
        component_id: usize,
    },
}

/// The result of [`ConsentFreshness::build_consent_check()`].
pub(crate) struct ConsentCheck {
    /// Local candidate.
    pub local: Candidate,
    /// The raw STUN Binding Request bytes to send.
    pub msg: Vec<u8>,
    /// Destination socket address.
    pub to: SocketAddr,
}

/// Per‑component state for the consent‑freshness process.
#[derive(Debug)]
struct Entry {
    stream_id: usize,
    component_id: usize,
    controlling: bool,
    tie_breaker: u64,
    local: Candidate,
    local_creds: Credentials,
    remote_creds: Credentials,
    to: SocketAddr,
    last_consent_received: Instant,
    next_send: Instant,
    revoked: bool,
    local_priority: u32,
}

/// The consent-freshness process.
#[derive(Debug)]
pub(crate) struct ConsentFreshness {
    entries: Vec<Entry>,
    config: Config,
}

impl ConsentFreshness {
    /// Create a new [`ConsentFreshness`] process with the given [`Config`].
    pub(crate) fn new(config: Config) -> Self {
        Self {
            entries: Vec::new(),
            config,
        }
    }

    /// Compute a randomized interval per RFC 7675 §5.1: 0.8–1.2 × basic period.
    /// Clamped to a minimum of 4 seconds.
    fn next_interval(&self) -> Duration {
        let factor = 0.8 + rand_f64() * 0.4;
        let secs = self.config.interval.as_secs_f64() * factor;
        Duration::from_secs_f64(secs).max(MINIMUM_CONSENT_INTERVAL)
    }

    /// Begin tracking consent for a newly-selected pair.
    #[tracing::instrument(
        name = "consent_freshness_start",
        skip(self),
        fields(
            stream.id = stream_id,
            component.id = component_id,
        )
    )]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        &mut self,
        stream_id: usize,
        component_id: usize,
        local: Candidate,
        to: SocketAddr,
        local_creds: Credentials,
        remote_creds: Credentials,
        controlling: bool,
        tie_breaker: u64,
        now: Instant,
    ) {
        let transport = local.transport_type;
        let from = local.base_address;
        let local_priority = local.priority;

        self.stop(stream_id, component_id);

        tracing::info!(
            "Starting consent freshness for stream {} component {} on {} {} -> {}",
            stream_id,
            component_id,
            transport,
            from,
            to,
        );

        self.entries.push(Entry {
            stream_id,
            component_id,
            controlling,
            tie_breaker,
            local,
            local_creds,
            remote_creds,
            to,
            last_consent_received: now,
            next_send: now + self.next_interval(),
            revoked: false,
            local_priority,
        });
    }

    /// Stop monitoring consent for a component.
    pub(crate) fn stop(&mut self, stream_id: usize, component_id: usize) {
        self.entries
            .retain(|e| e.stream_id != stream_id || e.component_id != component_id);
    }

    /// Clear all entries.
    pub(crate) fn close(&mut self) {
        self.entries.clear();
    }

    /// Build the STUN Binding Request for a consent check using the
    /// same code path as conncheck ([`conncheck::generate_binding_request()`]).
    ///
    /// Returns `None` if the component is not being tracked.
    pub(crate) fn build_consent_check(
        &mut self,
        stream_id: usize,
        component_id: usize,
        now: Instant,
    ) -> Option<ConsentCheck> {
        let next = self.next_interval();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.stream_id == stream_id && e.component_id == component_id)?;

        let Ok(msg) = conncheck::generate_binding_request(
            entry.local_priority,
            false,
            entry.controlling,
            entry.tie_breaker,
            entry.local_creds.clone(),
            entry.remote_creds.clone(),
        ) else {
            return None;
        };

        let tid = msg.transaction_id();
        let bytes = msg.finish().to_vec();

        tracing::trace!(
            "Building consent check (stream {} component {}) with tid {}",
            stream_id,
            component_id,
            tid,
        );

        entry.next_send = now + next;

        Some(ConsentCheck {
            local: entry.local.clone(),
            msg: bytes,
            to: entry.to,
        })
    }

    /// Called when the conncheck reports an authenticated consent
    /// response was received for `component_id`.
    pub(crate) fn on_response(&mut self, component_id: usize, now: Instant) {
        let next = self.next_interval();

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.component_id == component_id)
        {
            tracing::trace!(
                "Consent refreshed for stream {} component {} next send {:?}",
                entry.stream_id,
                entry.component_id,
                now + next
            );

            entry.last_consent_received = now;
            entry.next_send = now + next;
        }
    }

    /// Called when a 403 Forbidden is received for a consent check.
    ///
    /// This marks the entry so that the next `poll()` returns
    /// `ConsentRevoked`.
    pub(crate) fn on_revoked(&mut self, stream_id: usize, component_id: usize) {
        // With a single ConsentFreshness object per agent, we also need
        // to select based on the stream_id for the case where multiple
        // streams can be under consideration and component_id won't suffice.
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.stream_id == stream_id && e.component_id == component_id)
        {
            entry.revoked = true;

            tracing::warn!(
                "Consent revoked for stream {} component {} (403 Forbidden)",
                entry.stream_id,
                entry.component_id,
            );
        }
    }

    /// Poll the consent‑freshness process.
    pub(crate) fn poll(&mut self, now: Instant) -> ConsentFreshnessPoll {
        if let Some((idx, sid, cid)) = self.entries.iter().enumerate().find_map(|(i, entry)| {
            entry
                .revoked
                .then_some((i, entry.stream_id, entry.component_id))
        }) {
            self.entries.swap_remove(idx);

            return ConsentFreshnessPoll::ConsentRevoked {
                stream_id: sid,
                component_id: cid,
            };
        }

        let mut lowest_wait = None;

        for entry in &mut self.entries {
            // Check if the overall consent timeout has elapsed.
            if now >= entry.last_consent_received + self.config.timeout {
                let sid = entry.stream_id;
                let cid = entry.component_id;

                tracing::warn!(
                    "Consent expired for stream {} component {}: \
                     last response at {:?}, now {:?}",
                    sid,
                    cid,
                    entry.last_consent_received,
                    now,
                );

                return ConsentFreshnessPoll::ConsentExpired {
                    stream_id: sid,
                    component_id: cid,
                };
            }

            // If the interval has elapsed, send a new Binding Request.
            // RFC 7675 §5.1: To prevent expiry of consent, a STUN binding
            // request can be sent periodically. Each request is transmitted
            // once, we do not wait for a response before sending the next.
            if now >= entry.next_send {
                return ConsentFreshnessPoll::SendCheck {
                    stream_id: entry.stream_id,
                    component_id: entry.component_id,
                };
            }

            // Compute the earliest relevant deadline.
            let deadline = entry.last_consent_received + self.config.timeout;
            match lowest_wait {
                Some(prev) if prev <= deadline => {}
                _ => lowest_wait = Some(deadline),
            }

            match lowest_wait {
                Some(prev) if prev <= entry.next_send => {}
                _ => lowest_wait = Some(entry.next_send),
            }
        }

        ConsentFreshnessPoll::WaitUntil(lowest_wait.unwrap_or(now + Duration::from_secs(3600)))
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) fn set_config(&mut self, config: Config) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{candidate::CandidateType, tests::test_init_log};
    use stun_proto::types::{TransportType, message::*};

    fn local_creds() -> Credentials {
        Credentials::new("lufrag".into(), "lpwd".into())
    }

    fn remote_creds() -> Credentials {
        Credentials::new("rufrag".into(), "rpwd".into())
    }

    #[test]
    fn consent_freshness_sends_initial_check() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        // First poll should tell us to send a check (initial interval has
        // passed) but start() initialises next_send = now + interval, so
        // immediately after start we should get WaitUntil(now + interval).
        match cf.poll(now) {
            ConsentFreshnessPoll::WaitUntil(_) => {} // OK
            other => panic!("expected WaitUntil, got {other:?}"),
        }
    }

    #[test]
    fn next_interval_within_rfc_range() {
        let _log = test_init_log();
        let config = Config {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(60),
        };
        let cf = ConsentFreshness::new(config);
        // RFC 7675: the interval is randomized to 0.8-1.2x the base period
        // (clamped to a 4s minimum).  Sample many times to bound the randomized
        // range; this distinguishes the intended multiplication from a division.
        let mut min = Duration::MAX;
        let mut max = Duration::ZERO;
        for _ in 0..256 {
            let v = cf.next_interval();
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }
        assert!(min >= Duration::from_secs_f64(24.0), "min {min:?}");
        assert!(max < Duration::from_secs_f64(36.0), "max {max:?}");
    }

    #[test]
    fn consent_freshness_no_response_causes_expiry() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let interval = Config::default().interval;
        let timeout = Config::default().timeout;
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        // Send the first check
        let t1 = now + Duration::from_secs_f64(interval.as_secs_f64() * 1.5);
        {
            match cf.poll(t1) {
                ConsentFreshnessPoll::SendCheck { .. } => {}
                other => panic!("expected SendCheck, got {other:?}"),
            }
            let _ = cf.build_consent_check(0, 1, t1);
        }

        // No response. After timeout from start, consent should expire.
        let t_expire = now + timeout;
        match cf.poll(t_expire) {
            ConsentFreshnessPoll::ConsentExpired {
                stream_id,
                component_id,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(component_id, 1);
            }
            other => panic!("expected ConsentExpired, got {other:?}"),
        }
    }

    #[test]
    fn consent_freshness_response_refreshes_timer() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let interval = Config::default().interval;
        let timeout = Config::default().timeout;
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        let t1 = now + Duration::from_secs_f64(interval.as_secs_f64() * 1.5);
        {
            match cf.poll(t1) {
                ConsentFreshnessPoll::SendCheck { .. } => {}
                other => panic!("expected SendCheck at t1, got {other:?}"),
            }
            cf.build_consent_check(0, 1, t1);
        }

        // A response refreshes consent.
        let t_refresh = t1 + Duration::from_secs(1);
        cf.on_response(1, t_refresh);

        // Consent should NOT expire at now + timeout (it was refreshed).
        let t_check = now + timeout + Duration::from_secs(1);
        match cf.poll(t_check) {
            ConsentFreshnessPoll::SendCheck { .. } | ConsentFreshnessPoll::WaitUntil(_) => {}
            other => panic!("expected SendCheck or WaitUntil after refresh, got {other:?}"),
        }

        // Further past the refreshed timeout should expire.
        let t_expire = t_refresh + timeout + Duration::from_secs(1);
        match cf.poll(t_expire) {
            ConsentFreshnessPoll::ConsentExpired { .. } => {}
            other => panic!("expected ConsentExpired, got {other:?}"),
        }
    }

    #[test]
    fn consent_refreshed_on_subsequent_cycle() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let interval = Config::default().interval;
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        // Send first check at t1.
        let t1 = now + Duration::from_secs_f64(interval.as_secs_f64() * 1.5);
        {
            match cf.poll(t1) {
                ConsentFreshnessPoll::SendCheck {
                    stream_id,
                    component_id,
                } => {
                    assert_eq!(stream_id, 0);
                    assert_eq!(component_id, 1);
                }
                other => panic!("expected SendCheck, got {other:?}"),
            }

            let check = cf
                .build_consent_check(0, 1, t1)
                .expect("should produce a consent check");
            let msg = Message::from_bytes(&check.msg[..]).unwrap();

            assert!(msg.has_class(MessageClass::Request));
            assert!(msg.has_method(BINDING));
            assert_eq!(check.to, "10.0.0.2:2000".parse().unwrap());
        }

        // No response → second SendCheck at t2.
        let t2 = now + Duration::from_secs_f64(interval.as_secs_f64() * 4.0);
        match cf.poll(t2) {
            ConsentFreshnessPoll::SendCheck {
                stream_id,
                component_id,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(component_id, 1);
            }
            other => panic!("expected SendCheck at t2, got {other:?}"),
        }

        // Build the second request.
        let check2 = cf.build_consent_check(0, 1, t2).unwrap();
        let _tid2 = Message::from_bytes(&check2.msg[..])
            .unwrap()
            .transaction_id();

        // A response for the second request refreshes consent.
        cf.on_response(1, t2);

        // A third SendCheck should fire after the interval expires.
        let t3 = t2 + Duration::from_secs_f64(interval.as_secs_f64() * 2.5);
        match cf.poll(t3) {
            ConsentFreshnessPoll::SendCheck {
                stream_id,
                component_id,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(component_id, 1);
            }
            other => panic!("expected SendCheck at t3, got {other:?}"),
        }
    }

    #[test]
    fn consent_revoked_on_403() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        cf.on_revoked(0, 1);

        match cf.poll(now) {
            ConsentFreshnessPoll::ConsentRevoked {
                stream_id,
                component_id,
            } => {
                assert_eq!(stream_id, 0);
                assert_eq!(component_id, 1);
            }
            other => panic!("expected ConsentRevoked after 403, got {other:?}"),
        }

        // After revocation, subsequent polls must NOT produce a SendCheck.
        match cf.poll(now + Duration::from_secs(100)) {
            ConsentFreshnessPoll::WaitUntil(_) => {}
            other => panic!("expected WaitUntil after revocation, got {other:?}"),
        }
    }

    #[test]
    fn consent_freshness_ice_lite_never_starts() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let now = Instant::ZERO;

        // No entries → WaitUntil.
        match cf.poll(now) {
            ConsentFreshnessPoll::WaitUntil(_) => {}
            other => panic!("expected WaitUntil with empty entries, got {other:?}"),
        }
    }

    #[test]
    fn consent_freshness_stop_removes_entry() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate,
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        cf.stop(0, 1);

        // No entries should remain.
        match cf.poll(now) {
            ConsentFreshnessPoll::WaitUntil(_) => {}
            other => panic!("expected WaitUntil after stop, got {other:?}"),
        }
    }

    #[test]
    fn consent_freshness_close_clears_all() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        cf.start(
            0,
            1,
            candidate.clone(),
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );
        cf.start(
            0,
            2,
            candidate,
            "10.0.0.2:2001".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        cf.close();
        match cf.poll(now) {
            ConsentFreshnessPoll::WaitUntil(_) => {}
            other => panic!("expected WaitUntil after close, got {other:?}"),
        }
    }

    #[test]
    fn consent_freshness_multiple_components() {
        let _log = test_init_log();
        let mut cf = ConsentFreshness::new(Config::default());
        let interval = Config::default().interval;
        let now = Instant::ZERO;

        let addr: SocketAddr = "10.0.0.1:1000".parse().unwrap();
        let candidate = Candidate::builder(
            1,
            CandidateType::Host,
            TransportType::Udp,
            "foundation",
            addr,
        )
        .priority(1234)
        .build();

        // Two components in the same stream.
        cf.start(
            0,
            1,
            candidate.clone(),
            "10.0.0.2:2000".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );
        cf.start(
            0,
            2,
            candidate,
            "10.0.0.2:2001".parse().unwrap(),
            local_creds(),
            remote_creds(),
            true,
            42,
            now,
        );

        // Both should produce SendCheck after worst-case jitter.
        let t1 = now + Duration::from_secs_f64(interval.as_secs_f64() * 1.5);
        let mut send_checks: Vec<(usize, usize)> = Vec::new();
        loop {
            match cf.poll(t1) {
                ConsentFreshnessPoll::SendCheck {
                    stream_id,
                    component_id,
                } => {
                    let _ = cf.build_consent_check(stream_id, component_id, t1);
                    send_checks.push((stream_id, component_id));
                }
                ConsentFreshnessPoll::WaitUntil(_) => break,
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(send_checks.len(), 2);
        assert!(send_checks.contains(&(0, 1)));
        assert!(send_checks.contains(&(0, 2)));
    }
}
