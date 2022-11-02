// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use futures::future::Either;
use futures::Future;
use futures_timer::Delay;
use once_cell::sync::Lazy;

#[async_trait]
pub(crate) trait Clock: std::fmt::Debug + std::marker::Send + std::marker::Sync {
    async fn delay(
        &self,
        duration: Duration,
    ) -> Box<dyn ClockEntry + std::marker::Send + std::marker::Sync>;
    fn now(&self) -> Instant;
}

#[async_trait]
pub(crate) trait ClockEntry:
    std::fmt::Debug + std::marker::Send + std::marker::Sync
{
    // FIXME: impl Future instead
    async fn wait(&self);
}

#[derive(Debug, Default)]
struct SystemClock {}

#[async_trait]
impl Clock for SystemClock {
    async fn delay(
        &self,
        duration: Duration,
    ) -> Box<dyn ClockEntry + std::marker::Send + std::marker::Sync> {
        Box::new(SystemClockEntry {
            delay: Arc::new(Mutex::new(Some(Delay::new(duration)))), //delay: Delay::new(duration)
        })
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug)]
struct SystemClockEntry {
    delay: Arc<Mutex<Option<Delay>>>,
}

#[async_trait]
impl ClockEntry for SystemClockEntry {
    async fn wait(&self) {
        // XXX: is multiple waiters a thing?
        let delay = {
            let mut delay_guard = self.delay.lock().unwrap();
            delay_guard.take()
        };
        if let Some(delay) = delay {
            delay.await
        }
    }
}

pub(crate) struct TimeoutError;

pub(crate) async fn timeout<F, T>(
    clock: Arc<dyn Clock>,
    duration: Duration,
    f: F,
) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    let (abortable, _abort_handle) = futures::future::abortable(f);
    let wait = clock.delay(duration).await;
    let wait = async move {
        wait.wait().await;
        Err(TimeoutError)
    };

    futures::pin_mut!(abortable);
    futures::pin_mut!(wait);

    match futures::future::try_select(abortable, wait).await {
        Ok(Either::Left((x, _))) => Ok(x),
        Ok(Either::Right((y, _))) => y,
        Err(Either::Right((y, _))) => Err(y),
        _ => unreachable!(),
    }
}

pub(crate) enum ClockType {
    System,
    // XXX: currently unused and TestClock is created directly
    //#[cfg(test)]
    // Test,
}

impl Default for ClockType {
    fn default() -> Self {
        ClockType::System
    }
}

static SYSTEM_CLOCK_INSTANCE: Lazy<Arc<dyn Clock>> = Lazy::new(|| Arc::new(SystemClock::default()));

pub(crate) fn get_clock(clock_type: ClockType) -> Arc<dyn Clock> {
    match clock_type {
        ClockType::System => SYSTEM_CLOCK_INSTANCE.clone(),
        //#[cfg(test)]
        //ClockType::Test => Arc::new(tests::TestClock::default()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use async_std::task;

    use crate::utils::ChannelBroadcast;

    use super::*;
    use std::sync::{Arc, Mutex, Weak};

    #[derive(Debug)]
    pub(crate) struct TestClock {
        inner: Arc<Mutex<TestClockInner>>,
        new_instant_recv: async_channel::Receiver<Instant>,
        new_instant_send: async_channel::Sender<Instant>,
    }

    #[derive(Debug)]
    pub(crate) struct AdvanceEntry<'clock> {
        clock: &'clock TestClock,
        broadcast: Arc<ChannelBroadcast<Instant>>,
        instant: Instant,
    }

    impl<'clock> AdvanceEntry<'clock> {
        #[tracing::instrument(
            name = "clock_entry_advance",
            skip(self),
            fields(instant = ?self.instant)
        )]
        pub(crate) async fn advance(self) {
            let instant = {
                let mut inner = self.clock.inner.lock().unwrap();
                if self.instant > inner.now {
                    inner.now = self.instant;
                    trace!("now updated to {:?}", self.instant);
                    Some(self.instant)
                } else {
                    None
                }
            };
            if let Some(instant) = instant {
                self.broadcast.broadcast(instant).await;
            }
        }
    }

    impl TestClock {
        #[tracing::instrument(skip(self), ret)]
        pub(crate) async fn next_entry(&self) -> AdvanceEntry {
            while let Ok(instant) = self.new_instant_recv.recv().await {
                trace!("received instant {:?}", instant);
                let inner = self.inner.lock().unwrap();
                if instant > inner.now {
                    return AdvanceEntry {
                        clock: self,
                        broadcast: inner.broadcast.clone(),
                        instant,
                    };
                }
            }
            unreachable!();
        }

        #[tracing::instrument(level = "debug", skip(self))]
        pub(crate) async fn advance(&self) {
            let entry = self.next_entry().await;
            entry.advance().await;
        }

        pub(crate) async fn set_time(&self, instant: Instant) {
            let (broadcast, instant) = {
                let mut inner = self.inner.lock().unwrap();
                if instant > inner.now {
                    trace!("now is {:?}", instant);
                    inner.now = instant;
                }
                (inner.broadcast.clone(), inner.now)
            };
            broadcast.broadcast(instant).await;
        }
    }

    impl Default for TestClock {
        fn default() -> Self {
            let (send, recv) = async_channel::bounded(512);
            TestClock {
                inner: Arc::new(Mutex::new(TestClockInner::default())),
                new_instant_send: send,
                new_instant_recv: recv,
            }
        }
    }

    #[derive(Debug)]
    struct TestClockInner {
        now: Instant,
        broadcast: Arc<ChannelBroadcast<Instant>>,
    }

    impl Default for TestClockInner {
        fn default() -> Self {
            let now = Instant::now();
            TestClockInner {
                now,
                broadcast: Arc::new(ChannelBroadcast::default()),
            }
        }
    }

    #[derive(Debug)]
    struct TestClockEntry {
        inner: Weak<Mutex<TestClockInner>>,
        wait_until: Instant,
    }

    impl TestClockEntry {
        fn new(inner: &Arc<Mutex<TestClockInner>>, wait_until: Instant) -> Self {
            TestClockEntry {
                inner: Arc::downgrade(inner),
                wait_until,
            }
        }
    }

    #[async_trait]
    impl ClockEntry for TestClockEntry {
        #[tracing::instrument(
            name = "clock_entry_wait",
            level = "debug",
            skip(self),
            fields(
                instant = ?self.wait_until
            )
        )]
        async fn wait(&self) {
            let inner = match self.inner.upgrade() {
                Some(inner) => inner,
                None => return,
            };
            let receiver = {
                let inner = inner.lock().unwrap();
                if inner.now >= self.wait_until {
                    trace!(
                        "now {:?} has already passed wait time {:?}",
                        inner.now,
                        self.wait_until
                    );
                    return;
                }
                trace!(
                    "now {:?} has not reached wait time {:?}",
                    inner.now,
                    self.wait_until
                );
                inner.broadcast.channel()
            };
            while let Ok(val) = receiver.recv().await {
                if val >= self.wait_until {
                    trace!(
                        "clock time {:?} has passed wait time {:?}",
                        val,
                        self.wait_until
                    );
                    break;
                }
            }
        }
    }

    #[async_trait]
    impl Clock for TestClock {
        async fn delay(
            &self,
            duration: Duration,
        ) -> Box<dyn ClockEntry + std::marker::Send + std::marker::Sync> {
            let wait_until = {
                let inner = self.inner.lock().unwrap();
                let wait_until = inner.now + duration;
                trace!("now {:?} new delay until {:?}", inner.now, wait_until);
                wait_until
            };
            self.new_instant_send.send(wait_until).await.unwrap();
            Box::new(TestClockEntry::new(&self.inner, wait_until))
        }

        fn now(&self) -> Instant {
            let inner = self.inner.lock().unwrap();
            let now = inner.now;
            trace!("now {:?}", now);
            now
        }
    }

    #[test]
    fn system_clock_wait() {
        task::spawn(async move {
            let clock = get_clock(ClockType::System);
            let start = clock.now();
            let dur = Duration::from_secs(1);
            let entry = clock.delay(dur).await;
            entry.wait().await;
            assert!(clock.now() >= start + dur);
        });
    }

    #[test]
    fn test_clock_advance() {
        task::spawn(async move {
            let clock = TestClock::default();
            let start = clock.now();
            let dur = Duration::from_millis(100);
            let entry = clock.delay(dur).await;
            let f = task::spawn(async move {
                entry.wait().await;
            });
            clock.advance().await;
            assert!(clock.now() >= start + dur);
            f.await;
        });
    }

    #[test]
    fn test_clock_set_time() {
        task::spawn(async move {
            let clock = TestClock::default();
            let start = clock.now();
            let dur = Duration::from_millis(100);
            let entry = clock.delay(dur).await;
            clock.set_time(start + dur).await;
            entry.wait().await;
            assert!(clock.now() >= start + dur);
        });
    }
}
