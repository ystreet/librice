// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::utils::ChannelBroadcast;

use crate::clock::{Clock, get_clock, ClockType};

pub const STUN_REQUEST_PACE_TIME: Duration = Duration::from_millis(2000);

#[derive(Debug)]
pub struct ChannelPacer<T>
where
    T: std::fmt::Debug,
{
    recv_r: async_channel::Receiver<T>,
    recv_s: async_channel::Sender<T>,
    sender_broadcast: ChannelBroadcast<T>,
    state: Mutex<PaceState>,
    clock: Arc<dyn Clock>,
}

#[derive(Debug, Clone)]
struct PaceState {
    pacing: Duration,
    last_message_ts: Option<std::time::Instant>,
}

#[derive(Debug)]
pub(crate) struct PacerBuilder {
    pacing: Duration,
    clock: Option<Arc<dyn Clock>>,
}

impl PacerBuilder {
    fn new(pacing: Duration) -> Self {
        Self {
            pacing,
            clock: None,
        }
    }

    pub(crate) fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub(crate) fn build<T>(self) -> ChannelPacer<T>
    where
        T: std::fmt::Debug + Clone
    {
        let (send, recv) = async_channel::bounded(16);
        let clock = self.clock.unwrap_or_else(|| get_clock(ClockType::default()));
        ChannelPacer {
            recv_r: recv,
            recv_s: send,
            sender_broadcast: ChannelBroadcast::default(),
            state: Mutex::new(PaceState {
                pacing: self.pacing,
                last_message_ts: None,
            }),
            clock,
        }
    }
}

impl<T> ChannelPacer<T>
where
    T: std::fmt::Debug + Clone,
{
    pub(crate) fn new(pacing: Duration) -> Self {
        Self::builder(pacing).build()
    }

    pub(crate) fn builder(pacing: Duration) -> PacerBuilder {
        PacerBuilder::new(pacing)
    }

    pub(crate) async fn send_loop(&self) {
        while let Ok(item) = self.recv_r.recv().await {
            let delay = {
                let state = self.state.lock().unwrap();

                // delay the message if necessary
                if let Some(last_ts) = state.last_message_ts {
                    let elapsed = self.clock.now() - last_ts;
                    trace!(
                        "elapsed, {:?} pacing, {:?}",
                        elapsed,
                        state.pacing
                    );
                    state.pacing.checked_sub(elapsed)
                } else {
                    None
                }
            };
            if let Some(delay) = delay {
                trace!("delaying for {:?}", delay);
                let delay = self.clock.delay(delay).await;
                delay.wait().await;
            }
            self.sender_broadcast.broadcast(item).await;

            let mut state = self.state.lock().unwrap();
            state.last_message_ts = Some(self.clock.now());
        }
    }

    pub(crate) async fn send(&self, data: T) {
        self.recv_s.send(data).await.unwrap();
    }

    pub(crate) fn recv_channel(&self) -> async_channel::Receiver<T> {
        self.sender_broadcast.channel()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use std::sync::Arc;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn first_immediate() {
        init();
        task::block_on(async move {
            let pacing = Duration::from_millis(5000);
            let clock = get_clock(ClockType::Test);
            let pacer: Arc<ChannelPacer<u32>> = Arc::new(ChannelPacer::<u32>::builder(pacing).clock(clock.clone()).build());
            let recv_channel = pacer.recv_channel();
            task::spawn({
                let pacer = pacer.clone();
                async move { pacer.send_loop().await }
            });
            let f = task::spawn({
                async move {
                    let data = recv_channel.recv().await.unwrap();
                    info!("recv {:?}", data);
                }
            });

            let start_time = clock.now();
            info!("send 5");
            pacer.send(5).await;
            f.await;
            let end_time = clock.now();
            info!("elapsed {:?}", end_time - start_time);
            assert!(end_time - start_time < pacing);
        })
    }

    #[test]
    fn delay_second_message() {
        init();
        task::block_on(async move {
            let pacing = Duration::from_millis(2000);
            let clock = Arc::new(crate::clock::tests::TestClock::default());
            let pacer: Arc<ChannelPacer<u32>> = Arc::new(ChannelPacer::<u32>::builder(pacing).clock(clock.clone()).build());
            let recv_channel = pacer.recv_channel();
            let wait1 = task::spawn({
                let pacer = pacer.clone();
                async move { pacer.send_loop().await }
            });

            let start_time = clock.now();
            info!("send 5");
            pacer.send(5).await;
            info!("send 6");
            pacer.send(6).await;

            let data = recv_channel.recv().await.unwrap();
            info!("recv {:?}", data);

            clock.advance().await;
            info!("clock advanced");

            let data = recv_channel.recv().await.unwrap();
            info!("recv {:?}", data);

            let end_time = clock.now();
            info!("elapsed {:?}", end_time - start_time);
            assert!(end_time - start_time >= pacing);
            wait1.cancel().await;
        })
    }
}
