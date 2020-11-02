// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures_timer::Delay;

use crate::socket::ChannelBroadcast;

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
}

#[derive(Debug, Clone)]
struct PaceState {
    pacing: Duration,
    last_message_ts: Option<std::time::Instant>,
}

impl<T> ChannelPacer<T>
where
    T: std::fmt::Debug + Clone,
{
    pub fn new(pacing: Duration) -> Self {
        let (send, recv) = async_channel::bounded(16);
        Self {
            recv_r: recv,
            recv_s: send,
            sender_broadcast: ChannelBroadcast::default(),
            state: Mutex::new(PaceState {
                pacing,
                last_message_ts: None,
            }),
        }
    }

    pub async fn send_loop(&self) {
        while let Ok(item) = self.recv_r.recv().await {
            let delay = {
                let state = self.state.lock().unwrap();

                // delay the message if necessary
                if let Some(last_ts) = state.last_message_ts {
                    trace!(
                        "elapsed, {:?} pacing, {:?}",
                        last_ts.elapsed(),
                        state.pacing
                    );
                    state.pacing.checked_sub(last_ts.elapsed())
                } else {
                    None
                }
            };
            if let Some(delay) = delay {
                trace!("delaying for {:?}", delay);
                Delay::new(delay).await;
            }
            self.sender_broadcast.broadcast(item).await;

            let mut state = self.state.lock().unwrap();
            state.last_message_ts = Some(Instant::now());
        }
    }

    pub async fn send(&self, data: T) {
        self.recv_s.send(data).await.unwrap();
    }

    pub fn recv_channel(&self) -> async_channel::Receiver<T> {
        self.sender_broadcast.channel()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use std::sync::Arc;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn first_immediate() {
        init();
        task::block_on(async move {
            let pacing = Duration::from_millis(5000);
            let pacer: Arc<ChannelPacer<u32>> = Arc::new(ChannelPacer::new(pacing));
            let recv_channel = pacer.recv_channel();
            task::spawn({
                let pacer = pacer.clone();
                async move { pacer.send_loop().await }
            });
            let result = Arc::new(Mutex::new(None));
            let f = task::spawn({
                let result = result.clone();
                async move {
                    let data = recv_channel.recv().await.unwrap();
                    info!("recv {:?}", data);
                    let mut result = result.lock().unwrap();
                    result.replace(Instant::now());
                }
            });

            let now = Instant::now();
            info!("send 5");
            pacer.send(5).await;
            f.await;
            info!("elapsed {:?}", now.elapsed());
            assert!(now.elapsed() < pacing);
        })
    }

    #[test]
    fn delay_second_message() {
        init();
        task::block_on(async move {
            let pacing = Duration::from_millis(2000);
            let pacer: Arc<ChannelPacer<u32>> = Arc::new(ChannelPacer::new(pacing));
            let recv_channel = pacer.recv_channel();
            let wait1 = task::spawn({
                let pacer = pacer.clone();
                async move { pacer.send_loop().await }
            });
            let result = Arc::new(Mutex::new(None));
            let f = task::spawn({
                let result = result.clone();
                async move {
                    let data = recv_channel.recv().await.unwrap();
                    info!("recv {:?}", data);
                    let data = recv_channel.recv().await.unwrap();
                    info!("recv {:?}", data);
                    let mut result = result.lock().unwrap();
                    result.replace(Instant::now());
                }
            });

            let now = Instant::now();
            info!("send 5");
            pacer.send(5).await;
            info!("send 6");
            pacer.send(6).await;
            f.await;
            info!("elapsed {:?}", now.elapsed());
            assert!(now.elapsed() >= pacing);
            wait1.cancel().await;
        })
    }
}
