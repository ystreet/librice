// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::{Arc, Mutex};

pub(crate) struct DropLogger {
    msg: String,
}

impl DropLogger {
    pub(crate) fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Drop for DropLogger {
    fn drop(&mut self) {
        info!("{}", self.msg);
    }
}

#[derive(Clone)]
pub(crate) struct DebugWrapper<T>(&'static str, T);

impl<T> std::fmt::Debug for DebugWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl<T> std::ops::Deref for DebugWrapper<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.1
    }
}
impl<T> std::ops::DerefMut for DebugWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}
impl<T> DebugWrapper<T> {
    pub(crate) fn wrap(obj: T, name: &'static str) -> Self {
        Self(name, obj)
    }
}

type MaybeSenderFilterFn<T> = DebugWrapper<Arc<dyn Fn(&T) -> bool + Send + Sync + 'static>>;

#[derive(Debug, Clone)]
struct MaybeSender<T: std::fmt::Debug> {
    id: usize,
    sender: async_channel::Sender<T>,
    filter: MaybeSenderFilterFn<T>,
}

#[derive(Debug, Clone)]
struct Senders<T: std::fmt::Debug> {
    next_id: usize,
    senders: Vec<MaybeSender<T>>,
}

#[derive(Debug)]
pub(crate) struct ChannelBroadcast<T: std::fmt::Debug> {
    senders: DebugWrapper<Mutex<Senders<T>>>,
}

impl<T> Default for ChannelBroadcast<T>
where
    T: std::fmt::Debug,
{
    fn default() -> Self {
        Self {
            senders: DebugWrapper::wrap(
                Mutex::new(Senders {
                    next_id: 0,
                    senders: vec![],
                }),
                "...",
            ),
        }
    }
}

impl<T: Clone> ChannelBroadcast<T>
where
    T: Clone + std::fmt::Debug,
{
    // only sends when @filter returns true
    pub(crate) fn channel_with_filter(
        &self,
        filter: impl Fn(&T) -> bool + Send + Sync + 'static,
    ) -> async_channel::Receiver<T> {
        let (send, recv) = async_channel::bounded(16);
        let mut inner = self.senders.lock().unwrap();
        let sender_id = inner.next_id;
        inner.next_id += 1;
        inner.senders.push(MaybeSender {
            id: sender_id,
            sender: send,
            filter: DebugWrapper::wrap(Arc::new(filter), "ChannelFilter"),
        });
        recv
    }

    pub(crate) fn channel(&self) -> async_channel::Receiver<T> {
        self.channel_with_filter(|_| true)
    }

    pub(crate) async fn broadcast(&self, data: T) {
        let channels = {
            let inner = self.senders.lock().unwrap();
            inner.senders.clone()
        };

        trace!("sending to {} receivers", channels.len());
        let mut removed = vec![];
        for channel in channels.iter() {
            if (channel.filter)(&data) {
                // XXX: maybe a parallel send?
                if let Err(e) = channel.sender.send(data.clone()).await {
                    trace!("sender has errored with {:?}", e);
                    removed.push(channel.id);
                }
            }
        }

        if !removed.is_empty() {
            trace!("removing {} listeners", removed.len());
            let mut inner = self.senders.lock().unwrap();
            inner
                .senders
                .retain(|c| removed.iter().all(|&id| c.id != id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;

    fn init() {
        crate::tests::test_init_log();
    }

    #[test]
    fn channel() {
        init();
        task::block_on(async move {
            let cb = ChannelBroadcast::default();
            let recv = cb.channel();
            cb.broadcast(42).await;
            assert_eq!(42, recv.recv().await.unwrap());
        })
    }

    #[test]
    fn channel_filter() {
        init();
        task::block_on(async move {
            let cb = ChannelBroadcast::default();
            let recv = cb.channel_with_filter(|&v| v == 42);
            cb.broadcast(41).await;
            cb.broadcast(42).await;
            assert_eq!(42, recv.recv().await.unwrap());
        })
    }

    #[test]
    fn channel_create_destroy_stress() {
        init();
        task::block_on(async move {
            let cb = Arc::new(ChannelBroadcast::default());
            let n = 1000;
            let produce = task::spawn({
                let cb = cb.clone();
                async move {
                    for i in 0..n {
                        cb.broadcast(i).await;
                    }
                }
            });
            for _ in 0..n {
                task::spawn({
                    let cb = cb.clone();
                    async move {
                        let recv = cb.channel();
                        recv.recv().await.unwrap();
                    }
                });
            }
            produce.await;
        })
    }

    #[test]
    fn channel_dual_recv() {
        init();
        task::block_on(async move {
            let cb = ChannelBroadcast::default();
            let recv1 = cb.channel();
            let recv2 = cb.channel();
            cb.broadcast(41).await;
            assert_eq!(41, recv1.recv().await.unwrap());
            assert_eq!(41, recv2.recv().await.unwrap());
        })
    }

    #[test]
    fn channel_destroy() {
        init();
        task::block_on(async move {
            let cb = ChannelBroadcast::default();
            let recv1 = cb.channel();
            let recv2 = cb.channel();
            cb.broadcast(41).await;
            assert_eq!(41, recv1.recv().await.unwrap());
            assert_eq!(41, recv2.recv().await.unwrap());
            drop(recv1);
            assert_eq!(cb.senders.lock().unwrap().senders.len(), 2);
            cb.broadcast(42).await;
            assert_eq!(cb.senders.lock().unwrap().senders.len(), 1);
            assert_eq!(42, recv2.recv().await.unwrap());
        })
    }

    #[test]
    fn broadcast_destroy() {
        init();
        task::block_on(async move {
            let cb = ChannelBroadcast::default();
            let recv = cb.channel();
            cb.broadcast(41).await;
            assert_eq!(41, recv.recv().await.unwrap());
            drop(cb);
            assert!(matches!(recv.recv().await, Err(async_channel::RecvError)));
        })
    }

    #[test]
    fn channel_broadcast_large() {
        init();
        task::block_on(async move {
            let cb = Arc::new(ChannelBroadcast::default());
            let recv = cb.channel();
            task::spawn({
                let cb = cb.clone();
                async move {
                    for i in 0..1024 {
                        cb.broadcast(i).await;
                    }
                }
            });
            for i in 0..1024 {
                assert_eq!(i, recv.recv().await.unwrap());
            }
        })
    }
}
