// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_channel;
use futures::prelude::*;

use crate::agent::{AgentError, AgentFuture};

#[derive(Debug)]
enum TaskReturn {
    NoMoreFutures,
    Wakeup,
    FutureReturn(Result<(), AgentError>),
}

type TaskFuture = Pin<Box<dyn Future<Output = TaskReturn> + Send>>;

#[derive(Debug)]
pub(crate) struct TaskList {
    task_sender: Mutex<Option<async_channel::Sender<TaskFuture>>>,
    task_receiver: Mutex<Option<async_channel::Receiver<TaskFuture>>>,
}

impl TaskList {
    pub(crate) fn new() -> Self {
        let (send, recv) = async_channel::bounded(16);
        Self {
            task_sender: Mutex::new(Some(send)),
            task_receiver: Mutex::new(Some(recv)),
        }
    }

    pub(crate) fn add_task_block(&self, fut: AgentFuture) -> Result<(), AgentError> {
        async_std::task::block_on(self.add_task(fut))
    }

    pub(crate) async fn add_task(&self, fut: AgentFuture) -> Result<(), AgentError> {
        trace!("sending future");
        let sender = {
            self.task_sender
                .lock()
                .unwrap()
                .clone()
                .ok_or(AgentError::ConnectionClosed)?
        };
        sender
            .send(async move { TaskReturn::FutureReturn(fut.await) }.boxed())
            .await
            .map_err(|_| AgentError::ConnectionClosed)
    }

    async fn add_future_to_task_list(
        future_list: Arc<Mutex<VecDeque<TaskFuture>>>,
        mut receiver: async_channel::Receiver<TaskFuture>,
    ) -> TaskReturn {
        if let Some(task) = receiver.next().await {
            trace!("receiving future");
            future_list.lock().unwrap().push_back(task);
            TaskReturn::Wakeup
        } else {
            TaskReturn::NoMoreFutures
        }
    }

    pub(crate) async fn iterate_tasks(&self) -> Result<(), AgentError> {
        let receiver =
            { self.task_receiver.lock().unwrap().take() }.ok_or(AgentError::AlreadyInProgress)?;

        let mut futures = futures::stream::FuturesUnordered::new();
        let new_futures = Arc::new(Mutex::new(VecDeque::new()));
        futures
            .push(TaskList::add_future_to_task_list(new_futures.clone(), receiver.clone()).boxed());
        while let Some(ret) = futures.next().await {
            trace!("iterating over future");
            match ret {
                TaskReturn::Wakeup => {
                    trace!("wakeup, readding wakeup future");
                    futures.push(
                        TaskList::add_future_to_task_list(new_futures.clone(), receiver.clone())
                            .boxed(),
                    )
                }
                TaskReturn::NoMoreFutures => {
                    info!("no more futures");
                }
                TaskReturn::FutureReturn(ret) => ret?,
            }
            {
                let mut add_futures = new_futures.lock().unwrap();
                trace!("adding {} futures to tasklist", add_futures.len());
                while let Some(new_fut) = add_futures.pop_front() {
                    futures.push(new_fut);
                }
            }
        }

        {
            info!("task loop exited");
            self.task_receiver.lock().unwrap().replace(receiver);
        }
        Ok(())
    }

    pub(crate) async fn stop(&self) -> Result<(), AgentError> {
        info!("stopping task loop");
        self.task_sender.lock().unwrap().take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use std::time::Duration;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[derive(Debug)]
    struct Counter(usize);

    #[test]
    fn task_list() {
        init();
        let n_tasks: usize = 5;
        let tl = Arc::new(TaskList::new());
        async fn inc_sleep_start(tl: Arc<TaskList>, counter: Arc<Mutex<Counter>>) {
            let task_i = {
                let mut inner = counter.lock().unwrap();
                inner.0 += 1;
                inner.0 - 1
            };
            info!("executing task {}", task_i);
            task::sleep(Duration::from_millis(100)).await;
            tl.clone()
                .add_task(
                    inc_sleep(tl.clone(), counter.clone())
                        .map(|r| Ok(r))
                        .boxed(),
                )
                .await
                .unwrap();
            tl.clone()
                .add_task(inc_sleep(tl, counter).map(|r| Ok(r)).boxed())
                .await
                .unwrap();
            info!("executed task {}", task_i);
        }
        async fn inc_sleep(tl: Arc<TaskList>, counter: Arc<Mutex<Counter>>) {
            let n_tasks = 5 * 3 - 2;
            let task_i = {
                let mut inner = counter.lock().unwrap();
                inner.0 += 1;
                inner.0 - 1
            };
            info!("executing task {}", task_i);
            task::sleep(Duration::from_millis(100)).await;
            if task_i > n_tasks {
                tl.stop().await.unwrap();
            }
            info!("executed task {}", task_i);
        }

        task::block_on(async move {
            let counter = Arc::new(Mutex::new(Counter(0)));

            for _ in 0..n_tasks {
                tl.add_task(
                    inc_sleep_start(tl.clone(), counter.clone())
                        .map(|r| Ok(r))
                        .boxed(),
                )
                .await
                .unwrap();
            }
            tl.iterate_tasks().await.unwrap();
            assert_eq!(counter.lock().unwrap().0, n_tasks * 3);
        });
    }
}
