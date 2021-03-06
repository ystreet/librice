// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::sync::Arc;

use futures::StreamExt;

use librice::agent::{Agent, AgentMessage};
use librice::component::ComponentState;
use librice::stream::Credentials;

mod common;

#[test]
fn agent_static_connection() {
    common::debug_init();
    async_std::task::block_on(async move {
        let lagent = Arc::new(Agent::default());
        lagent.set_controlling(true);
        let ragent = Arc::new(Agent::default());

        let lcreds = Credentials::new("luser".into(), "lpass".into());
        let rcreds = Credentials::new("ruser".into(), "rpass".into());

        let mut l_msg_s = lagent.message_channel();
        let lstream = lagent.add_stream();
        lstream.set_local_credentials(lcreds.clone());
        lstream.set_remote_credentials(rcreds.clone());
        let lcomp = lstream.add_component().unwrap();

        let mut r_msg_s = ragent.message_channel();
        let rstream = ragent.add_stream();
        rstream.set_local_credentials(rcreds);
        rstream.set_remote_credentials(lcreds);
        let rcomp = rstream.add_component().unwrap();

        async_std::task::spawn({
            let agent = lagent.clone();
            async move {
                agent.run_loop().await.unwrap();
            }
        });
        async_std::task::spawn({
            let agent = ragent.clone();
            async move {
                agent.run_loop().await.unwrap();
            }
        });

        // poor-man's async semaphore
        let (lgatherdone_send, lgatherdone_recv) = async_channel::bounded::<i32>(1);
        let lgather = async_std::task::spawn({
            let rstream = rstream.clone();
            async move {
                while let Some(msg) = l_msg_s.next().await {
                    match msg {
                        AgentMessage::NewLocalCandidate(comp, cand) => {
                            rstream.add_remote_candidate(comp.id, cand).unwrap()
                        }
                        AgentMessage::GatheringCompleted(_comp) => {
                            lgatherdone_send.send(0).await.unwrap()
                        }
                        AgentMessage::ComponentStateChange(_comp, state) => {
                            if state == ComponentState::Connected || state == ComponentState::Failed
                            {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let (rgatherdone_send, rgatherdone_recv) = async_channel::bounded::<i32>(1);
        let rgather = async_std::task::spawn({
            let lstream = lstream.clone();
            async move {
                while let Some(msg) = r_msg_s.next().await {
                    match msg {
                        AgentMessage::NewLocalCandidate(comp, cand) => {
                            lstream.add_remote_candidate(comp.id, cand).unwrap()
                        }
                        AgentMessage::GatheringCompleted(_comp) => {
                            rgatherdone_send.send(0).await.unwrap()
                        }
                        AgentMessage::ComponentStateChange(_comp, state) => {
                            if state == ComponentState::Connected || state == ComponentState::Failed
                            {
                                break;
                            }
                        }
                    }
                }
            }
        });

        futures::try_join!(lstream.gather_candidates(), rstream.gather_candidates()).unwrap();

        futures::try_join!(lgatherdone_recv.recv(), rgatherdone_recv.recv()).unwrap();

        lagent.start().unwrap();
        ragent.start().unwrap();

        futures::join!(lgather, rgather);

        let rcomp_recv_stream = rcomp.receive_stream();
        let data = vec![5; 8];
        lcomp.send(&data).await.unwrap();
        futures::pin_mut!(rcomp_recv_stream);
        let received = rcomp_recv_stream.next().await.unwrap();
        assert_eq!(data, received);

        let lcomp_recv_stream = lcomp.receive_stream();
        let data = vec![3; 8];
        rcomp.send(&data).await.unwrap();
        futures::pin_mut!(lcomp_recv_stream);
        let received = lcomp_recv_stream.next().await.unwrap();
        assert_eq!(data, received);

        futures::try_join!(lagent.close(), ragent.close()).unwrap();
    });
}
