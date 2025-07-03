// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::time::Instant;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use librice_proto::agent::Agent;
use librice_proto::candidate::{Candidate, CandidatePair};
use stun_proto::agent::Transmit;
use stun_proto::types::TransportType;

fn bench_sendrecv_udp(c: &mut Criterion) {
    let local_addr = "192.168.1.1:1000".parse().unwrap();
    let local_candidate = Candidate::builder(
        1,
        librice_proto::candidate::CandidateType::Host,
        stun_proto::types::TransportType::Udp,
        "1",
        local_addr,
    )
    .base_address(local_addr)
    .priority(1000)
    .build();
    let remote_addr = "192.168.1.2:2000".parse().unwrap();
    let remote_candidate = Candidate::builder(
        1,
        librice_proto::candidate::CandidateType::Host,
        stun_proto::types::TransportType::Udp,
        "1",
        remote_addr,
    )
    .base_address(local_addr)
    .priority(1000)
    .build();

    let mut agent = Agent::builder().trickle_ice(true).controlling(true).build();
    let stream_id = agent.add_stream();

    let mut stream = agent.mut_stream(stream_id).unwrap();
    let component_id = stream.add_component().unwrap();
    stream.add_local_candidate(local_candidate.clone());
    stream.end_of_local_candidates();
    stream.add_remote_candidate(remote_candidate.clone());

    let pair = CandidatePair::new(local_candidate, remote_candidate);
    let mut component = stream.mut_component(component_id).unwrap();
    component.set_selected_pair(pair).unwrap();

    let mut group = c.benchmark_group("Component/Udp");
    for size in [32, 1024, 16000] {
        let mut component = stream.mut_component(component_id).unwrap();
        group.throughput(criterion::Throughput::Bytes(size as u64));
        let data = vec![1; size];
        let now = Instant::now();
        group.bench_function(BenchmarkId::new("Send", size), |b| {
            b.iter_batched(
                || data.clone(),
                |data| {
                    let _transmit = component.send(data, now);
                },
                criterion::BatchSize::SmallInput,
            )
        });
        group.bench_function(BenchmarkId::new("Recv", size), |b| {
            b.iter_batched(
                || Transmit::new(data.clone(), TransportType::Udp, remote_addr, local_addr),
                |data| {
                    let _transmit = stream.handle_incoming_data(1, data, now);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_sendrecv_tcp(c: &mut Criterion) {
    let local_addr = "192.168.1.1:1000".parse().unwrap();
    let local_candidate = Candidate::builder(
        1,
        librice_proto::candidate::CandidateType::Host,
        stun_proto::types::TransportType::Tcp,
        "1",
        local_addr,
    )
    .base_address(local_addr)
    .priority(1000)
    .tcp_type(librice_proto::candidate::TcpType::Active)
    .build();
    let remote_addr = "192.168.1.2:2000".parse().unwrap();
    let remote_candidate = Candidate::builder(
        1,
        librice_proto::candidate::CandidateType::Host,
        stun_proto::types::TransportType::Tcp,
        "1",
        remote_addr,
    )
    .base_address(local_addr)
    .priority(1000)
    .tcp_type(librice_proto::candidate::TcpType::Passive)
    .build();

    let mut agent = Agent::builder().trickle_ice(true).controlling(true).build();
    let stream_id = agent.add_stream();

    let mut stream = agent.mut_stream(stream_id).unwrap();
    let component_id = stream.add_component().unwrap();
    stream.add_local_candidate(local_candidate.clone());
    stream.end_of_local_candidates();
    stream.add_remote_candidate(remote_candidate.clone());

    let pair = CandidatePair::new(local_candidate, remote_candidate);
    let mut component = stream.mut_component(component_id).unwrap();
    component.set_selected_pair(pair).unwrap();

    let mut group = c.benchmark_group("Component/Tcp");
    for size in [32, 1024, 16000] {
        let mut component = stream.mut_component(component_id).unwrap();
        group.throughput(criterion::Throughput::Bytes(size as u64));
        let data = vec![1; size];
        let now = Instant::now();
        group.bench_function(BenchmarkId::new("Send", size), |b| {
            b.iter_batched(
                || data.clone(),
                |data| {
                    let _transmit = component.send(data, now);
                },
                criterion::BatchSize::SmallInput,
            )
        });
        group.bench_function(BenchmarkId::new("Recv", size), |b| {
            b.iter_batched(
                || {
                    let mut framed = vec![0; data.len() + 2];
                    framed[0] = ((size & 0xff00) >> 8) as u8;
                    framed[1] = (size & 0xff) as u8;
                    framed[2..].copy_from_slice(&data);
                    Transmit::new(data.clone(), TransportType::Udp, remote_addr, local_addr)
                },
                |data| {
                    let _transmit = stream.handle_incoming_data(1, data, now);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_sendrecv(c: &mut Criterion) {
    bench_sendrecv_udp(c);
    bench_sendrecv_tcp(c);
}

criterion_group!(send, bench_sendrecv);
criterion_main!(send);
