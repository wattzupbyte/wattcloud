//! Performance benchmarks for sdk-core crypto operations.
//!
//! Run with: cargo bench
//! Results are saved to target/criterion/ as HTML reports.
//!
//! These benchmarks establish a regression baseline. Any slowdown >10% should
//! be investigated before merging.
//!
//! unwrap() is appropriate in benches: a crypto-primitive Err signals a bug
//! in the code under test, and we want the bench to surface that as a panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sdk_core::byo::argon2id_derive_byo;
use sdk_core::crypto::hashing::{blake2b_256, hmac_sha256};
use sdk_core::crypto::kdf::argon2id_derive;
use sdk_core::crypto::pqc::{
    generate_hybrid_keypair, hybrid_decapsulate_v6, hybrid_encapsulate_v6,
};
use sdk_core::crypto::symmetric::{aes_gcm_encrypt, generate_aes_key};
use sdk_core::crypto::wire_format::{decrypt_file_v7, encrypt_file_v7};
use std::hint::black_box;

fn bench_argon2id(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");
    // Note: Argon2id with m=65536 KiB takes ~1-3s — use sample count of 3
    group.sample_size(3);

    let password = b"BenchmarkPassword123!";
    let salt = [0x42u8; 32];

    group.bench_function("derive_64_bytes", |b| {
        b.iter(|| argon2id_derive(black_box(password), black_box(&salt)).unwrap())
    });

    group.finish();
}

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    let data_1kb = vec![0x42u8; 1024];
    let data_1mb = vec![0x42u8; 1024 * 1024];

    group.throughput(Throughput::Bytes(1024));
    group.bench_with_input(
        BenchmarkId::new("blake2b_256", "1KB"),
        &data_1kb,
        |b, data| b.iter(|| blake2b_256(black_box(data))),
    );

    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_with_input(
        BenchmarkId::new("blake2b_256", "1MB"),
        &data_1mb,
        |b, data| b.iter(|| blake2b_256(black_box(data))),
    );

    let key = [0x11u8; 32];
    group.throughput(Throughput::Bytes(1024));
    group.bench_with_input(
        BenchmarkId::new("hmac_sha256", "1KB"),
        &data_1kb,
        |b, data| b.iter(|| hmac_sha256(black_box(&key), black_box(data)).unwrap()),
    );

    group.finish();
}

fn bench_aes_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm");
    let key = generate_aes_key().unwrap();

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}KB", size / 1024)),
            &data,
            |b, d| b.iter(|| aes_gcm_encrypt(black_box(d), black_box(&key)).unwrap()),
        );
    }

    group.finish();
}

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem");
    let kp = generate_hybrid_keypair().unwrap();

    group.bench_function("hybrid_encapsulate_v6", |b| {
        b.iter(|| {
            hybrid_encapsulate_v6(
                black_box(&kp.mlkem_public_key),
                black_box(&kp.x25519_public_key),
            )
            .unwrap()
        })
    });

    let enc = hybrid_encapsulate_v6(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();
    group.bench_function("hybrid_decapsulate_v6", |b| {
        b.iter(|| {
            hybrid_decapsulate_v6(
                black_box(&enc.eph_x25519_pub),
                black_box(&enc.mlkem_ciphertext),
                black_box(&enc.encrypted_file_key),
                black_box(&kp.mlkem_secret_key),
                black_box(&kp.x25519_secret_key),
            )
            .unwrap()
        })
    });

    group.finish();
}

fn bench_v7_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("v7_file");
    let kp = generate_hybrid_keypair().unwrap();

    for size in [64 * 1024usize, 1024 * 1024, 10 * 1024 * 1024] {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{}MB", size / (1024 * 1024))),
            &data,
            |b, d| {
                b.iter(|| {
                    encrypt_file_v7(
                        black_box(&kp.mlkem_public_key),
                        black_box(&kp.x25519_public_key),
                        black_box(&[d.as_slice()]),
                    )
                    .unwrap()
                })
            },
        );

        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[&data]).unwrap();

        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{}MB", size / (1024 * 1024))),
            &encrypted,
            |b, enc| {
                b.iter(|| {
                    decrypt_file_v7(
                        black_box(enc),
                        black_box(&kp.mlkem_secret_key),
                        black_box(&kp.x25519_secret_key),
                    )
                    .unwrap()
                })
            },
        );
    }

    group.finish();
}

/// BYO vault KDF: Argon2id with 128MB / 3 iter / 4 parallel (BYO_PLAN §1.3).
/// This is the production parameter set used on every vault unlock.
/// Target: < 10s on reference hardware.
fn bench_argon2id_byo(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id_byo");
    // 128MB takes several seconds — limit to 3 samples to keep CI tractable.
    group.sample_size(3);
    // Signal that this is a latency-sensitive measurement (no throughput unit).
    group.measurement_time(std::time::Duration::from_secs(30));

    let password = b"BYOBenchmarkPassphrase!TestOnly";
    let salt = [0xDE_u8; 32];

    group.bench_function("argon2id_128mb_3iter_4p", |b| {
        b.iter(|| argon2id_derive_byo(black_box(password), black_box(&salt)).unwrap())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_argon2id,
    bench_argon2id_byo,
    bench_hashing,
    bench_aes_gcm,
    bench_kem,
    bench_v7_file,
);
criterion_main!(benches);
