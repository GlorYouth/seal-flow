use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use num_cpus;
use rand::{rngs::OsRng, TryRngCore};
use rayon;
use seal_flow::base::keys::{TypedAsymmetricPrivateKey, TypedAsymmetricPublicKey};
use seal_flow::prelude::*;
use std::hint::black_box;
use std::io::{Cursor, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEM: AsymmetricAlgorithmEnum = AsymmetricAlgorithmEnum::Kyber768;
const DEM: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = 1024 * KIBIBYTE;
const PLAINTEXT_SIZE: usize = MEBIBYTE; // 1 MiB

/// Generates keys and a vector of random bytes for benchmarking.
fn setup() -> (
    TypedAsymmetricPublicKey,
    TypedAsymmetricPrivateKey,
    Vec<u8>,
) {
    let (pk, sk) = KEM
        .into_asymmetric_wrapper()
        .generate_keypair()
        .unwrap()
        .into_keypair();
    let mut plaintext = vec![0u8; PLAINTEXT_SIZE];
    OsRng.try_fill_bytes(&mut plaintext).unwrap();
    (pk, sk, plaintext)
}

/// Creates a benchmark group for hybrid encryption modes.
fn benchmark_hybrid_encryption(c: &mut Criterion) {
    let (pk, _, plaintext) = setup();
    let kek_id = "benchmark_kek".to_string();
    let seal = HybridSeal::default();

    let mut group = c.benchmark_group("Hybrid Encryption");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            seal.encrypt(pk.clone(), kek_id.clone())
                .execute_with(DEM)
                .to_vec(black_box(&plaintext))
                .unwrap();
        });
    });

    // --- In-memory Parallel ---
    group.bench_function("in_memory_parallel", |b| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .unwrap();
        pool.install(|| {
            b.iter(|| {
                seal.encrypt(pk.clone(), kek_id.clone())
                    .execute_with(DEM)
                    .to_vec_parallel(black_box(&plaintext))
                    .unwrap();
            });
        });
    });

    // --- Streaming ---
    group.bench_function("streaming", |b| {
        b.iter(|| {
            let mut encrypted_data = Vec::with_capacity(PLAINTEXT_SIZE + 1024);
            let mut encryptor = seal
                .encrypt(pk.clone(), kek_id.clone())
                .execute_with(DEM)
                .into_writer(&mut encrypted_data)
                .unwrap();
            encryptor.write_all(black_box(&plaintext)).unwrap();
            encryptor.finish().unwrap();
        });
    });

    // --- Asynchronous Streaming ---
    group.bench_function("asynchronous", |b: &mut Bencher| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        b.to_async(&runtime).iter(|| async {
            let mut encrypted_data = Vec::with_capacity(PLAINTEXT_SIZE + 1024);
            let mut encryptor = seal
                .encrypt(pk.clone(), kek_id.clone())
                .execute_with(DEM)
                .into_async_writer(&mut encrypted_data)
                .await
                .unwrap();
            encryptor.write_all(black_box(&plaintext)).await.unwrap();
            encryptor.shutdown().await.unwrap();
        });
    });

    // --- Parallel Streaming ---
    group.bench_function("parallel_streaming", |b| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .unwrap();
        pool.install(|| {
            b.iter(|| {
                let mut encrypted_data = Vec::with_capacity(PLAINTEXT_SIZE + 1024);
                seal.encrypt(pk.clone(), kek_id.clone())
                    .execute_with(DEM)
                    .pipe_parallel(Cursor::new(black_box(&plaintext)), &mut encrypted_data)
                    .unwrap();
            });
        });
    });

    group.finish();
}

/// Creates a benchmark group for hybrid decryption modes.
fn benchmark_hybrid_decryption(c: &mut Criterion) {
    let (pk, sk, plaintext) = setup();
    let kek_id = "benchmark_kek".to_string();
    let seal = HybridSeal::default();

    // Prepare encrypted data for each mode to be decrypted
    let in_memory_ciphertext = seal
        .encrypt(pk, kek_id)
        .execute_with(DEM)
        .to_vec(&plaintext)
        .unwrap();

    let mut group = c.benchmark_group("Hybrid Decryption");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            let pending = seal
                .decrypt()
                .slice(black_box(&in_memory_ciphertext))
                .unwrap();
            pending.with_key_to_vec(&sk).unwrap();
        });
    });

    // --- In-memory Parallel ---
    group.bench_function("in_memory_parallel", |b| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .unwrap();
        pool.install(|| {
            b.iter(|| {
                let pending = seal
                    .decrypt()
                    .slice_parallel(black_box(&in_memory_ciphertext))
                    .unwrap();
                pending.with_key_to_vec(&sk).unwrap();
            });
        });
    });

    // --- Streaming ---
    group.bench_function("streaming", |b| {
        b.iter(|| {
            let pending = seal
                .decrypt()
                .reader(Cursor::new(black_box(in_memory_ciphertext.clone())))
                .unwrap();
            let mut decryptor = pending.with_key_to_reader(&sk).unwrap();
            let mut decrypted_data = Vec::with_capacity(PLAINTEXT_SIZE);
            std::io::copy(&mut decryptor, &mut decrypted_data).unwrap();
        });
    });

    // --- Asynchronous Streaming ---
    group.bench_function("asynchronous", |b: &mut Bencher| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        b.to_async(&runtime).iter(|| async {
            let pending = seal
                .decrypt()
                .async_reader(Cursor::new(black_box(&in_memory_ciphertext)))
                .await
                .unwrap();
            let mut decryptor = pending.with_key_to_reader(&sk).await.unwrap();
            let mut decrypted_data = Vec::with_capacity(PLAINTEXT_SIZE);
            decryptor.read_to_end(&mut decrypted_data).await.unwrap();
        });
    });

    // --- Parallel Streaming ---
    group.bench_function("parallel_streaming", |b| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .unwrap();
        pool.install(|| {
            b.iter(|| {
                let mut decrypted_data = Vec::with_capacity(PLAINTEXT_SIZE);
                let pending = seal
                    .decrypt()
                    .reader_parallel(Cursor::new(black_box(&in_memory_ciphertext)))
                    .unwrap();
                pending
                    .with_key_to_writer(&sk, &mut decrypted_data)
                    .unwrap();
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_hybrid_encryption,
    benchmark_hybrid_decryption
);
criterion_main!(benches);
