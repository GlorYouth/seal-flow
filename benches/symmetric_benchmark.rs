use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use num_cpus;
use rand::{rngs::OsRng, TryRngCore};
use rayon;
use seal_flow::base::keys::TypedSymmetricKey;
use seal_flow::prelude::*;
use std::hint::black_box;
use std::io::{Cursor, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const THE_ALGORITHM: SymmetricAlgorithmEnum = SymmetricAlgorithmEnum::Aes256Gcm;

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = 1024 * KIBIBYTE;
const PLAINTEXT_SIZE: usize = MEBIBYTE; // 1 MiB

/// Generates a key and a vector of random bytes for benchmarking.
fn setup() -> (TypedSymmetricKey, Vec<u8>) {
    let key = THE_ALGORITHM
        .into_symmetric_wrapper()
        .generate_typed_key()
        .unwrap();
    let mut plaintext = vec![0u8; PLAINTEXT_SIZE];
    OsRng.try_fill_bytes(&mut plaintext).unwrap();
    (key, plaintext)
}

/// Creates a benchmark group for symmetric encryption modes.
fn benchmark_symmetric_encryption(c: &mut Criterion) {
    let (key, plaintext) = setup();
    let key_id = "benchmark_key".to_string();
    let seal = SymmetricSeal::default();

    let mut group = c.benchmark_group("Symmetric Encryption");
    group.sample_size(10); // Use a smaller sample size for heavy I/O benchmarks
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            seal.encrypt(key.clone(), key_id.clone())
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
                seal.encrypt(key.clone(), key_id.clone())
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
                .encrypt(key.clone(), key_id.clone())
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
                .encrypt(key.clone(), key_id.clone())
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
                seal.encrypt(key.clone(), key_id.clone())
                    .pipe_parallel(Cursor::new(black_box(&plaintext)), &mut encrypted_data)
                    .unwrap();
            });
        });
    });

    group.finish();
}

/// Creates a benchmark group for symmetric decryption modes.
fn benchmark_symmetric_decryption(c: &mut Criterion) {
    let (key, plaintext) = setup();
    let key_id = "benchmark_key".to_string();
    let seal = SymmetricSeal::default();

    // Prepare encrypted data for each mode to be decrypted
    let in_memory_ciphertext = seal
        .encrypt(key.clone(), key_id)
        .to_vec(&plaintext)
        .unwrap();

    let mut group = c.benchmark_group("Symmetric Decryption");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            let pending = seal
                .decrypt()
                .slice(black_box(&in_memory_ciphertext))
                .unwrap();
            pending.with_key_to_vec(&key).unwrap();
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
                pending.with_key_to_vec(&key).unwrap();
            });
        });
    });

    // --- Streaming ---
    group.bench_function("streaming", |b| {
        b.iter(|| {
            let pending = seal
                .decrypt()
                .reader(Cursor::new(black_box(&in_memory_ciphertext)))
                .unwrap();
            let mut decryptor = pending.with_key_to_reader(&key).unwrap();
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
            let mut decryptor = pending.with_key_to_async_reader(&key).await.unwrap();
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
                    .with_key_to_writer(&key, &mut decrypted_data)
                    .unwrap();
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_symmetric_encryption,
    benchmark_symmetric_decryption
);
criterion_main!(benches);
