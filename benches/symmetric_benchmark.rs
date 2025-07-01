use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use num_cpus;
use rand::{rngs::OsRng, TryRngCore};
use rayon;
use seal_crypto::prelude::*;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use seal_flow::prelude::*;
use seal_flow::seal::symmetric::SymmetricSeal;
use std::hint::black_box;
use std::io::{Cursor, Write};
use tokio::io::AsyncWriteExt;

type TestDek = Aes256Gcm;

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = 1024 * KIBIBYTE;
const PLAINTEXT_SIZE: usize = MEBIBYTE; // 1 MiB

/// Generates a key and a vector of random bytes for benchmarking.
fn setup() -> (<TestDek as SymmetricKeySet>::Key, Vec<u8>) {
    let key = TestDek::generate_key().unwrap();
    let mut plaintext = vec![0u8; PLAINTEXT_SIZE];
    OsRng.try_fill_bytes(&mut plaintext).unwrap();
    (key, plaintext)
}

/// Creates a benchmark group for symmetric encryption modes.
fn benchmark_symmetric_encryption(c: &mut Criterion) {
    let (key, plaintext) = setup();
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let key_id = "benchmark_key".to_string();
    let seal = SymmetricSeal::new();

    let mut group = c.benchmark_group("Symmetric Encryption");
    group.sample_size(10); // Use a smaller sample size for heavy I/O benchmarks
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            seal.encrypt(key_wrapped.clone(), key_id.clone())
                .to_vec::<TestDek>(black_box(&plaintext))
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
                seal.encrypt(key_wrapped.clone(), key_id.clone())
                    .to_vec_parallel::<TestDek>(black_box(&plaintext))
                    .unwrap();
            });
        });
    });

    // --- Streaming ---
    group.bench_function("streaming", |b| {
        b.iter(|| {
            let mut encrypted_data = Vec::with_capacity(PLAINTEXT_SIZE + 1024);
            let mut encryptor = seal
                .encrypt(key_wrapped.clone(), key_id.clone())
                .into_writer::<TestDek, _>(&mut encrypted_data)
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
                .encrypt(key_wrapped.clone(), key_id.clone())
                .into_async_writer::<TestDek, _>(&mut encrypted_data)
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
                seal.encrypt(key_wrapped.clone(), key_id.clone())
                    .pipe_parallel::<TestDek, _, _>(
                        Cursor::new(black_box(&plaintext)),
                        &mut encrypted_data,
                    )
                    .unwrap();
            });
        });
    });

    group.finish();
}

/// Creates a benchmark group for symmetric decryption modes.
fn benchmark_symmetric_decryption(c: &mut Criterion) {
    let (key, plaintext) = setup();
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let key_id = "benchmark_key".to_string();
    let seal = SymmetricSeal::new();

    // Prepare encrypted data for each mode to be decrypted
    let in_memory_ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .to_vec::<TestDek>(&plaintext)
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
            pending.with_typed_key::<TestDek>(key.clone()).unwrap();
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
                pending.with_typed_key::<TestDek>(key.clone()).unwrap();
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
            let mut decryptor = pending.with_typed_key::<TestDek>(key.clone()).unwrap();
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
            let mut decryptor = pending.with_typed_key::<TestDek>(key.clone()).unwrap();
            let mut decrypted_data = Vec::with_capacity(PLAINTEXT_SIZE);
            tokio::io::copy(&mut decryptor, &mut decrypted_data)
                .await
                .unwrap();
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
                    .with_typed_key_to_writer::<TestDek, _>(key.clone(), &mut decrypted_data)
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
