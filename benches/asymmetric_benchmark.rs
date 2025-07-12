use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use num_cpus;
use rand::{rngs::OsRng, TryRngCore};
use rayon;
use seal_flow::algorithms::asymmetric::Kyber768;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;
use seal_flow::seal::hybrid::HybridSeal;
use std::hint::black_box;
use std::io::{Cursor, Write};
use tokio::io::AsyncWriteExt;

type TestKem = Kyber768;
type TestDek = Aes256Gcm;

const KIBIBYTE: usize = 1024;
const MEBIBYTE: usize = 1024 * KIBIBYTE;
const PLAINTEXT_SIZE: usize = MEBIBYTE; // 1 MiB

/// Generates keys and a vector of random bytes for benchmarking.
fn setup() -> (
    AsymmetricPublicKey,
    <TestKem as AsymmetricKeySet>::PrivateKey,
    Vec<u8>,
) {
    let (pk, sk) = TestKem::generate_keypair().unwrap();
    let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
    let mut plaintext = vec![0u8; PLAINTEXT_SIZE];
    OsRng.try_fill_bytes(&mut plaintext).unwrap();
    (pk_wrapped, sk, plaintext)
}

/// Creates a benchmark group for hybrid encryption modes.
fn benchmark_hybrid_encryption(c: &mut Criterion) {
    let (pk, _, plaintext) = setup();
    let kek_id = "benchmark_kek".to_string();
    let seal = HybridSeal::new();

    let mut group = c.benchmark_group("Hybrid Encryption");
    group.sample_size(10);
    group.throughput(criterion::Throughput::Bytes(PLAINTEXT_SIZE as u64));

    // --- In-memory (Ordinary) ---
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            seal.encrypt::<TestDek>(pk.clone(), kek_id.clone())
                .with_algorithm::<TestKem>()
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
                seal.encrypt::<TestDek>(pk.clone(), kek_id.clone())
                    .with_algorithm::<TestKem>()
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
                .encrypt::<TestDek>(pk.clone(), kek_id.clone())
                .with_algorithm::<TestKem>()
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
                .encrypt::<TestDek>(pk.clone(), kek_id.clone())
                .with_algorithm::<TestKem>()
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
                seal.encrypt::<TestDek>(pk.clone(), kek_id.clone())
                    .with_algorithm::<TestKem>()
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
    let seal = HybridSeal::new();

    // Prepare encrypted data for each mode to be decrypted
    let in_memory_ciphertext = seal
        .encrypt::<TestDek>(pk, kek_id)
        .with_algorithm::<TestKem>()
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
            pending.with_key::<TestKem, TestDek>(&sk).unwrap();
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
                pending.with_key::<TestKem, TestDek>(&sk).unwrap();
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
            let mut decryptor = pending.with_key::<TestKem, TestDek>(&sk).unwrap();
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
            let mut decryptor = pending
                .with_key::<TestKem, TestDek>(sk.clone())
                .await
                .unwrap();
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
                    .with_key_to_writer::<TestKem, TestDek, _>(&sk, &mut decrypted_data)
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
