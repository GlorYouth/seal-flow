# seal-flow

[![Crates.io](https://img.shields.io/crates/v/seal-flow.svg)](https://crates.io/crates/seal-flow)
[![Docs.rs](https://docs.rs/seal-flow/badge.svg)](https://docs.rs/seal-flow)

A stateless, high-level cryptographic workflow library built on top of `seal-crypto`. It provides a unified, easy-to-use interface for common cryptographic operations like hybrid and symmetric encryption, supporting multiple processing modes including one-shot (in-memory), parallel, streaming, and asynchronous.

[中文文档 (Chinese README)](./README_CN.md)

## Core Concepts

`seal-flow` is designed with a layered API to cater to different developer needs, from beginners to experts.

### 1. Layered API

The library exposes three distinct API layers:

-   **High-Level API (`seal` module):** This is the recommended entry point for most users. It features a fluent builder pattern (`SymmetricSeal`, `HybridSeal`) that abstracts away all complexity. You simply chain methods to define the operation, select the mode, and execute.
-   **Mid-Level API (`flows` module):** For advanced users who need more fine-grained control. This layer allows you to directly access and use specific execution flows (e.g., `streaming`, `parallel`, `asynchronous`) without the builder abstraction.
-   **Low-Level API (`crypto` module):** Provides direct, unfiltered access to the underlying `seal-crypto` crate for cryptographic primitives. This is for experts who need to build custom logic on top of the core algorithms.

### 2. Interoperability

A key feature of `seal-flow` is its perfect interoperability between processing modes. Data encrypted using any mode (e.g., `streaming`) can be decrypted by any other mode (e.g., `in_memory_parallel`), as long as the underlying algorithm (`Aes256Gcm`, etc.) and keys are the same.

This is guaranteed by a unified data format and is validated by our comprehensive `interoperability_matrix` integration test. This gives you the flexibility to choose the most efficient mode for encryption and decryption independently, based on your specific needs. For example, a memory-constrained server can stream-encrypt a large file, and a powerful client machine can decrypt it in parallel for maximum performance.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
seal-flow = "0.1.0" # Replace with the latest version
```

## Usage

### Quick Start: High-Level API

Here's a quick example of a symmetric encryption/decryption roundtrip using the high-level API.

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

fn main() -> Result<()> {
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-secret-key-id".to_string();
    let plaintext = b"Data that is being protected.";

    // The high-level API factory is stateless and easy to use
    let seal = SymmetricSeal::new();

    // Encrypt data held in memory
    let ciphertext = seal
        .in_memory::<Aes256Gcm>()
        .encrypt(&key, plaintext, key_id)?;

    // Decrypt data held in memory.
    // The API promotes a safer two-step decryption process.
    // First, create a pending decryptor to inspect metadata without decrypting.
    let pending_decryptor = seal
        .in_memory::<Aes256Gcm>()
        .decrypt(&ciphertext)?;

    // You can now inspect the key ID from the header to find the correct key.
    // For this example, we'll use the key we already have.
    let decrypted_text = pending_decryptor.with_key::<Aes256Gcm>(&key)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully encrypted and decrypted data!");
    Ok(())
}
```

### Decryption Workflow: Finding and Using the Right Key

Before decrypting, you often need to know which key to use. `seal-flow` provides a safe and ergonomic `PendingDecryptor` pattern to solve this. You can inspect the metadata of an encrypted stream to get the key ID *before* supplying the key and processing the ciphertext.

This workflow prevents errors and simplifies key management.

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use std::collections::HashMap;
use std::io::Cursor;

fn main() -> Result<()> {
    // 1. Setup a key store and create a key
    let mut key_store = HashMap::new();
    let key1 = Aes256Gcm::generate_key()?;
    let key_id = "key-id-1".to_string();
    key_store.insert(key_id.clone(), key1);
    
    let plaintext = b"some secret data";
    let seal = SymmetricSeal::new();

    // 2. Encrypt data with a specific key ID
    let ciphertext = seal
        .in_memory::<Aes256Gcm>()
        .encrypt(key_store.get(&key_id).unwrap(), plaintext, key_id)?;

    // --- The Decryption Workflow ---

    // 3. Begin the decryption process by creating a pending decryptor from a reader
    let pending_decryptor = seal
        .streaming_decryptor_from_reader(Cursor::new(&ciphertext))?;

    // 4. Get the key ID from the encrypted header. This is a cheap operation.
    let found_key_id = pending_decryptor.key_id().expect("Key ID not found in header!");
    println!("Found key ID: {}", found_key_id);
    
    // 5. Retrieve the correct key from your key store.
    let decryption_key = key_store.get(found_key_id).expect("Key not found in store!");

    // 6. Provide the key to get a fully operational decryptor.
    let mut decryptor = pending_decryptor.with_key::<Aes256Gcm>(decryption_key)?;
    
    // 7. Decrypt the data.
    let mut decrypted_text = Vec::new();
    decryptor.read_to_end(&mut decrypted_text)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully identified key ID and decrypted data!");

    Ok(())
}
```

For more detailed examples covering all modes and API layers, please see the `examples/` directory.

## Running Examples

You can run the provided examples using `cargo`:

```bash
# Run the high-level symmetric encryption example
cargo run --example high_level_symmetric --features=async

# Run the mid-level hybrid encryption example
cargo run --example mid_level_hybrid --features=async
```

## License

This project is licensed under the Mozilla Public License 2.0. See the [LICENSE](LICENSE) file for details.

## API Layers in Detail

### High-Level API (`seal` module)

Uses a stateless factory for maximum simplicity and flexibility.

-   **Symmetric:** `SymmetricSeal::new().<mode>.<operation>(&key, ...)`
-   **Hybrid:** `HybridSeal::new().<mode>.encrypt(&pk, ...)` or `HybridSeal::new().<mode>.decrypt(&sk, ...)`

### Mid-Level API (`flows` module)

Provides direct access to functions and structs for each flow.

-   **Symmetric:** `seal_flow::flows::symmetric::ordinary::encrypt(...)`
-   **Hybrid:** `seal_flow::flows::hybrid::streaming::Encryptor::new(...)`

### Low-Level API (`crypto` module)

Direct access to `seal-crypto`.

-   `seal_flow::crypto::schemes::symmetric::aes_gcm::Aes256Gcm::encrypt(...)` 