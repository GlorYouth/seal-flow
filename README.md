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
        .encrypt::<Aes256Gcm>(&key, key_id)
        .to_vec(plaintext)?;

    // Decrypt data held in memory.
    // The API promotes a safer two-step decryption process.
    // First, create a pending decryptor to inspect metadata without decrypting.
    let pending_decryptor = seal.decrypt().from_slice(&ciphertext)?;

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
        .encrypt::<Aes256Gcm>(key_store.get(&key_id).unwrap(), key_id)
        .to_vec(plaintext)?;

    // --- The Decryption Workflow ---

    // 3. Begin the decryption process by creating a pending decryptor from a reader
    let pending_decryptor = seal.decrypt().from_reader(Cursor::new(&ciphertext))?;

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

### Key Management with Providers

For more robust and decoupled key management, `seal-flow` introduces the `SymmetricKeyProvider` and `AsymmetricKeyProvider` traits. Instead of manually fetching a key from a store, you can implement these traits to let the decryptor automatically look up the correct key.

This is especially useful for integrating with a Key Management Service (KMS), a database, or other centralized configuration systems.

Here's how to use a provider:

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use std::collections::HashMap;

// 1. Define your key provider struct.
struct MyKeyProvider {
    key_store: HashMap<String, <Aes256Gcm as SymmetricKeySet>::Key>,
}

// 2. Implement the `SymmetricKeyProvider` trait.
impl SymmetricKeyProvider for MyKeyProvider {
    fn get_symmetric_key<'a>(&'a self, key_id: &str) -> Option<SymmetricKey<'a>> {
        // Look up the key and wrap it in the `SymmetricKey` enum.
        self.key_store.get(key_id).map(|k| SymmetricKey::Aes256Gcm(k))
    }
}

fn main() -> Result<()> {
    // 3. Create an instance of your provider.
    let mut key_store = HashMap::new();
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-kms-key".to_string();
    key_store.insert(key_id.clone(), key);
    let provider = MyKeyProvider { key_store };
    
    let plaintext = b"some secret data";
    let seal = SymmetricSeal::new();

    // Encrypt with the key from the provider (or any other source).
    let ciphertext = seal
        .encrypt::<Aes256Gcm>(provider.key_store.get(&key_id).unwrap(), key_id)
        .to_vec(plaintext)?;

    // 4. Decrypt using the provider.
    // `seal-flow` automatically calls `get_symmetric_key` with the ID from the header.
    let pending_decryptor = seal.decrypt().from_slice(&ciphertext)?;
    let decrypted_text = pending_decryptor.with_provider(&provider)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted using the key provider!");

    Ok(())
}
```

### Using Associated Data (AAD)

`seal-flow` supports Associated Data (AAD), which is data that is authenticated but not encrypted. This is useful for binding ciphertext to its context, such as a version number, filename, or other metadata, without needing to encrypt the metadata itself.

The `with_aad()` method can be chained during both encryption and decryption. The AAD must be identical during both processes for decryption to succeed.

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

fn main() -> Result<()> {
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-aad-key".to_string();
    let plaintext = b"This data is secret.";
    let aad = b"This is my context metadata.";

    let seal = SymmetricSeal::new();

    // Encrypt with AAD
    let ciphertext = seal
        .encrypt::<Aes256Gcm>(&key, key_id)
        .with_aad(aad)
        .to_vec(plaintext)?;

    // To decrypt, you MUST provide the same AAD.
    let pending_decryptor = seal.decrypt().from_slice(&ciphertext)?;
    let decrypted_text = pending_decryptor
        .with_aad(aad) // Provide the same AAD
        .with_key::<Aes256Gcm>(&key)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted with AAD!");

    // Attempting to decrypt with wrong or missing AAD will fail.
    let pending_fail = seal.decrypt().from_slice(&ciphertext)?;
    assert!(pending_fail.with_aad(b"wrong aad").with_key::<Aes256Gcm>(&key).is_err());
    
    let pending_fail2 = seal.decrypt().from_slice(&ciphertext)?;
    assert!(pending_fail2.with_key::<Aes256Gcm>(&key).is_err());
    
    println!("Correctly failed to decrypt with wrong/missing AAD.");

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

Uses a stateless factory for maximum simplicity and flexibility. All operations start with `encrypt` or `decrypt`.

-   **Symmetric:** `SymmetricSeal::new().encrypt(&key, ...).to_vec(plaintext)?`
-   **Hybrid:** `HybridSeal::new().encrypt(&pk, ...).to_vec(plaintext)?`

### Mid-Level API (`flows` module)

Provides direct access to functions and structs for each flow.

-   **Symmetric:** `seal_flow::flows::symmetric::ordinary::encrypt(...)`
-   **Hybrid:** `seal_flow::flows::hybrid::streaming::Encryptor::new(...)`

### Low-Level API (`crypto` module)

Direct access to `seal-crypto`.

-   `seal_flow::crypto::schemes::symmetric::aes_gcm::Aes256Gcm::encrypt(...)` 