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
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // Decrypt data held in memory.
    // The API promotes a safer two-step decryption process.
    // First, create a pending decryptor to inspect metadata without decrypting.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;

    // You can now inspect the key ID from the header to find the correct key.
    // For this example, we'll use the key we already have.
    let decrypted_text = pending_decryptor.with_typed_key::<Aes256Gcm>(key)?;

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
    let key = Aes256Gcm::generate_key()?;
    let key_id = "key-id-1".to_string();
    key_store.insert(key_id.clone(), key.clone());
    
    let plaintext = b"some secret data";
    let seal = SymmetricSeal::new();

    // 2. Encrypt data with a specific key ID
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // --- The Decryption Workflow ---

    // 3. Begin the decryption process by creating a pending decryptor from a reader
    let pending_decryptor = seal.decrypt().reader(Cursor::new(&ciphertext))?;

    // 4. Get the key ID from the encrypted header. This is a cheap operation.
    let found_key_id = pending_decryptor.key_id().expect("Key ID not found in header!");
    println!("Found key ID: {}", found_key_id);
    
    // 5. Retrieve the correct key from your key store.
    let decryption_key = key_store.get(found_key_id).expect("Key not found in store!");

    // 6. Provide the key to get a fully operational decryptor.
    let mut decryptor = pending_decryptor.with_typed_key::<Aes256Gcm>(decryption_key.clone())?;
    
    // 7. Decrypt the data.
    let mut decrypted_text = Vec::new();
    decryptor.read_to_end(&mut decrypted_text)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully identified key ID and decrypted data!");

    Ok(())
}
```

### Simplified Key Management with Key Wrappers

`seal-flow` uses strongly-typed key wrappers like `SymmetricKey` and `AsymmetricPrivateKey` to improve security and prevent key misuse. Instead of passing raw bytes, you pass these wrapper types.

For decryption, there are two primary methods to supply a key:

1.  `with_key(key: K)`: This is the simplest method. `K` is a key wrapper struct (e.g., `SymmetricKey`). This method infers the cryptographic algorithm from the ciphertext header, providing a streamlined and secure default. It will automatically parse the header, select the right algorithm, and then attempt decryption. This is the recommended approach for most use cases.

2.  `with_typed_key<A>(key: A::Key)`: This method is for advanced scenarios where you want to explicitly specify which cryptographic algorithm `A` to use, overriding what's in the header. `A::Key` is the concrete key type from `seal-crypto` (e.g., `aes_gcm::Key`). This can be useful for legacy systems or custom protocols where the header might not be trusted or available.

Here's an example of the recommended `with_key` approach:

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use std::collections::HashMap;

fn main() -> Result<()> {
    // Setup: Create and store a key.
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-kms-key".to_string();
    let plaintext = b"some secret data";

    // In a real application, you would store and retrieve the raw key bytes.
    let key_bytes = key.to_bytes();
    
    let seal = SymmetricSeal::new();

    // Encrypt with the wrapped key.
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // Decryption:
    // 1. In a real scenario, you'd fetch the key bytes from a KMS or database.
    let retrieved_key_bytes = key_bytes; // Simulate fetching

    // 2. Wrap the raw bytes in the `SymmetricKey` type.
    let decryption_key = SymmetricKey::new(retrieved_key_bytes);

    // 3. Decrypt using `with_key`.
    // `seal-flow` automatically infers the algorithm (Aes256Gcm) from the header.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let decrypted_text = pending_decryptor.with_key(decryption_key)?;

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
    let key_wrapped = SymmetricKey::new(key.to_bytes());
    let ciphertext = seal
        .encrypt(key_wrapped, key_id)
        .with_aad(aad)
        .to_vec::<Aes256Gcm>(plaintext)?;

    // To decrypt, you MUST provide the same AAD.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    let decrypted_text = pending_decryptor
        .with_aad(aad) // Provide the same AAD
        .with_typed_key::<Aes256Gcm>(key.clone())?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully decrypted with AAD!");

    // Attempting to decrypt with wrong or missing AAD will fail.
    let pending_fail = seal.decrypt().slice(&ciphertext)?;
    assert!(pending_fail.with_aad(b"wrong aad").with_typed_key::<Aes256Gcm>(key.clone()).is_err());
    
    let pending_fail2 = seal.decrypt().slice(&ciphertext)?;
    assert!(pending_fail2.with_typed_key::<Aes256Gcm>(key).is_err());
    
    println!("Correctly failed to decrypt with wrong/missing AAD.");

    Ok(())
}
```

### Hybrid Encryption Example

Here is an example of hybrid encryption using the high-level API. This demonstrates encrypting with a public key and decrypting with the corresponding private key, retrieved as bytes from a key store.

```rust
use seal_flow::prelude::*;
use seal_crypto::{
    prelude::*,
    schemes::asymmetric::traditional::rsa::Rsa2048,
    schemes::hash::Sha256,
    schemes::symmetric::aes_gcm::Aes256Gcm,
};
use std::collections::HashMap;

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;

fn main() -> Result<()> {
    // 1. Setup: Generate a key pair and store the private key.
    let (pk, sk) = Kem::generate_keypair()?;

    let mut private_key_store = HashMap::new();
    let kek_id = "my-hybrid-key".to_string();
    private_key_store.insert(kek_id.clone(), sk.clone());

    let plaintext = b"This is a secret message for hybrid encryption.";
    let seal = HybridSeal::new();

    // 2. Encrypt using the public key.
    let pk_wrapped = AsymmetricPublicKey::new(pk.to_bytes());
    let ciphertext = seal
        .encrypt::<Dek>(pk_wrapped, kek_id)
        .to_vec::<Kem>(plaintext)?;

    // 3. Decrypt: First, create a pending decryptor to inspect the header.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;
    
    // 4. Find the key ID and retrieve the private key from the store.
    let found_kek_id = pending_decryptor.kek_id().unwrap();
    let private_key = private_key_store.get(found_kek_id).unwrap();

    // 5. Use the private key to decrypt the data.
    let decrypted_text = pending_decryptor.with_typed_key::<Kem, Dek>(private_key)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully performed hybrid encryption and decryption!");

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