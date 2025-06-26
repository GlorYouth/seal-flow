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

    // The high-level builder API is fluent and easy to use
    let seal = SymmetricSeal::new(&key);

    // Encrypt data held in memory
    let ciphertext = seal
        .in_memory::<Aes256Gcm>()
        .encrypt(plaintext, key_id)?;

    // Decrypt data held in memory
    let decrypted_text = seal
        .in_memory::<Aes256Gcm>()
        .decrypt(&ciphertext)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully encrypted and decrypted data!");
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

Uses a builder pattern for maximum simplicity.

-   **Symmetric:** `SymmetricSeal::new(&key).<mode>.<operation>()`
-   **Hybrid:** `HybridSeal::new_encrypt(&pk).<mode>.encrypt()` or `HybridSeal::new_decrypt(&sk).<mode>.decrypt()`

### Mid-Level API (`flows` module)

Provides direct access to functions and structs for each flow.

-   **Symmetric:** `seal_flow::flows::symmetric::ordinary::encrypt(...)`
-   **Hybrid:** `seal_flow::flows::hybrid::streaming::Encryptor::new(...)`

### Low-Level API (`crypto` module)

Direct access to `seal-crypto`.

-   `seal_flow::crypto::schemes::symmetric::aes_gcm::Aes256Gcm::encrypt(...)` 