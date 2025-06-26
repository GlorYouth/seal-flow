# seal-flow

[![Crates.io](https://img.shields.io/crates/v/seal-flow.svg)](https://crates.io/crates/seal-flow)
[![Docs.rs](https://docs.rs/seal-flow/badge.svg)](https://docs.rs/seal-flow)

`seal-flow` 是一个构建在 `seal-crypto` 之上的无状态、高级别的密码学工作流（workflow）库。它为混合加密和对称加密等常见的密码学操作提供了统一且易于使用的接口，并支持多种处理模式，包括一次性（内存）、并行、流式和异步模式。

## 核心设计

`seal-flow` 设计了分层的API，以满足从初学者到专家的不同开发者的需求。

### 1. 分层API

本库暴露了三个明确的API层级：

-   **高层API (`seal` 模块):** 这是推荐给绝大多数用户的入口点。它提供了一个流畅的构建者模式（`SymmetricSeal`, `HybridSeal`），抽象了所有实现的复杂性。你只需简单地链式调用方法来定义操作、选择模式并执行。
-   **中层API (`flows` 模块):** 专为需要更细粒度控制的高级用户设计。该层允许你直接访问和使用特定的执行流（例如 `streaming`, `parallel`, `asynchronous`），而无需通过构建者模式的抽象。
-   **底层API (`crypto` 模块):** 提供对底层 `seal-crypto` crate 中密码学原语的直接、无过滤的访问。这适用于需要在核心算法之上构建自定义逻辑的专家。

### 2. 互操作性

`seal-flow` 的一个关键特性是其处理模式之间的完美互操作性。使用任何一种模式（例如 `streaming`）加密的数据，都可以被任何其他模式（例如 `in_memory_parallel`）解密，只要底层的算法（如 `Aes256Gcm`）和密钥保持一致。

这一特性由统一的数据格式保证，并由我们全面的 `interoperability_matrix` 集成测试进行验证。这使你能够根据具体需求，灵活地、独立地为加密和解密选择最高效的模式。例如，一个内存受限的服务器可以流式加密一个大文件，而一台性能强大的客户端机器则可以并行解密它以获得最佳性能。

## 安装

将此行添加到你的 `Cargo.toml` 中：

```toml
[dependencies]
seal-flow = "0.1.0" # 请替换为最新版本
```

## 使用方法

### 快速上手：高层API

这是一个使用高层API进行对称加密/解密往返操作的简单示例。

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;

fn main() -> Result<()> {
    let key = Aes256Gcm::generate_key()?;
    let key_id = "my-secret-key-id".to_string();
    let plaintext = b"这是需要被保护的数据。";

    // 高层API工厂是无状态且易于使用的
    let seal = SymmetricSeal::new();

    // 加密内存中的数据
    let ciphertext = seal
        .in_memory::<Aes256Gcm>()
        .encrypt(&key, plaintext, key_id)?;

    // 解密内存中的数据
    // API 推荐一个更安全的两步解密流程。
    // 首先，创建一个待定解密器，在不解密的情况下检查元数据。
    let pending_decryptor = seal
        .in_memory::<Aes256Gcm>()
        .decrypt(&ciphertext)?;

    // 现在你可以从头部检查密钥ID，以找到正确的密钥。
    // 在此示例中，我们将使用已有的密钥。
    let decrypted_text = pending_decryptor.with_key(&key)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("成功加密和解密数据！");
    Ok(())
}
```

### 解密工作流：查找并使用正确的密钥

在解密之前，你通常需要知道该使用哪个密钥。`seal-flow` 提供了一个安全且符合人体工程学的 `PendingDecryptor` 模式来解决这个问题。你可以在提供密钥和处理密文*之前*，检查加密流的元数据以获取密钥ID。

这个工作流可以防止出错并简化密钥管理。

```rust
use seal_flow::prelude::*;
use seal_crypto::prelude::SymmetricKeyGenerator;
use seal_crypto::schemes::symmetric::aes_gcm::Aes256Gcm;
use std::collections::HashMap;
use std::io::Cursor;

fn main() -> Result<()> {
    // 1. 设置一个密钥存储并创建一个密钥
    let mut key_store = HashMap::new();
    let key1 = Aes256Gcm::generate_key()?;
    let key_id = "key-id-1".to_string();
    key_store.insert(key_id.clone(), key1);
    
    let plaintext = b"一些机密数据";
    let seal = SymmetricSeal::new();

    // 2. 使用特定的密钥ID加密数据
    let ciphertext = seal
        .in_memory::<Aes256Gcm>()
        .encrypt(key_store.get(&key_id).unwrap(), plaintext, key_id)?;

    // --- 解密工作流 ---

    // 3. 通过从读取器创建一个待定解密器来开始解密过程
    let pending_decryptor = seal
        .streaming_decryptor_from_reader::<Aes256Gcm, _>(Cursor::new(&ciphertext))?;

    // 4. 从加密头部获取密钥ID。这是一个廉价的操作。
    let found_key_id = pending_decryptor.key_id().expect("在头部未找到密钥ID！");
    println!("找到密钥ID: {}", found_key_id);
    
    // 5. 从你的密钥存储中检索正确的密钥。
    let decryption_key = key_store.get(found_key_id).expect("在存储中未找到密钥！");

    // 6. 提供密钥以获得一个功能完备的解密器。
    let mut decryptor = pending_decryptor.with_key(decryption_key)?;
    
    // 7. 解密数据。
    let mut decrypted_text = Vec::new();
    decryptor.read_to_end(&mut decrypted_text)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("成功识别密钥ID并解密数据！");

    Ok(())
}
```

关于涵盖所有模式和API层级的更详细示例，请参阅 `examples/` 目录。

## 运行示例

你可以使用 `cargo` 来运行我们提供的示例：

```bash
# 运行高层对称加密示例
cargo run --example high_level_symmetric --features=async

# 运行中层混合加密示例
cargo run --example mid_level_hybrid --features=async
```

## 许可证 (License)

本项目采用 Mozilla Public License 2.0 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## API分层详解

### 高层API (`seal` module)

使用无状态工厂以实现最大程度的简洁性和灵活性。

-   **对称加密:** `SymmetricSeal::new().<mode>.<operation>(&key, ...)`
-   **混合加密:** `HybridSeal::new().<mode>.encrypt(&pk, ...)` 或 `HybridSeal::new().<mode>.decrypt(&sk, ...)`

### 中层API (`flows` module)

提供对每个流程的函数和结构体的直接访问。

-   **对称加密:** `seal_flow::flows::symmetric::ordinary::encrypt(...)`
-   **混合加密:** `seal_flow::flows::hybrid::streaming::Encryptor::new(...)`

### 底层API (`crypto` module)

直接访问 `seal-crypto`。

-   `seal_flow::crypto::schemes::symmetric::aes_gcm::Aes256Gcm::encrypt(...)` 