//! An example demonstrating hybrid encryption, which combines asymmetric (KEM)
//! and symmetric (DEM) encryption for secure key exchange and efficient data encryption.
//!
//! 混合加密示例，它结合了非对称（KEM）和对称（DEM）加密，
//! 以实现安全的密钥交换和高效的数据加密。
//!
//! To run this example:
//! ```bash
//! cargo run --example hybrid_encryption
//! ```

use anyhow::Result;
use seal_flow::crypto::algorithms::asymmetric::kem::KemAlgorithm;
use seal_flow::crypto::bincode;
use seal_flow::crypto::traits::KemAlgorithmTrait;
use seal_flow::common::header::{AeadParams, AeadParamsBuilder, SealFlowHeader};
use seal_flow::crypto::prelude::*;
use seal_flow::prelude::{EncryptionConfigurator, prepare_decryption_from_slice};
use seal_flow::sha2::{Digest, Sha256};
use std::borrow::Cow;
use seal_flow::crypto::algorithms::kdf::key::KdfKeyAlgorithm;

/// Parameters for Key Derivation Function (KDF).
///
/// 密钥派生函数（KDF）的参数。
#[derive(Clone, bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
#[bincode(crate = "bincode")]
struct KdfParams {
    algorithm: KdfKeyAlgorithm,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
}

/// A custom header for hybrid encryption. It includes the encapsulated key
/// required for the recipient to decrypt the symmetric key.
///
/// 用于混合加密的自定义标头。它包含接收方解密对称密钥所需的封装密钥。
#[derive(Clone, bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
#[bincode(crate = "bincode")]
struct HybridHeader {
    params: AeadParams,
    encapsulated_key: EncapsulatedKey,
    kem_algorithm: KemAlgorithm,
    kdf_params: KdfParams,
}

impl SealFlowHeader for HybridHeader {
    fn aead_params(&self) -> &AeadParams {
        &self.params
    }

    fn extra_data(&self) -> Option<&[u8]> {
        // Not used in this example.
        None
    }
}

fn main() -> Result<()> {
    println!("Running hybrid encryption example...");

    // --- Recipient Side: Key Generation ---
    println!("\n--- Recipient: Generating KEM key pair ---");
    let kem_algorithm = KemAlgorithm::build().kyber1024().into_asymmetric_wrapper();
    let recipient_key_pair = kem_algorithm.generate_keypair()?;
    let recipient_pk = recipient_key_pair.public_key();
    println!("  - Recipient generated public/private key pair.");

    // --- Sender Side: Encryption ---
    let plaintext = b"this is a top-secret message for the recipient";
    let aad = b"authenticated data for hybrid encryption";

    let ciphertext = {
        println!("\n--- Sender: Encrypting Data ---");

        // 1. KEM: Encapsulate a new symmetric key using the recipient's public key.
        // This creates a temporary symmetric key and its encapsulated (encrypted) version.
        // 1. KEM：使用接收者的公钥封装一个新的对称密钥。
        // 这会创建一个临时对称密钥及其封装（加密）版本。
        let (shared_secret, encapsulated_key) = kem_algorithm.encapsulate_key(&recipient_pk)?;

        // 2. KDF: Derive a symmetric key from the shared secret.
        // 2. KDF：从共享密钥派生对称密钥。
        let symmetric_algorithm = SymmetricAlgorithm::build().aes256_gcm();

        // Encapsulate KDF parameters for deriving the symmetric key from the shared secret.
        // 封装 KDF 参数，用于从共享密钥派生对称密钥。
        let kdf_params = KdfParams {
            algorithm: KdfAlgorithm::build().key().hkdf_sha256(),
            salt: Some(b"seal-flow-hybrid-salt".to_vec()), // A salt is crucial for security.
            info: Some(b"seal-flow-hybrid-info".to_vec()), // Context-specific info.
        };

        // Derive the symmetric key from the shared secret using the KDF parameters.
        // 使用 KDF 参数从共享密钥派生对称密钥。
        let ephemeral_symmetric_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(),
            symmetric_algorithm,
        )?;

        println!(
            "  - Ephemeral symmetric key generated and encapsulated with recipient's public key."
        );

        // 3. DEM: Use the ephemeral symmetric key to encrypt the actual data.
        // 3. DEM：使用临时对称密钥加密实际数据。
        let params = AeadParamsBuilder::new(symmetric_algorithm, 4096)
            .aad_hash(aad, Sha256::new())
            .base_nonce(|nonce| nonce.fill(3))
            .build();

        // Create the hybrid header, storing the encapsulated key and algorithms used.
        // 创建混合标头，存储封装的密钥和使用的算法。
        let header = HybridHeader {
            params,
            encapsulated_key,
            kem_algorithm: kem_algorithm.algorithm(),
            kdf_params,
        };
        println!("  - Hybrid header created, includes encapsulated key and KDF params.");

        // Configure and run the encryption flow.
        let configurator = EncryptionConfigurator::new(
            header,
            Cow::Owned(ephemeral_symmetric_key), // We own the ephemeral key. 我们拥有临时密钥。
            Some(aad.to_vec()),
        );

        let ciphertext = configurator
            .into_writer(Vec::new())?
            .encrypt_ordinary_to_vec(plaintext)?;

        println!("  - Data encrypted successfully.");
        ciphertext
    };

    // --- Recipient Side: Decryption ---
    let decrypted_plaintext = {
        println!("\n--- Recipient: Decrypting Data ---");

        // 1. Parse the header from the ciphertext.
        // 1. 从密文中解析标头。
        let pending_decryption = prepare_decryption_from_slice::<HybridHeader>(&ciphertext, None)?;
        let header = pending_decryption.header();
        println!("  - Hybrid header parsed successfully.");

        // 2. KEM: Decapsulate the symmetric key using the recipient's private key.
        // 2. KEM：使用接收者的私钥解封对称密钥。
        let shared_secret = header
            .kem_algorithm
            .into_asymmetric_wrapper()
            .decapsulate_key(&recipient_key_pair.private_key(), &header.encapsulated_key)?;
        println!("  - Shared secret recovered successfully.");

        // Use the KDF parameters from the header to derive the symmetric key.
        // 使用标头中的 KDF 参数来派生对称密钥。
        let kdf_params = &header.kdf_params;
        let symmetric_key = shared_secret.derive_key(
            kdf_params.algorithm,
            kdf_params.salt.as_deref(),
            kdf_params.info.as_deref(),
            header.params.algorithm(),
        )?;
        println!("  - Symmetric key derived successfully using KDF params from header.");

        // 3. DEM: Use the recovered symmetric key to decrypt the data.
        // 3. DEM：使用恢复的对称密钥解密数据。
        let decrypted_plaintext =
            pending_decryption.decrypt_ordinary(Cow::Owned(symmetric_key), Some(aad.to_vec()))?;

        println!(
            "  - Decrypted plaintext: \"{}\"",
            String::from_utf8_lossy(&decrypted_plaintext)
        );
        decrypted_plaintext
    };

    // --- Verification ---
    println!("\n--- Verification ---");
    assert_eq!(plaintext.as_ref(), decrypted_plaintext.as_slice());
    println!("✅ Success: Decrypted data matches the original plaintext.");

    Ok(())
}
