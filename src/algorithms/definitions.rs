//! Defines the concrete algorithm types and implements the corresponding traits.

use super::traits::{
    AsymmetricAlgorithmDetails, KdfAlgorithmDetails, SignatureAlgorithmDetails,
    SymmetricAlgorithmDetails, XofAlgorithmDetails,
};
use crate::common;
use seal_crypto::prelude::Hasher;

use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
    Dilithium2, Dilithium3, Dilithium5,
};
use seal_crypto::schemes::asymmetric::post_quantum::kyber::{Kyber1024, Kyber512, Kyber768};
use seal_crypto::schemes::asymmetric::traditional::{
    ecc::{EcdsaP256, Ed25519},
    rsa::{Rsa2048, Rsa4096},
};
use seal_crypto::schemes::kdf::hkdf::HkdfSha256;
use seal_crypto::schemes::symmetric::aes_gcm::{Aes128Gcm, Aes256Gcm};
use seal_crypto::schemes::symmetric::chacha20_poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use seal_crypto::schemes::xof::shake::Shake256;

// --- Symmetric Algorithms ---
impl SymmetricAlgorithmDetails for Aes128Gcm {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes128Gcm;
}

impl SymmetricAlgorithmDetails for Aes256Gcm {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::Aes256Gcm;
}

impl SymmetricAlgorithmDetails for ChaCha20Poly1305 {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::ChaCha20Poly1305;
}

impl SymmetricAlgorithmDetails for XChaCha20Poly1305 {
    const ALGORITHM: common::algorithms::SymmetricAlgorithm =
        common::algorithms::SymmetricAlgorithm::XChaCha20Poly1305;
}

// --- Asymmetric Algorithms ---

impl<H: Hasher> AsymmetricAlgorithmDetails for Rsa2048<H> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa2048;
}

impl<H: Hasher> AsymmetricAlgorithmDetails for Rsa4096<H> {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Rsa4096;
}

impl AsymmetricAlgorithmDetails for Kyber512 {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber512;
}

impl AsymmetricAlgorithmDetails for Kyber768 {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber768;
}

impl AsymmetricAlgorithmDetails for Kyber1024 {
    const ALGORITHM: common::algorithms::AsymmetricAlgorithm =
        common::algorithms::AsymmetricAlgorithm::Kyber1024;
}

// --- Signature Algorithms ---

impl SignatureAlgorithmDetails for Dilithium2 {
    const ALGORITHM: common::algorithms::SignatureAlgorithm =
        common::algorithms::SignatureAlgorithm::Dilithium2;
}

impl SignatureAlgorithmDetails for Dilithium3 {
    const ALGORITHM: common::algorithms::SignatureAlgorithm =
        common::algorithms::SignatureAlgorithm::Dilithium3;
}

impl SignatureAlgorithmDetails for Dilithium5 {
    const ALGORITHM: common::algorithms::SignatureAlgorithm =
        common::algorithms::SignatureAlgorithm::Dilithium5;
}

impl SignatureAlgorithmDetails for Ed25519 {
    const ALGORITHM: common::algorithms::SignatureAlgorithm =
        common::algorithms::SignatureAlgorithm::Ed25519;
}

impl SignatureAlgorithmDetails for EcdsaP256 {
    const ALGORITHM: common::algorithms::SignatureAlgorithm =
        common::algorithms::SignatureAlgorithm::EcdsaP256;
}

impl KdfAlgorithmDetails for HkdfSha256 {
    const ALGORITHM: common::algorithms::KdfAlgorithm =
        common::algorithms::KdfAlgorithm::HkdfSha256;
}

impl XofAlgorithmDetails for Shake256 {
    const ALGORITHM: common::algorithms::XofAlgorithm = common::algorithms::XofAlgorithm::Shake256;
}
