//! Defines the concrete algorithm types and implements the corresponding traits.

use crate::algorithms::traits::{
    KdfAlgorithmDetails, SignatureAlgorithmDetails, 
    XofAlgorithmDetails,
};
use crate::common;
// --- Signature Algorithms ---
pub mod signature {
    use super::*;
    pub use seal_crypto::schemes::asymmetric::post_quantum::dilithium::{
        Dilithium2, Dilithium3, Dilithium5,
    };
    pub use seal_crypto::schemes::asymmetric::traditional::ecc::{EcdsaP256, Ed25519};

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
}

pub mod kdf {
    use super::*;
    pub use seal_crypto::schemes::kdf::hkdf::{HkdfSha256, HkdfSha384, HkdfSha512};
    pub mod passwd {
        pub use seal_crypto::schemes::kdf::{
            argon2::Argon2,
            pbkdf2::{Pbkdf2Sha256, Pbkdf2Sha384, Pbkdf2Sha512},
        };
    }

    impl KdfAlgorithmDetails for HkdfSha256 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha256;
    }

    impl KdfAlgorithmDetails for HkdfSha384 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha384;
    }

    impl KdfAlgorithmDetails for HkdfSha512 {
        const ALGORITHM: common::algorithms::KdfAlgorithm =
            common::algorithms::KdfAlgorithm::HkdfSha512;
    }
}

pub mod xof {
    use super::*;
    pub use seal_crypto::schemes::xof::shake::{Shake128, Shake256};

    impl XofAlgorithmDetails for Shake128 {
        const ALGORITHM: common::algorithms::XofAlgorithm =
            common::algorithms::XofAlgorithm::Shake128;
    }

    impl XofAlgorithmDetails for Shake256 {
        const ALGORITHM: common::algorithms::XofAlgorithm =
            common::algorithms::XofAlgorithm::Shake256;
    }
}

pub mod hash {
    pub use seal_crypto::schemes::hash::{Sha256, Sha384, Sha512};
}
