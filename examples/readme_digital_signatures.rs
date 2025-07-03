use seal_flow::prelude::*;
use seal_crypto::{
    prelude::*,
    schemes::{
        asymmetric::traditional::rsa::Rsa2048,
        asymmetric::traditional::ecc::Ed25519,
        hash::Sha256,
        symmetric::aes_gcm::Aes256Gcm,
    },
};

type Kem = Rsa2048<Sha256>;
type Dek = Aes256Gcm;

fn main() -> Result<()> {
    let seal = HybridSeal::new();

    // 1. Generate keys for encryption (KEM) and signing.
    let (pk_kem, sk_kem) = Kem::generate_keypair()?;
    let (pk_sig, sk_sig) = Ed25519::generate_keypair()?;

    let plaintext = b"this data will be signed and encrypted";

    // 2. Encrypt and sign the data.
    let pk_kem_wrapped = AsymmetricPublicKey::new(pk_kem.to_bytes());
    let ciphertext = seal
        .encrypt::<Dek>(pk_kem_wrapped, "kem-key-id".to_string())
        .with_signer::<Ed25519>(AsymmetricPrivateKey::new(sk_sig.to_bytes()), "sig-key-id".to_string())
        .to_vec::<Kem>( plaintext)?;

    // 3. Decrypt and verify the signature.
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;

    let sk_kem_wrapped = AsymmetricPrivateKey::new(sk_kem.to_bytes());

    let decrypted_text = pending_decryptor
        .with_verification_key(SignaturePublicKey::new(pk_sig.to_bytes()))?
        .with_key(sk_kem_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully signed, encrypted, decrypted, and verified data!");
    Ok(())
} 