use seal_flow::prelude::*;
use seal_crypto::{
    prelude::{DigestXofReader, XofDerivation}, // Import traits
    schemes::{
        kdf::{hkdf::HkdfSha256, pbkdf2::Pbkdf2Sha256},
        xof::shake::Shake256,
    },
};

fn main() -> Result<()> {
    // --- Use Case 1: Key Rotation with HKDF ---
    // You have a single master key and need to generate different versions of
    // a derived key for key rotation purposes.
    let master_key = SymmetricKey::new(vec![0u8; 32]);
    let hkdf = HkdfSha256::default();

    // Derive a key for version 1
    let key_v1 = master_key.derive_key(&hkdf, Some(b"rotation-salt"), Some(b"version-1"), 32)?;
    println!("Key V1 derived successfully.");

    // When you need to rotate, simply change the context ("info")
    let key_v2 = master_key.derive_key(&hkdf, Some(b"rotation-salt"), Some(b"version-2"), 32)?;
    println!("Key V2 derived successfully.");

    assert_ne!(key_v1.as_bytes(), key_v2.as_bytes());

    // --- Use Case 2: Multi-Level Derivation with an XOF (SHAKE256) ---
    // You derive a long master secret from a password, and then use an XOF
    // to generate multiple keys of different lengths from that secret.
    let password = b"a-very-secure-user-password";
    let pbkdf2 = Pbkdf2Sha256::new(100_000); // Use high iterations in production

    // First, derive 64 bytes of master secret material from the password.
    let master_secret =
        SymmetricKey::derive_from_password(password, &pbkdf2, b"app-salt", 64)?;

    // Now, create and initialize an XOF instance with the master secret.
    let mut xof_reader = Shake256::default().reader(master_secret.as_bytes(), None, None)?;

    // Read a 32-byte key for encryption
    let mut encryption_key_bytes = [0u8; 32];
    xof_reader.read(&mut encryption_key_bytes);
    let encryption_key = SymmetricKey::new(encryption_key_bytes.to_vec());
    println!("Derived encryption key using XOF.");

    // Read a 16-byte key for another purpose
    let mut iv_key_bytes = [0u8; 16];
    xof_reader.read(&mut iv_key_bytes);
    let iv_key = SymmetricKey::new(iv_key_bytes.to_vec());
    println!("Derived IV key using XOF.");
    
    // The keys are different because the XOF stream is being consumed.
    assert_ne!(encryption_key.as_bytes()[..16], iv_key.as_bytes()[..]);

    Ok(())
} 