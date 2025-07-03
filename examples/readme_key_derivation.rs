use seal_flow::prelude::*;
use seal_crypto::schemes::kdf::{hkdf::HkdfSha256, pbkdf2::Pbkdf2Sha256};

fn main() -> Result<()> {
    // Derive a child key from a master key
    let master_key = SymmetricKey::new(vec![0u8; 32]);
    let deriver = HkdfSha256::default();
    let encryption_key = master_key.derive_key(
        &deriver,
        Some(b"salt"),
        Some(b"context-for-encryption"),
        32,
    )?;

    // Derive a key from a password
    let password = b"user-secure-password";
    let pbkdf2 = Pbkdf2Sha256::new(100_000); // Use a high iteration count
    let password_derived_key = SymmetricKey::derive_from_password(
        password,
        &pbkdf2,
        b"random-salt",
        32,
    )?;

    // To use these keys, you would pass them to the `encrypt` function.
    // For example:
    // let ciphertext = seal.encrypt(encryption_key, ...).to_vec(...)?;
    // let ciphertext2 = seal.encrypt(password_derived_key, ...).to_vec(...)?;
    
    println!("Successfully derived keys: {:?} and {:?}", encryption_key, password_derived_key);

    Ok(())
} 