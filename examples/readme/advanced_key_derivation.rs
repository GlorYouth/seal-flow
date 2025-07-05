use seal_flow::algorithms::kdf::HkdfSha256;
use seal_flow::algorithms::kdf::passwd::Pbkdf2Sha256;
use seal_flow::algorithms::xof::Shake256;
use seal_flow::prelude::*;

fn main() -> Result<()> {
    println!("--- Use Case 1: Key Rotation with HKDF ---");
    // You have a single, long-term master key and need to generate different
    // versions of a derived key for periodic key rotation.
    // 场景1：使用 HKDF 进行密钥轮换。
    // 您有一个长期有效的主密钥，并需要从中生成不同版本的派生密钥以进行定期轮换。
    let master_key = SymmetricKey::new(vec![0u8; 32]);
    let hkdf = HkdfSha256::default();

    // Derive a key for version 1 using specific context "info".
    // 使用特定的上下文"info"为版本1派生一个密钥。
    let key_v1 = master_key.derive_key(&hkdf, Some(b"rotation-salt"), Some(b"version-1"), 32)?;
    println!("Key V1 derived successfully.");

    // When it's time to rotate, you just change the "info" parameter to get a new,
    // cryptographically distinct key from the same master key.
    // 当需要轮换密钥时，您只需更改"info"参数，就能从同一个主密钥中获得一个全新的、
    // 在密码学上完全不同的密钥。
    let key_v2 = master_key.derive_key(&hkdf, Some(b"rotation-salt"), Some(b"version-2"), 32)?;
    println!("Key V2 derived successfully.");

    assert_ne!(key_v1.as_bytes(), key_v2.as_bytes());
    println!("Confirmed: Key V1 and Key V2 are different.");

    println!("\n--- Use Case 2: Multi-Level Derivation with an XOF (SHAKE256) ---");
    // You derive a long master secret from a low-entropy source like a password,
    // and then use an Extendable-Output Function (XOF) to generate multiple
    // keys of different lengths from that single secret.
    // 场景2：使用 XOF（SHAKE256）进行多级派生。
    // 您首先从一个低熵源（如密码）派生出一个长的主密钥，然后使用可扩展输出函数（XOF）
    // 从这个单一的密钥中生成多个不同长度的密钥。
    let password = b"a-very-secure-user-password";
    let pbkdf2 = Pbkdf2Sha256::new(100_000); // Use high iterations in production

    // First, use PBKDF2 to stretch the password into a longer, high-entropy secret.
    // This is the input keying material (IKM) for the XOF.
    // 首先，使用 PBKDF2 将密码"拉伸"成一个更长的、高熵的密钥。
    // 这将作为 XOF 的输入密钥材料（IKM）。
    let master_secret = SymmetricKey::derive_from_password(password, &pbkdf2, b"app-salt", 64)?;

    // Now, create an XOF reader initialized with the master secret.
    // The XOF acts like a cryptographically secure stream of bytes derived from the secret.
    // 现在，用主密钥初始化一个 XOF reader。
    // XOF 的行为就像一个从主密钥派生出的、密码学安全的字节流。
    let mut xof_reader = Shake256::default().reader(master_secret.as_bytes(), None, None)?;

    // Read the first 32 bytes from the stream for an encryption key.
    // 从流中读取前32个字节，用作加密密钥。
    let mut encryption_key_bytes = [0u8; 32];
    xof_reader.read(&mut encryption_key_bytes);
    let encryption_key = SymmetricKey::new(encryption_key_bytes.to_vec());
    println!("Derived 32-byte encryption key using XOF.");

    // Continue reading the next 16 bytes from the same stream for another purpose.
    // 继续从同一个流中读取接下来的16个字节，用于其他目的。
    let mut iv_key_bytes = [0u8; 16];
    xof_reader.read(&mut iv_key_bytes);
    let iv_key = SymmetricKey::new(iv_key_bytes.to_vec());
    println!("Derived 16-byte IV key using XOF.");

    // The keys are different because the XOF stream is being consumed sequentially.
    // 这两个密钥是不同的，因为 XOF 流是按顺序消耗的。
    assert_ne!(encryption_key.as_bytes()[..16], iv_key.as_bytes()[..]);
    println!("Confirmed: The two derived keys are different.");

    Ok(())
}
