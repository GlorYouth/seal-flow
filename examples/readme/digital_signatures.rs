use seal_flow::algorithms::signature::Ed25519;
use seal_flow::algorithms::asymmetric::Rsa2048;
use seal_flow::algorithms::hash::Sha256;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::*;

// Define the asymmetric algorithm for Key Encapsulation (KEM).
// 定义用于密钥封装 (KEM) 的非对称算法。
type Kem = Rsa2048<Sha256>;
// Define the symmetric algorithm for Data Encapsulation (DEK).
// 定义用于数据封装 (DEK) 的对称算法。
type Dek = Aes256Gcm;
// Define the algorithm for digital signatures.
// 定义用于数字签名的算法。
type Sig = Ed25519;

fn main() -> Result<()> {
    // The high-level API factory is stateless and reusable.
    // 高级 API 工厂是无状态且可重用的。
    let seal = HybridSeal::new();

    // 1. Generate two separate key pairs: one for encryption (KEM) and one for signing.
    //    The KEM key pair is for the recipient. The signing key pair is for the sender.
    // 1. 生成两个独立的密钥对：一个用于加密（KEM），一个用于签名。
    //    KEM 密钥对属于接收方，签名密钥对属于发送方。
    let (pk_kem, sk_kem) = Kem::generate_keypair()?;
    let (pk_sig, sk_sig) = Sig::generate_keypair()?;

    let plaintext = b"this data will be signed and encrypted";

    // 2. Encrypt and Sign (Sender's Side)
    // 2. 加密与签名（发送方）
    let pk_kem_wrapped = AsymmetricPublicKey::new(pk_kem.to_bytes());
    let sk_sig_wrapped = AsymmetricPrivateKey::new(sk_sig.to_bytes());
    let ciphertext = seal
        .encrypt::<Dek>(pk_kem_wrapped, "kem-key-id".to_string())
        // The sender signs the data with their private signing key.
        // 发送方用自己的签名私钥对数据进行签名。
        .with_signer::<Sig>(sk_sig_wrapped, "sig-key-id".to_string())
        .to_vec::<Kem>(plaintext)?;

    // 3. Decrypt and Verify (Recipient's Side)
    // 3. 解密与验证（接收方）
    let pending_decryptor = seal.decrypt().slice(&ciphertext)?;

    // Wrap the recipient's private KEM key and the sender's public signature key.
    // 包装接收方的 KEM 私钥和发送方的签名公钥。
    let sk_kem_wrapped = AsymmetricPrivateKey::new(sk_kem.to_bytes());
    let pk_sig_wrapped = SignaturePublicKey::new(pk_sig.to_bytes());

    // The recipient first provides the sender's public key to verify the signature.
    // If verification fails, the process stops and returns an error.
    // Then, the recipient provides their private KEM key to decrypt the data.
    // 接收方首先提供发送方的公钥来验证签名。
    // 如果验证失败，流程将终止并返回错误。
    // 然后，接收方提供自己的 KEM 私钥来解密数据。
    let decrypted_text = pending_decryptor
        .with_verification_key(pk_sig_wrapped)?
        .with_key(sk_kem_wrapped)?;

    assert_eq!(plaintext, &decrypted_text[..]);
    println!("Successfully signed, encrypted, decrypted, and verified data!");
    Ok(())
}
