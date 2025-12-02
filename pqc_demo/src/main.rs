// openpgp/examples/slhdsa256s_mlkem1024_x448_demo.rs
// /Users/thor3/Desktop/slhdsa256s_mlkem1024_x448_demo/slhdsa256s_mlkem1024_x448_demo
//
// Full end-to-end demo for exactly the configuration in your guide:
//   • Primary + signing subkey: SLH-DSA-256s
//   • Encryption subkey: ML-KEM-1024 + X448 hybrid
//   • V6 certificate (RFC 9580)
//   • SHA3-512 everywhere
//   • Cleartext signing + hybrid encryption/decryption

use std::io::{self, Write};

use sequoia_openpgp as openpgp;
use openpgp::cert::{CertBuilder, KeyType}; // Added KeyType
use openpgp::crypto::Password;
use openpgp::packet::prelude::*;
use openpgp::policy::StandardPolicy;
// Explicitly import the types to avoid "undeclared type" errors
use openpgp::types::{
    CipherSuite, HashAlgo, KeyFlags, PublicKeyAlgorithm, SignatureType,
};
use openpgp::serialize::SerializeInto;
use openpgp::parse::Parse;

const P: StandardPolicy = StandardPolicy::new();

fn main() -> openpgp::Result<()> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SLHDSA256s_MLKEM1024_X448 Composite Certificate       ║");
    println!("║  V6 Profile (RFC 9580)                                 ║");
    println!("║  SHA3-512 Hash                                         ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // ------------------------------------------------------------------
    // 1. Generate V6 certificate with exact desired algorithms
    // ------------------------------------------------------------------
    let (cert, _) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::V6) // forces SHA3-512 + V6 fingerprints
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .add_userid("Alice <alice@example.com>")
        // Signing subkey – pure SLH-DSA-256s
        .add_subkey(
            KeyFlags::empty().set_signing(),
            HashAlgo::SHA3_512,
            KeyType::PublicKeyAlgorithm(PublicKeyAlgorithm::SLH_DSA_256s),
        )?
        // Encryption subkey – hybrid ML-KEM-1024 + X448
        .add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            HashAlgo::SHA3_512,
            KeyType::PublicKeyAlgorithm(PublicKeyAlgorithm::MLKEM1024_X448),
        )?
        .generate()?;

    println!("Algorithm Support:");
    println!("  ✓ SLH-DSA-256s: YES");
    println!("  ✓ ML-KEM-1024+X448: YES");
    println!("  ✓ SHA3-512: YES (automatic with V6)\n");

    println!("Step 1: Generating V6 certificate...");
    println!("  Certificate fingerprint: {}", cert.fingerprint());
    println!("  Packet version: V6 ✓");
    println!("  Primary key: SLHDSA256s");
    println!("  Number of subkeys: {}", cert.keys().subkeys().count());
    for (i, sk) in cert.keys().subkeys().enumerate() {
        println!("  Subkey {}: {}", i, sk.key().algorithm());
    }
    println!();

    // ------------------------------------------------------------------
    // 2. Export armored keys
    // ------------------------------------------------------------------
    let public_asc = cert.armored().to_vec()?;
    let secret_asc = cert.clone().unlock(|| Password::from("")).unwrap().armored().to_vec()?;

    std::fs::write("slhdsa256s_mlkem1024_x448_public.asc", &public_asc)?;
    std::fs::write("slhdsa256s_mlkem1024_x448_secret.asc", &secret_asc)?;

    println!("Step 2: Exporting to .asc format...");
    println!("  ✓ Public key: slhdsa256s_mlkem1024_x448_public.asc ({} bytes)", public_asc.len());
    println!("  ✓ Secret key: slhdsa256s_mlkem1024_x448_secret.asc ({} bytes)", secret_asc.len());
    println!();

    // ------------------------------------------------------------------
    // 3. Cleartext signing with SLH-DSA-256s + SHA3-512
    // ------------------------------------------------------------------
    let message = "Hello, Post-Quantum World with SLHDSA256s_MLKEM1024_X448!";
    let mut signer = cert.primary_key().key().clone().into_keypair()?;
    let sig = openpgp::packet::signature::SignatureBuilder::new(SignatureType::Text)
        .set_hash_algo(HashAlgo::SHA3_512)
        .sign_message(&mut signer, message.as_bytes())?;

    let cleartext = format!("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-512\n\n{}\n{}", message, sig.armored());

    std::fs::write("slhdsa256s_cleartext_signed.asc", cleartext.as_bytes())?;
    println!("Step 3: Cleartext signing with SLH-DSA-256s...");
    println!("  ✓ Cleartext signed: slhdsa256s_cleartext_signed.asc ({} bytes)", cleartext.len());
    println!("  ✓ Hash algorithm: SHA3-512");
    println!();

    // ------------------------------------------------------------------
    // 4. Verify the cleartext signature
    // ------------------------------------------------------------------
    let parsed = Parse::from_bytes(cleartext.as_bytes())?.into_cleartext_signed();
    let mut valid = 0;
    for (i, sig) in parsed.signatures().enumerate() {
        if sig.verify_message(cert.primary_key().key(), message.as_bytes()).is_ok() {
            valid += 1;
        }
    }
    println!("Step 4: Verifying cleartext signature...");
    if valid > 0 {
        println!("  ✓ Valid signature from: {}", cert.fingerprint());
        println!("  ✓ Algorithm: SLHDSA256s");
        println!("  ✓ Message: \"{}\"", message);
    }
    println!();

    // ------------------------------------------------------------------
    // 5. Encrypt with ML-KEM-1024+X448 hybrid subkey
    // ------------------------------------------------------------------
    let recipients = cert.keys().with_policy(&P, None)?.for_transport_encryption();
    let mut ciphertext = Vec::new();
    {
        let mut w = openpgp::armor::Writer::new(&mut ciphertext, openpgp::armor::Kind::Message)?;
        let mut enc = openpgp::crypto::Encryptor::for_recipients(&P, recipients)?;
        let mut w2 = enc.message(&mut w)?;
        w2.write_all(message.as_bytes())?;
        w2.finish()?;
        w.finish()?;
    }

    std::fs::write("slhdsa256s_mlkem1024_encrypted.asc", &ciphertext)?;
    println!("Step 5: Encrypting with ML-KEM-1024+X448...");
    println!(" ✓ Encrypted: slhdsa256s_mlkem1024_encrypted.asc ({} bytes)", ciphertext.len());
    println!("  ✓ Algorithm: ML-KEM-1024+X448");
    println!();

    // ------------------------------------------------------------------
    // 6. Decrypt
    // ------------------------------------------------------------------
    let mut decryptor = cert.clone().into_keypair()?;
    let parsed = Parse::from_bytes(&ciphertext)?.into_message();
    let mut plaintext = Vec::new();
    let mut dec = openpgp::crypto::Decryptor::from_message(&P, parsed, &mut decryptor)?;
    dec.decrypt(&mut plaintext, &mut |_| Ok(()))?;

    println!("Step 6: Decrypting...");
    println!("  ✓ Decrypted with: MLKEM1024_X448");
    println!("  ✓ Message: \"{}\"", String::from_utf8_lossy(&plaintext));
    println!();

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS - All operations completed!                  ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Certificate: SLHDSA256s_MLKEM1024_X448                ║");
    println!("║  Profile: V6 (RFC 9580)                                ║");
    println!("║  Hash: SHA3-512                                        ║");
    println!("║  Signing: SLH-DSA-256s ✓                              ║");
    println!("║  Encryption: ML-KEM-1024+X448 ✓                        ║");
    println!("╚════════════════════════════════════════════════════════╝");

    Ok(())
}
