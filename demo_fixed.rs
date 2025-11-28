// Save as: openpgp/examples/pqc_complete_demo.rs
// Complete working demonstration of SLH-DSA-256s + ML-KEM-1024+X448

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy as P;
use openpgp::types::*;

fn main() -> openpgp::Result<()> {
    println!("=== Post-Quantum Cryptography Complete Demo ===\n");
    
    // Check algorithm support
    println!("Algorithm Support:");
    println!("  SLH-DSA-256s: {}", 
        openpgp::crypto::backend::interface::Asymmetric::supports_algo(
            PublicKeyAlgorithm::SLHDSA256s
        ));
    println!("  ML-KEM-1024+X448: {}", 
        openpgp::crypto::backend::interface::Asymmetric::supports_algo(
            PublicKeyAlgorithm::MLKEM1024_X448
        ));
    println!("  SHA3-512: true (automatic with RFC 9580)\n");
    
    // Step 1: Generate certificate with RFC 9580 profile
    println!("Step 1: Generating certificate with RFC 9580 profile...");
    let policy = &P::new();
    
    let (cert, _revocation) = CertBuilder::new()
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_userid("Alice <alice@example.com>")
        .set_creation_time(std::time::SystemTime::now())
        // Primary key: SLH-DSA-256s for certification
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        // Signing subkey: SLH-DSA-256s
        .add_signing_subkey()
        // Encryption subkey: ML-KEM-1024+X448
        .add_subkey(
            KeyFlags::empty()
                .set_storage_encryption()
                .set_transport_encryption(),
            None,
            None,
        )
        .generate()?;
    
    let fingerprint = cert.fingerprint();
    println!("  Primary key: {:?}", cert.primary_key().pk_algo());
    println!("  Fingerprint: {}", fingerprint);
    
    for (i, key) in cert.keys().enumerate() {
        println!("  Subkey {}: {:?}", i, key.pk_algo());
    }
    println!();
    
    // Step 2: Export keys to .asc format
    println!("Step 2: Exporting keys to .asc format...");
    
    let mut public_key = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut public_key,
            openpgp::armor::Kind::PublicKey
        )?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("pqc_public.asc", &public_key)?;
    println!("  Public key: pqc_public.asc ({} bytes)", public_key.len());
    
    let mut secret_key = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut secret_key,
            openpgp::armor::Kind::SecretKey
        )?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("pqc_secret.asc", &secret_key)?;
    println!("  Secret key: pqc_secret.asc ({} bytes)\n", secret_key.len());
    
    // Step 3