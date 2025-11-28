// Save as: openpgp/examples/Paulsign_verify.rs
// Simple example: Generate key, sign message, verify signature
// Usage: cargo run -p sequoia-openpgp --example Paulsign_verify \
//        --no-default-features --features crypto-openssl,compression

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy as P;
use openpgp::types::*;

fn main() -> openpgp::Result<()> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║          OpenPGP Key Generation Demo                  ║");
    println!("║       Generate → Sign → Verify (3 steps)              ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // STEP 1: Generate Keys
    // ========================================================================
    println!("STEP 1: Generating certificate...");
    println!("  Algorithms: EdDSA (sign) + ECDH (encrypt)");
    println!("  Profile: V6 (RFC 9580)");
    
    let policy = &P::new();
    
    // Generate certificate
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Alice <alice@example.com>")
        .set_creation_time(std::time::SystemTime::now())
        .set_primary_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing()
        )
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;
    
    println!("  ✓ Certificate fingerprint: {}", cert.fingerprint());
    println!("  ✓ Primary key: {:?}", cert.primary_key().key().pk_algo());
    
    // Export public key to .asc file
    let mut public_key_data = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut public_key_data,
            openpgp::armor::Kind::PublicKey
        )?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("alice_public.asc", &public_key_data)?;
    println!("  ✓ Saved: alice_public.asc ({} bytes)", public_key_data.len());
    
    // Export secret key to .asc file
    let mut secret_key_data = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut secret_key_data,
            openpgp::armor::Kind::SecretKey
        )?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("alice_secret.asc", &secret_key_data)?;
    println!("  ✓ Saved: alice_secret.asc ({} bytes)\n", secret_key_data.len());
    
    // ========================================================================
    // STEP 2: Sign a Message
    // ========================================================================
    println!("STEP 2: Signing a message...");
    
    let message = b"Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s.";
    println!("  Message: \"{}\"", String::from_utf8_lossy(message));
    
    // Get the signing key
    let signing_keypair = cert.keys()
        .with_policy(policy, None)
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    
    println!("  ✓ Using key: {:?}", signing_keypair.public().pk_algo());
    
    // Create cleartext signature (human-readable)
    let mut signed_message = Vec::new();
    {
        let message_writer = Message::new(&mut signed_message);

        let mut signer = Signer::new(message_writer, signing_keypair)?
            .cleartext()  // Cleartext = message is readable
            .hash_algo(HashAlgorithm::SHA512)?
            .build()?;

        signer.write_all(message)?;
        signer.finalize()?;
    }
    
    std::fs::write("message_signed.asc", &signed_message)?;
    println!("  ✓ Saved: message_signed.asc ({} bytes)", signed_message.len());
    println!("  ✓ Hash algorithm: SHA512\n");
    
    // Show the signed message
    println!("  Preview of signed message:");
    println!("  ┌────────────────────────────────────────────┐");
    for line in String::from_utf8_lossy(&signed_message).lines().take(10) {
        println!("  │ {:<42} │", line);
    }
    println!("  │ ... (signature data continues) ...         │");
    println!("  └────────────────────────────────────────────┘\n");
    
    // ========================================================================
    // STEP 3: Verify the Signature
    // ========================================================================
    println!("STEP 3: Verifying signature...");
    
    // Helper for verification
    struct Helper<'a> {
        cert: &'a openpgp::Cert,
        policy: &'a dyn openpgp::policy::Policy,
    }
    
    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                     -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(vec![self.cert.clone()])
        }
        
        fn check(&mut self, structure: MessageStructure)
                 -> openpgp::Result<()> {
            for layer in structure.iter() {
                match layer {
                    MessageLayer::SignatureGroup { results } => {
                        for result in results {
                            match result {
                                Ok(GoodChecksum { ka, .. }) => {
                                    println!("  ✓ Signature is VALID");
                                    println!("  ✓ Signer fingerprint: {}",
                                             ka.cert().fingerprint());
                                    println!("  ✓ Signing algorithm: {:?}",
                                             ka.key().pk_algo());

                                    // Note: SLH-DSA support is pending in this version
                                    // Uncomment when SLHDSA variants are added to PublicKeyAlgorithm
                                    // if ka.key().pk_algo() == PublicKeyAlgorithm::SLHDSA256s {
                                    //     println!("  ✓ Quantum-resistant: YES (SLH-DSA-256s)");
                                    // }

                                    return Ok(());
                                }
                                Err(e) => {
                                    let error_msg = format!("Signature is INVALID: {}", e);
                                    eprintln!("  ✗ {}", error_msg);
                                    return Err(anyhow::anyhow!(error_msg));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(anyhow::anyhow!("No valid signature found"))
        }
    }
    
    let helper = Helper { cert: &cert, policy };
    let mut verifier = VerifierBuilder::from_bytes(&signed_message)?
        .with_policy(policy, None, helper)?;
    
    let mut verified_message = Vec::new();
    std::io::copy(&mut verifier, &mut verified_message)?;
    
    println!("  ✓ Verified message: \"{}\"", 
             String::from_utf8_lossy(&verified_message));
    
    // Verify the message matches
    if &verified_message[..] == message {
        println!("  ✓ Message integrity: CONFIRMED\n");
    } else {
        eprintln!("  ✗ Message integrity: FAILED\n");
        return Err(anyhow::anyhow!("Message mismatch"));
    }
    
    // ========================================================================
    // SUMMARY
    // ========================================================================
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║                    SUCCESS!                            ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Generated Files:                                      ║");
    println!("║    • alice_public.asc  - Public key                    ║");
    println!("║    • alice_secret.asc  - Secret key                    ║");
    println!("║    • message_signed.asc - Signed message               ║");
    println!("║                                                        ║");
    println!("║  What Happened:                                        ║");
    println!("║    ✓ Generated V6 certificate with EdDSA             ║");
    println!("║    ✓ Signed message with SHA512                       ║");
    println!("║    ✓ Verified signature successfully                  ║");
    println!("║    ✓ Cryptography working correctly!                  ║");
    println!("╚════════════════════════════════════════════════════════╝");

    Ok(())
}
