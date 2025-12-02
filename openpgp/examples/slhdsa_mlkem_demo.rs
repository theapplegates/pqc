// Save as: openpgp/examples/slhdsa256s_mlkem1024_x448_demo.rs
// Complete demonstration of SLHDSA256s_MLKEM1024_X448 composite with V6 profile

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy as P;
use openpgp::types::*;

// Algorithm constants from official standards
// SLH-DSA-256s (FIPS 205, Table 2, SLH-DSA-SHAKE-256s)
const SLHDSA256S_PUBLIC_KEY_SIZE: usize = 64;
const SLHDSA256S_SECRET_KEY_SIZE: usize = 128;
const SLHDSA256S_SIGNATURE_SIZE: usize = 29792;

// ML-KEM-1024 (FIPS 203, Table 2, ML-KEM-1024)
const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;
const MLKEM1024_SECRET_KEY_SIZE: usize = 3168;
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;

// X448 (RFC 7748, Section 5)
const X448_PUBLIC_KEY_SIZE: usize = 56;
const X448_SECRET_KEY_SIZE: usize = 56;

// ML-KEM-1024+X448 composite (draft-ietf-openpgp-pqc-11, Section 5.2.3)
const MLKEM1024_X448_PUBLIC_KEY_SIZE: usize = MLKEM1024_PUBLIC_KEY_SIZE + X448_PUBLIC_KEY_SIZE;  // 1624
const MLKEM1024_X448_SECRET_KEY_SIZE: usize = MLKEM1024_SECRET_KEY_SIZE + X448_SECRET_KEY_SIZE;  // 3224

fn main() -> openpgp::Result<()> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SLHDSA256s_MLKEM1024_X448 Composite Certificate      ║");
    println!("║  V6 Profile (RFC 9580)                                 ║");
    println!("║  SHA512 Hash for OpenPGP signatures                    ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!();
    println!("Algorithm Specifications:");
    println!("  SLH-DSA-256s:      {} byte public, {} byte secret, {} byte signature (FIPS 205)",
             SLHDSA256S_PUBLIC_KEY_SIZE, SLHDSA256S_SECRET_KEY_SIZE, SLHDSA256S_SIGNATURE_SIZE);
    println!("  ML-KEM-1024:       {} byte public, {} byte secret (FIPS 203)",
             MLKEM1024_PUBLIC_KEY_SIZE, MLKEM1024_SECRET_KEY_SIZE);
    println!("  X448:              {} byte public, {} byte secret (RFC 7748)",
             X448_PUBLIC_KEY_SIZE, X448_SECRET_KEY_SIZE);
    println!("  ML-KEM-1024+X448:  {} byte public, {} byte secret (composite)",
             MLKEM1024_X448_PUBLIC_KEY_SIZE, MLKEM1024_X448_SECRET_KEY_SIZE);
    println!();
    
    // Step 1: Generate V6 certificate with composite PQC algorithms
    println!("Step 1: Generating V6 certificate...");
    let policy = &P::new();
    
    let (cert, _revocation) = CertBuilder::new()
        // User ID
        .add_userid("Alice <alice@example.com>")
        .set_creation_time(std::time::SystemTime::now())
        // Use V6 profile (RFC 9580) - required for PQC algorithms
        .set_profile(openpgp::Profile::RFC9580)?
        // Primary key: SLH-DSA-256s (certification + signing)
        .set_primary_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing()
        )
        // Use new methods to set algorithms independently
        .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)
        .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)
        // Add SLH-DSA-256s signing subkey
        .add_signing_subkey()
        // Add ML-KEM-1024+X448 encryption subkey
        .add_transport_encryption_subkey()
        .generate()?;
    
    // Verify the certificate structure
    println!("  Certificate fingerprint: {}", cert.fingerprint());
    println!("  Packet version: V{}", match cert.primary_key().key().version() {
        6 => "6 ✓",
        v => panic!("Wrong version: V{}", v),
    });

    println!("  Primary key: {:?}", cert.primary_key().key().pk_algo());
    assert_eq!(cert.primary_key().key().pk_algo(), PublicKeyAlgorithm::SLHDSA256s,
               "Primary key must be SLH-DSA-256s");

    // Check subkeys with policy
    let subkeys: Vec<_> = cert.keys().with_policy(policy, None).subkeys().collect();
    println!("  Number of subkeys: {}", subkeys.len());

    for (i, key) in subkeys.iter().enumerate() {
        let algo = key.key().pk_algo();
        let flags = key.key_flags();
        println!("  Subkey {}: {:?}", i, algo);
        println!("    Flags: {:?}", flags);
        
        if i == 0 {
            // First subkey should be signing (SLH-DSA-256s)
            assert_eq!(algo, PublicKeyAlgorithm::SLHDSA256s,
                       "Signing subkey must be SLH-DSA-256s");
            assert!(flags.map(|f| f.for_signing()).unwrap_or(false),
                    "First subkey must be for signing");
        } else if i == 1 {
            // Second subkey should be encryption (ML-KEM-1024+X448)
            assert_eq!(algo, PublicKeyAlgorithm::MLKEM1024_X448,
                       "Encryption subkey must be ML-KEM-1024+X448");
            assert!(flags.map(|f| f.for_storage_encryption() || f.for_transport_encryption())
                         .unwrap_or(false),
                    "Second subkey must be for encryption");
        }
    }
    println!();
    
    // Step 2: Export to ASCII armored .asc format
    println!("Step 2: Exporting to .asc format...");
    
    let mut public_key = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut public_key,
            openpgp::armor::Kind::PublicKey
        )?;
        cert.serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("slhdsa256s_mlkem1024_x448_public.asc", &public_key)?;
    println!("  ✓ Public key: slhdsa256s_mlkem1024_x448_public.asc ({} bytes)", 
             public_key.len());
    
    let mut secret_key = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(
            &mut secret_key,
            openpgp::armor::Kind::SecretKey
        )?;
        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;
    }
    std::fs::write("slhdsa256s_mlkem1024_x448_secret.asc", &secret_key)?;
    println!("  ✓ Secret key: slhdsa256s_mlkem1024_x448_secret.asc ({} bytes)\n",
             secret_key.len());
    
    // Step 3: Cleartext sign a message (SHA512 hash)
    // Note: Use SHA512 (SHA-2), not SHA3-512, as it's in the default acceptable hash list
    println!("Step 3: Cleartext signing with SLH-DSA-256s...");
    let message = b"Hello, Post-Quantum World with SLHDSA256s_MLKEM1024_X448!";
    
    let signing_keypair = cert.keys().with_policy(policy, None)
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    
    let mut signed_message = Vec::new();
    {
        let message_writer = Message::new(&mut signed_message);
        let message_writer = Armorer::new(message_writer)
            .kind(openpgp::armor::Kind::Message)
            .build()?;

        let mut signer = Signer::new(message_writer, signing_keypair)?
            .cleartext()  // Cleartext signature (human-readable)
            .hash_algo(HashAlgorithm::SHA512)?  // Use SHA512 (SHA-2)
            .build()?;

        signer.write_all(message)?;
        signer.finalize()?;
    }
    
    std::fs::write("slhdsa256s_cleartext_signed.asc", &signed_message)?;
    println!("  ✓ Cleartext signed: slhdsa256s_cleartext_signed.asc ({} bytes)",
             signed_message.len());
    println!("  ✓ Hash algorithm: SHA512\n");
    
    // Step 4: Verify the cleartext signature
    println!("Step 4: Verifying cleartext signature...");
    
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
            for layer in structure.into_iter() {
                match layer {
                    MessageLayer::SignatureGroup { results } => {
                        for result in results {
                            match result {
                                Ok(GoodChecksum { ka, .. }) => {
                                    println!("  ✓ Valid signature from: {}",
                                             ka.cert().fingerprint());
                                    println!("  ✓ Algorithm: {:?}",
                                             ka.key().pk_algo());

                                    // Verify it's SLH-DSA-256s
                                    assert_eq!(ka.key().pk_algo(),
                                               PublicKeyAlgorithm::SLHDSA256s,
                                               "Signature must be from SLH-DSA-256s key");
                                    return Ok(());
                                }
                                Err(e) => {
                                    eprintln!("  ✗ Bad signature: {}", e);
                                    return Err(anyhow::anyhow!("Bad signature"));
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
    
    println!("  ✓ Message: \"{}\"", String::from_utf8_lossy(&verified_message));
    println!();
    
    // Step 5: Encrypt a message with ML-KEM-1024+X448
    println!("Step 5: Encrypting with ML-KEM-1024+X448...");
    
    let recipients = cert.keys().with_policy(policy, None)
        .for_storage_encryption()
        .for_transport_encryption();
    
    let mut encrypted_message = Vec::new();
    {
        let message_writer = Message::new(&mut encrypted_message);
        let message_writer = Armorer::new(message_writer)
            .kind(openpgp::armor::Kind::Message)
            .build()?;
        
        let mut encryptor = Encryptor::for_recipients(message_writer, recipients)
            .symmetric_algo(SymmetricAlgorithm::AES256)
            .aead_algo(AEADAlgorithm::EAX)
            .build()?;
        
        encryptor.write_all(message)?;
        encryptor.finalize()?;
    }
    
    std::fs::write("slhdsa256s_mlkem1024_encrypted.asc", &encrypted_message)?;
    println!("  ✓ Encrypted: slhdsa256s_mlkem1024_encrypted.asc ({} bytes)",
             encrypted_message.len());
    println!("  ✓ Algorithm: ML-KEM-1024+X448\n");
    
    // Step 6: Decrypt the message
    println!("Step 6: Decrypting...");
    
    struct DecHelper<'a> {
        cert: &'a openpgp::Cert,
        policy: &'a dyn openpgp::policy::Policy,
    }
    
    impl<'a> VerificationHelper for DecHelper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                     -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(vec![])
        }
        
        fn check(&mut self, _structure: MessageStructure)
                 -> openpgp::Result<()> {
            Ok(())
        }
    }
    
    impl<'a> DecryptionHelper for DecHelper<'a> {
        fn decrypt(&mut self, pkesks: &[openpgp::packet::PKESK],
                   _skesks: &[openpgp::packet::SKESK],
                   sym_algo: Option<SymmetricAlgorithm>,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &openpgp::crypto::SessionKey) -> bool)
                   -> openpgp::Result<Option<openpgp::Cert>>
        {
            for pkesk in pkesks {
                let keypairs = self.cert.keys().with_policy(self.policy, None)
                    .for_transport_encryption()
                    .for_storage_encryption()
                    .secret()
                    .filter_map(|k| k.key().clone().into_keypair().ok());

                for mut keypair in keypairs {
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        if decrypt(algo, &session_key) {
                            println!("  ✓ Decrypted with: {:?}", keypair.public().pk_algo());

                            // Verify it's ML-KEM-1024+X448
                            assert_eq!(keypair.public().pk_algo(),
                                       PublicKeyAlgorithm::MLKEM1024_X448,
                                       "Decryption must use ML-KEM-1024+X448 key");

                            return Ok(Some(self.cert.clone()));
                        }
                    }
                }
            }
            Err(anyhow::anyhow!("Decryption failed"))
        }
    }
    
    let helper = DecHelper { cert: &cert, policy };
    let mut decryptor = DecryptorBuilder::from_bytes(&encrypted_message)?
        .with_policy(policy, None, helper)?;
    
    let mut decrypted_message = Vec::new();
    std::io::copy(&mut decryptor, &mut decrypted_message)?;
    
    println!("  ✓ Message: \"{}\"", String::from_utf8_lossy(&decrypted_message));
    assert_eq!(message, &decrypted_message[..],
               "Decrypted message must match original");
    println!();
    
    // Final summary
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS - All operations completed!                  ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Certificate: SLHDSA256s_MLKEM1024_X448               ║");
    println!("║  Profile: V6 (RFC 9580)                                ║");
    println!("║  Hash: SHA512 (for OpenPGP signatures)                ║");
    println!("║  Signing: SLH-DSA-256s ✓                              ║");
    println!("║  Encryption: ML-KEM-1024+X448 ✓                       ║");
    println!("╚════════════════════════════════════════════════════════╝");
    
    Ok(())
}
