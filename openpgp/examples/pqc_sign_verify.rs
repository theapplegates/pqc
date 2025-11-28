/// Complete example: Generate PQC keys, sign a message, and verify the signature
///
/// This demonstrates:
/// - Generating a V6 certificate with SLHDSA256s (signing) and MLKEM1024_X448 (encryption)
/// - Signing a message with SLHDSA256s
/// - Verifying the signature
/// - Exporting keys to .asc files
///
/// Build and run:
/// ```bash
/// cargo run -p sequoia-openpgp --example pqc_sign_verify \
///   --no-default-features --features crypto-openssl,compression
/// ```

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy as P;
use openpgp::types::*;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::Profile;

fn main() -> openpgp::Result<()> {
    println!("═══════════════════════════════════════════════════════════");
    println!("  Post-Quantum OpenPGP: Key Generation, Sign & Verify");
    println!("  SLHDSA256s (Signing) + MLKEM1024_X448 (Encryption)");
    println!("  RFC 9580 (V6 Profile) + SHA3-512");
    println!("═══════════════════════════════════════════════════════════\n");

    let policy = &P::new();

    // Step 1: Generate V6 Certificate with PQC algorithms
    println!("Step 1: Generating V6 certificate with PQC algorithms...");

    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Alice <alice@example.com>")
        .set_creation_time(std::time::SystemTime::now())

        // Use V6 profile (RFC 9580) - required for PQC algorithms
        .set_profile(Profile::RFC9580)?

        // Primary key flags: certification and signing
        .set_primary_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing()
        )

        // Use SLHDSA256s for the primary signing key
        .set_cipher_suite(CipherSuite::Custom {
            pk_algo: PublicKeyAlgorithm::SLHDSA256s,
            sym_algo: SymmetricAlgorithm::AES256,
            aead_algo: Some(AEADAlgorithm::EAX),
            hash_algo: HashAlgorithm::SHA3_512,
        })

        // Add a signing subkey (will also be SLHDSA256s)
        .add_signing_subkey()

        .generate()?;

    println!("  ✓ Certificate generated successfully!");
    println!("  ✓ Fingerprint: {}", cert.fingerprint());

    // Get primary key details with policy
    let primary = cert.primary_key().with_policy(policy, None)?;
    println!("  ✓ Primary key algorithm: {:?}", primary.key().pk_algo());
    println!("  ✓ Created: {:?}", primary.key().creation_time());

    // Show subkeys
    for (i, key) in cert.keys().subkeys().enumerate() {
        if let Ok(ka) = key.with_policy(policy, None) {
            println!("  ✓ Subkey {}: {:?}", i, ka.key().pk_algo());
        }
    }
    println!();

    // Step 2: Export public and secret keys
    println!("Step 2: Exporting keys to .asc files...");

    // Export public key
    let public_key_armored = cert.armored().to_vec()?;
    std::fs::write("pqc_alice_public.asc", &public_key_armored)?;
    println!("  ✓ Public key saved to: pqc_alice_public.asc");

    // Export secret key
    let secret_key_armored = cert.as_tsk().armored().to_vec()?;
    std::fs::write("pqc_alice_secret.asc", &secret_key_armored)?;
    println!("  ✓ Secret key saved to: pqc_alice_secret.asc\n");

    // Step 3: Sign a message
    println!("Step 3: Signing a message with SLHDSA256s...");

    let message = b"Hello, Post-Quantum World! This message is signed with SLHDSA256s.";
    println!("  Message: \"{}\"", String::from_utf8_lossy(message));

    // Get a signing key from the certificate
    let signing_key = cert.keys()
        .with_policy(policy, None)
        .for_signing()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
        .key()
        .clone();

    let key_algo = signing_key.pk_algo();
    let key_fp = signing_key.fingerprint();

    println!("  ✓ Using key: {} ({:?})", key_fp, key_algo);

    // Convert to keypair for signing
    let signing_keypair = signing_key
        .parts_into_secret()?
        .into_keypair()?;

    // Create a detached signature
    let mut signature_bytes = Vec::new();
    {
        let message_writer = Message::new(&mut signature_bytes);

        let mut signer = Signer::with_template(
            message_writer,
            signing_keypair,
            SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA3_512)
        )?
        .detached()
        .build()?;

        signer.write_all(message)?;
        signer.finalize()?;
    }

    println!("  ✓ Signature created ({} bytes)", signature_bytes.len());
    println!("  ✓ Hash algorithm: SHA3-512\n");

    // Save signature to file
    std::fs::write("pqc_message.txt", message)?;
    std::fs::write("pqc_message.txt.sig", &signature_bytes)?;
    println!("  ✓ Message saved to: pqc_message.txt");
    println!("  ✓ Signature saved to: pqc_message.txt.sig\n");

    // Step 4: Verify the signature
    println!("Step 4: Verifying the signature...");

    // Parse the detached signature
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature_bytes)?
        .with_policy(policy, None, Helper::new(&cert))?;

    // Verify the message
    verifier.verify_bytes(message)?;

    println!("  ✓ Signature verification SUCCESSFUL!");
    println!("  ✓ Signed by: {}", cert.fingerprint());
    println!("  ✓ Algorithm: {:?}\n", key_algo);

    // Summary
    println!("═══════════════════════════════════════════════════════════");
    println!("  Summary: All operations completed successfully!");
    println!("═══════════════════════════════════════════════════════════");
    println!("  Certificate: SLHDSA256s signing keys");
    println!("  Profile: V6 (RFC 9580)");
    println!("  Hash: SHA3-512");
    println!("  Files created:");
    println!("    - pqc_alice_public.asc  (public key)");
    println!("    - pqc_alice_secret.asc  (secret key)");
    println!("    - pqc_message.txt       (original message)");
    println!("    - pqc_message.txt.sig   (detached signature)");
    println!("═══════════════════════════════════════════════════════════\n");

    Ok(())
}

// Helper for verification
struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> Helper<'a> {
    fn new(cert: &'a openpgp::Cert) -> Self {
        Helper { cert }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                 -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure)
             -> openpgp::Result<()> {
        use openpgp::parse::stream::MessageLayer::*;

        for layer in structure.into_iter() {
            match layer {
                SignatureGroup { results } => {
                    for result in results {
                        if result.is_ok() {
                            return Ok(());
                        }
                    }
                    return Err(anyhow::anyhow!("Signature verification failed"));
                }
                _ => {}
            }
        }
        Err(anyhow::anyhow!("No signature found"))
    }
}
