/// Complete example: Generate PQC keys, sign a message, encrypt, decrypt,
/// and verify the signature.
///
/// This demonstrates:
/// - Generating a V6 certificate with MLDSA65+Ed25519 (signing)
/// - Adding a transport-encryption subkey
/// - Signing a message
/// - Verifying the detached signature
/// - Encrypting and decrypting a message
/// - Exporting keys to .asc files
///
/// Cargo.toml (PQC pre-release + OpenSSL backend), e.g.:
///   sequoia-openpgp = "=2.2.0-pqc.1"
///   features = ["crypto-openssl", "compression"]
///
/// Then:
///   cargo run --example pqc_sign_verify --no-default-features \
///       --features crypto-openssl,compression

use std::io::{Write, Read};

use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::cert::CipherSuite;
use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy as P;
use openpgp::serialize::stream::*;
use openpgp::serialize::SerializeInto;
use openpgp::types::*;
use openpgp::Profile;

fn main() -> openpgp::Result<()> {
    println!("═══════════════════════════════════════════════════════════");
    println!("  Post-Quantum OpenPGP: Key Generation, Sign, Encrypt, Verify");
    println!("  MLDSA65 + Ed25519 (signing)");
    println!("  RFC 9580 (V6 Profile) + SHA3-512");
    println!("═══════════════════════════════════════════════════════════\n");

    let policy = &P::new();

    // Step 1: Generate V6 Certificate with PQC cipher suite
    println!("Step 1: Generating V6 certificate with MLDSA65+Ed25519...");

    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Alice <alice@example.com>")
        .set_creation_time(std::time::SystemTime::now())
        // Use V6 profile (RFC 9580) - required for PQC algorithms
        .set_profile(Profile::RFC9580)?
        // Primary key flags: certification and signing
        .set_primary_key_flags(
            KeyFlags::empty()
                .set_certification()
                .set_signing(),
        )
        // Use MLDSA65+Ed25519 for the primary key / suite
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        // Add a signing subkey (also MLDSA65+Ed25519 in this suite)
        .add_signing_subkey()
        // Add an encryption subkey (transport encryption)
        .add_transport_encryption_subkey()
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
            println!(
                "  ✓ Subkey {}: {:?}  (flags: {:?})",
                i,
                ka.key().pk_algo(),
                ka.key_flags()
            );
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
    println!("Step 3: Signing a message with MLDSA65+Ed25519...");

    let message =
        b"Hello, Post-Quantum World! This message is signed with MLDSA65+Ed25519.";
    println!("  Message: \"{}\"", String::from_utf8_lossy(message));

    // Get a signing key from the certificate
    let signing_key = cert
        .keys()
        .with_policy(policy, None)
        .for_signing()
        .next()
        .ok_or_else(|| openpgp::Error::InvalidOperation("No signing key found".into()))?
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
                // NOTE: set_hash_algo returns Self, NOT Result<Self>, so no `?` here.
                .set_hash_algo(HashAlgorithm::SHA3_512),
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
    println!("Step 4: Verifying the detached signature...");

    // Parse the detached signature
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature_bytes)?
        .with_policy(policy, None, Helper::new(&cert))?;

    // Verify the message
    verifier.verify_bytes(message)?;

    println!("  ✓ Signature verification SUCCESSFUL!");
    println!("  ✓ Signed by: {}", cert.fingerprint());
    println!("  ✓ Algorithm: {:?}\n", key_algo);

    // Step 5: Encrypt + Decrypt using the PQC/V6 certificate
    println!("Step 5: Encrypting + decrypting a message with the encryption subkey...");

    encrypt_and_decrypt_roundtrip(&cert, policy)?;

    // Summary
    println!("═══════════════════════════════════════════════════════════");
    println!("  Summary: All operations completed successfully!");
    println!("═══════════════════════════════════════════════════════════");
    println!("  Certificate: MLDSA65+Ed25519 signing keys");
    println!("  Subkeys: signing + transport-encryption");
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

/// Step 5 implementation: encrypt and decrypt a message using the
/// transport-encryption subkey in `cert`.
fn encrypt_and_decrypt_roundtrip(
    cert: &openpgp::Cert,
    policy: &P,
) -> openpgp::Result<()> {
    // Select encryption-capable recipients (transport-encryption).
    let recipients = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    let plaintext =
        b"Hello, encrypted PQC+V6 world! This should roundtrip via Encryptor/Decryptor.";

    // Encrypt to `recipients`.
    let mut ciphertext = Vec::new();
    {
        let message = Message::new(&mut ciphertext);
        let message = Encryptor::for_recipients(message, recipients).build()?;
        let mut w = LiteralWriter::new(message).build()?;
        w.write_all(plaintext)?;
        w.finalize()?;
    }

    println!("  ✓ Encrypted message size: {} bytes", ciphertext.len());

    // We need a cert with secret key material (TSK) for decryption.
    let tsk = cert.as_tsk();

    // Helper for decryption + (optional) signature verification.
    struct EncHelper<'a> {
        tsk: &'a openpgp::Cert,
        policy: &'a P,
    }

    impl<'a> VerificationHelper for EncHelper<'a> {
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<openpgp::Cert>> {
            // We only care about our own cert here.
            Ok(vec![self.tsk.clone()])
        }

        fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
            // For this demo we just say "sure, fine".
            Ok(())
        }
    }

    impl<'a> DecryptionHelper for EncHelper<'a> {
        fn decrypt(
            &mut self,
            pkesks: &[PKESK],
            _skesks: &[SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
        ) -> openpgp::Result<Option<openpgp::Cert>> {
            // Try each PKESK with each suitable *secret* key we have.
            for pkesk in pkesks {
                for ka in self
                    .tsk
                    .keys()
                    .with_policy(self.policy, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .unencrypted_secret()
                    .key_handles(pkesk.recipient())
                    .for_transport_encryption()
                {
                    let mut keypair = ka.key().clone().into_keypair()?;
                    if let Ok((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        if decrypt(algo, &session_key) {
                            // Return the cert we used.
                            return Ok(Some(self.tsk.clone()));
                        }
                    }
                }
            }

            Err(openpgp::Error::InvalidOperation(
                "No suitable key to decrypt session key".into(),
            ))
        }
    }

    let helper = EncHelper { tsk: &tsk, policy };

    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?
        .with_policy(policy, None, helper)?;

    let mut decrypted = Vec::new();
    decryptor.read_to_end(&mut decrypted)?;

    println!(
        "  ✓ Decrypted message: \"{}\"",
        String::from_utf8_lossy(&decrypted)
    );

    Ok(())
}

// Helper for DETACHED SIGNATURE VERIFICATION (Step 4)
struct Helper<'a> {
    cert: &'a openpgp::Cert,
}

impl<'a> Helper<'a> {
    fn new(cert: &'a openpgp::Cert) -> Self {
        Helper { cert }
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        use openpgp::parse::stream::MessageLayer::*;

        for layer in structure.into_iter() {
            match layer {
                SignatureGroup { results } => {
                    for result in results {
                        if result.is_ok() {
                            return Ok(());
                        }
                    }
                    return Err(openpgp::Error::BadSignature(
                        "Signature verification failed".into(),
                    ));
                }
                _ => {}
            }
        }
        Err(openpgp::Error::BadSignature(
            "No signature found".into(),
        ))
    }
}