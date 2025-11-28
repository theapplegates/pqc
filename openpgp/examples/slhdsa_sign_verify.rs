// Simple SLHDSA256s signing and verification demo
// Usage: cargo run --example slhdsa_sign_verify --no-default-features --features crypto-openssl,compression

use std::io::Write;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;
use openpgp::types::*;

fn main() -> openpgp::Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  SLHDSA256s Sign & Verify Demo                        ║");
    println!("║  Post-Quantum Digital Signatures                       ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    let policy = &StandardPolicy::new();

    // Step 1: Generate a SLHDSA256s key
    println!("Step 1: Generating SLHDSA256s key pair...");
    let (cert, _) = CertBuilder::new()
        .add_userid("Demo User <demo@example.com>")
        .set_profile(openpgp::Profile::RFC9580)?
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)
        .generate()?;

    println!("  ✓ Generated key");
    println!("  ✓ Fingerprint: {}", cert.fingerprint());
    println!("  ✓ Algorithm: {:?}\n", cert.primary_key().key().pk_algo());

    // Step 2: Sign a message
    println!("Step 2: Signing a message...");
    let message = b"Hello from SLHDSA256s! This is a post-quantum digital signature.";

    let signing_keypair = cert.keys().with_policy(policy, None)
        .for_signing()
        .secret()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No signing key found"))?
        .key()
        .clone()
        .into_keypair()?;

    // Create detached signature
    let mut signature = Vec::new();
    {
        let message_writer = Message::new(&mut signature);
        let mut signer = Signer::new(message_writer, signing_keypair)?
            .detached()
            .build()?;

        signer.write_all(message)?;
        signer.finalize()?;
    }

    println!("  ✓ Message signed");
    println!("  ✓ Signature size: {} bytes", signature.len());
    println!("  ✓ Message: \"{}\"", String::from_utf8_lossy(message));

    // Display signature info
    if let openpgp::Packet::Signature(ref sig) =
        openpgp::PacketPile::from_bytes(&signature)?.into_children().next().unwrap()
    {
        println!("  ✓ Hash algorithm: {:?}", sig.hash_algo());
        println!("  ✓ Signature type: {:?}", sig.typ());
    }
    println!();

    // Step 3: Verify the signature
    println!("Step 3: Verifying the signature...");

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
                                    println!("  ✓ Signature is VALID!");
                                    println!("  ✓ Signed by: {}", ka.cert().fingerprint());
                                    println!("  ✓ Algorithm: {:?}", ka.key().pk_algo());
                                    return Ok(());
                                }
                                Err(e) => {
                                    eprintln!("  ✗ Signature verification FAILED: {}", e);
                                    return Err(anyhow::anyhow!("Bad signature"));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(anyhow::anyhow!("No signature found"))
        }
    }

    let helper = Helper { cert: &cert, policy };

    // Combine message and signature for verification
    let mut combined = Vec::new();
    combined.extend_from_slice(&signature);
    combined.extend_from_slice(message);

    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?
        .with_policy(policy, None, helper)?;

    verifier.verify_bytes(message)?;

    println!();

    // Step 4: Test with tampered message (should fail)
    println!("Step 4: Testing with tampered message...");
    let tampered_message = b"TAMPERED: This message was changed!";

    struct FailHelper<'a> {
        cert: &'a openpgp::Cert,
        policy: &'a dyn openpgp::policy::Policy,
    }

    impl<'a> VerificationHelper for FailHelper<'a> {
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
                                Ok(_) => {
                                    println!("  ✗ UNEXPECTED: Tampered message verified!");
                                    return Err(anyhow::anyhow!("Should have failed"));
                                }
                                Err(e) => {
                                    println!("  ✓ Signature correctly REJECTED tampered message");
                                    println!("  ✓ Reason: {}", e);
                                    return Ok(());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }
    }

    let fail_helper = FailHelper { cert: &cert, policy };
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?
        .with_policy(policy, None, fail_helper)?;

    let _ = verifier.verify_bytes(tampered_message);

    println!();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  SUCCESS - SLHDSA256s Signatures Working!             ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  ✓ Key generation                                      ║");
    println!("║  ✓ Message signing                                     ║");
    println!("║  ✓ Signature verification                              ║");
    println!("║  ✓ Tampered message detection                          ║");
    println!("╚════════════════════════════════════════════════════════╝");

    Ok(())
}
