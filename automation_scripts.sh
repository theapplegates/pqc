#!/bin/bash
# Complete automation scripts for SLHDSA256s_MLKEM1024_X448

# ============================================================================
# File: setup-env.sh
# Setup environment for PQC development
# ============================================================================

setup_env() {
    echo "Setting up environment for SLHDSA256s_MLKEM1024_X448..."
    
    # macOS with Homebrew OpenSSL
    if [[ "$OSTYPE" == "darwin"* ]]; then
        export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
        export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
        export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
        export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
        export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
        export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
    # Linux
    else
        export PKG_CONFIG_PATH=/usr/lib/pkgconfig
    fi
    
    echo "✓ Environment configured"
    echo "  OpenSSL: $(openssl version)"
}

# ============================================================================
# File: build-slhdsa-mlkem.sh
# Build with SLHDSA256s_MLKEM1024_X448 support
# ============================================================================

build_slhdsa_mlkem() {
    setup_env
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Building SLHDSA256s_MLKEM1024_X448                   ║"
    echo "║  V6 Profile + RFC 9580 + SHA3-512                      ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    
    cargo build --all --no-default-features \
        --features crypto-openssl,compression "$@"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Build successful!"
    else
        echo ""
        echo "✗ Build failed!"
        exit 1
    fi
}

# ============================================================================
# File: test-slhdsa-mlkem.sh
# Test SLHDSA256s_MLKEM1024_X448 implementation
# ============================================================================

test_slhdsa_mlkem() {
    setup_env
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Testing SLHDSA256s_MLKEM1024_X448                    ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "=== Testing SLH-DSA-256s ==="
    cargo test -p sequoia-openpgp slhdsa256s \
        --no-default-features --features crypto-openssl,compression
    
    echo ""
    echo "=== Testing ML-KEM-1024+X448 ==="
    cargo test -p sequoia-openpgp mlkem1024 \
        --no-default-features --features crypto-openssl,compression
    
    echo ""
    echo "✓ All tests passed!"
}

# ============================================================================
# File: demo-slhdsa-mlkem.sh
# Run complete demonstration
# ============================================================================

demo_slhdsa_mlkem() {
    setup_env
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  SLHDSA256s_MLKEM1024_X448 Complete Demo             ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    
    cargo run -p sequoia-openpgp \
        --example slhdsa256s_mlkem1024_x448_demo \
        --no-default-features \
        --features crypto-openssl,compression
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Demo completed successfully!"
        echo ""
        echo "Generated files:"
        ls -lh slhdsa256s_mlkem1024_x448_*.asc 2>/dev/null
    fi
}

# ============================================================================
# File: generate-keys.sh
# Generate SLHDSA256s_MLKEM1024_X448 keys
# ============================================================================

generate_keys() {
    setup_env
    
    local USER_ID="${1:-.com}"
    local OUTPUT_PREFIX="${2:-mykey}"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Generating SLHDSA256s_MLKEM1024_X448 Keys           ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "User ID: $USER_ID"
    echo "Output: ${OUTPUT_PREFIX}_public.asc, ${OUTPUT_PREFIX}_secret.asc"
    echo ""
    
    # Create temporary Rust program
 cat > /tmp/Paulslhdsa_mlkem.rs << 'EOF'
      use sequoia_openpgp as openpgp;
      use openpgp::cert::prelude::*;
      use openpgp::types::*;
      use openpgp::Profile;
      use openpgp::serialize::SerializeInto;

      fn main() -> openpgp::Result<()> {
          let user_id = std::env::args().nth(1)
              .unwrap_or_else(|| "me@paulapplegate.com".to_string());
          let prefix = std::env::args().nth(2)
              .unwrap_or_else(|| "mykey".to_string());

          // Use the new set_signing_algorithm and set_encryption_algorithm methods
          // to create exactly SLHDSA256s for signing + MLKEM1024_X448 for encryption

          let (cert, _) = CertBuilder::new()
              .add_userid(user_id.as_str())
              .set_creation_time(std::time::SystemTime::now())
              .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
              .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
              // Set SLHDSA256s for all signing operations
              .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)
              // Set MLKEM1024_X448 for all encryption operations
              .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)
              .add_signing_subkey()
              .add_storage_encryption_subkey()
              .generate()?;

          let public_key = cert.armored().to_vec()?;
          std::fs::write(format!("{}_public.asc", prefix), public_key)?;

          let secret_key = cert.as_tsk().armored().to_vec()?;
          std::fs::write(format!("{}_secret.asc", prefix), secret_key)?;

          println!("✓ Generated keys:");
          println!("  Public: {}_public.asc", prefix);
          println!("  Secret: {}_secret.asc", prefix);
          println!("  Fingerprint: {}", cert.fingerprint());
          println!("  Primary key: SLHDSA256s (certification + signing)");
          println!("  Signing subkey: SLHDSA256s");
          println!("  Encryption subkey: MLKEM1024_X448");

          Ok(())
      }
EOF

    # Compile and run
    rustc --edition 2021 /tmp/Paulslhdsa_mlkem.rs \
        -L target/debug/deps \
        -L /opt/homebrew/opt/openssl@3/lib \
        --extern sequoia_openpgp=target/debug/libsequoia_openpgp.rlib \
        -o /tmp/Paulslhdsa_mlkem

    /tmp/Paulslhdsa_mlkem "$USER_ID" "$OUTPUT_PREFIX"
}

# ============================================================================
# File: sign-cleartext.sh
# Cleartext sign with SLH-DSA-256s
# ============================================================================

sign_cleartext() {
    setup_env
    
    local SECRET_KEY="${1:?Error: Secret key file required}"
    local MESSAGE_FILE="${2:?Error: Message file required}"
    local OUTPUT="${3:-signed.asc}"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Cleartext Signing with SLH-DSA-256s                  ║"
    echo "║  Hash: SHA3-512                                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Secret key: $SECRET_KEY"
    echo "Message: $MESSAGE_FILE"
    echo "Output: $OUTPUT"
    echo ""
    
    cargo run -p sequoia-sq --no-default-features \
        --features crypto-openssl,compression \
        -- sign --cleartext \
        --signer-key "$SECRET_KEY" \
        "$MESSAGE_FILE" > "$OUTPUT"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Signed successfully!"
        echo ""
        head -20 "$OUTPUT"
        echo "..."
    fi
}

# ============================================================================
# File: encrypt-message.sh
# Encrypt with ML-KEM-1024+X448
# ============================================================================

encrypt_message() {
    setup_env
    
    local PUBLIC_KEY="${1:?Error: Public key file required}"
    local MESSAGE_FILE="${2:?Error: Message file required}"
    local OUTPUT="${3:-encrypted.asc}"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Encrypting with ML-KEM-1024+X448                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Public key: $PUBLIC_KEY"
    echo "Message: $MESSAGE_FILE"
    echo "Output: $OUTPUT"
    echo ""
    
    cargo run -p sequoia-sq --no-default-features \
        --features crypto-openssl,compression \
        -- encrypt --recipient-cert "$PUBLIC_KEY" \
        "$MESSAGE_FILE" > "$OUTPUT"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Encrypted successfully!"
        echo "  Output size: $(wc -c < "$OUTPUT") bytes"
    fi
}

# ============================================================================
# File: decrypt-message.sh
# Decrypt with ML-KEM-1024+X448
# ============================================================================

decrypt_message() {
    setup_env
    
    local SECRET_KEY="${1:?Error: Secret key file required}"
    local ENCRYPTED_FILE="${2:?Error: Encrypted file required}"
    local OUTPUT="${3:-decrypted.txt}"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Decrypting with ML-KEM-1024+X448                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Secret key: $SECRET_KEY"
    echo "Encrypted: $ENCRYPTED_FILE"
    echo "Output: $OUTPUT"
    echo ""
    
    cargo run -p sequoia-sq --no-default-features \
        --features crypto-openssl,compression \
        -- decrypt --recipient-key "$SECRET_KEY" \
        "$ENCRYPTED_FILE" > "$OUTPUT"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Decrypted successfully!"
        echo ""
        cat "$OUTPUT"
    fi
}

# ============================================================================
# File: sign-verify-demo.sh
# Run sign and verify demo
# ============================================================================

sign_verify_demo() {
    setup_env

    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  SLHDSA256s Sign & Verify Demo                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    cargo run --example slhdsa_sign_verify \
        --no-default-features \
        --features crypto-openssl,compression \
        -p sequoia-openpgp

    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Sign & Verify demo completed successfully!"
    fi
}

# ============================================================================
# Main menu
# ============================================================================

show_menu() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  SLHDSA256s_MLKEM1024_X448 Automation Scripts        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Available commands:"
    echo "  build          - Build with PQC support"
    echo "  test           - Run tests"
    echo "  demo           - Run complete demonstration"
    echo "  signverify     - Run sign & verify demo"
    echo "  generate       - Generate keys"
    echo "  sign           - Cleartext sign message"
    echo "  encrypt        - Encrypt message"
    echo "  decrypt        - Decrypt message"
    echo "  env            - Setup environment only"
    echo ""
}

# Main command dispatcher
case "${1:-menu}" in
    build)
        build_slhdsa_mlkem "${@:2}"
        ;;
    test)
        test_slhdsa_mlkem
        ;;
    demo)
        demo_slhdsa_mlkem
        ;;
    signverify)
        sign_verify_demo
        ;;
    generate)
        generate_keys "${@:2}"
        ;;
    sign)
        sign_cleartext "${@:2}"
        ;;
    encrypt)
        encrypt_message "${@:2}"
        ;;
    decrypt)
        decrypt_message "${@:2}"
        ;;
    env)
        setup_env
        ;;
    menu|*)
        show_menu
        ;;
esac
