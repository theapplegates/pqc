#!/bin/bash
# run_demo.sh - Simple script to run keygen, sign, and verify demo

set -e

echo "════════════════════════════════════════════════════════"
echo "  Setting up environment..."
echo "════════════════════════════════════════════════════════"

# macOS OpenSSL setup
if [[ "$OSTYPE" == "darwin"* ]]; then
    export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
    export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
    export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
    export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
    export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
    export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
    echo "✓ OpenSSL 3.x environment configured"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Building Sequoia with PQC support..."
echo "════════════════════════════════════════════════════════"

cargo build -p sequoia-openpgp --example pqc_sign_verify \
    --no-default-features --features crypto-openssl,compression

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Running keygen, sign, and verify demo..."
echo "════════════════════════════════════════════════════════"
echo ""

cargo run -p sequoia-openpgp --example pqc_sign_verify \
    --no-default-features --features crypto-openssl,compression

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Generated files:"
echo "════════════════════════════════════════════════════════"
ls -lh alice_*.asc message_signed.asc 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════"
echo "  View signed message:"
echo "════════════════════════════════════════════════════════"
head -20 message_signed.asc
echo "... (signature continues) ..."
echo ""
echo "✓ Demo complete!"
