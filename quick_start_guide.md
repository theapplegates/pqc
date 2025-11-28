# Quick Start: Generate Key, Sign, and Verify

## Option 1: Automated (Easiest)

### Step 1: Create the files

Save these two files in your `sequoia` directory:

**File 1**: `openpgp/examples/Paulsign_verify.rs`
- Copy the "Complete Keygen, Sign, and Verify Example" artifact

**File 2**: `run-demo.sh`
- Copy the "Simple Run Script" artifact

### Step 2: Make script executable

```bash
chmod +x run-demo.sh
```

### Step 3: Run it!

```bash
./run-demo.sh
```

**Expected output:**
```
════════════════════════════════════════════════════════
  Running keygen, sign, and verify demo...
════════════════════════════════════════════════════════

╔════════════════════════════════════════════════════════╗
║          SLHDSA256s_MLKEM1024_X448 Demo              ║
║       Generate → Sign → Verify (3 steps)              ║
╚════════════════════════════════════════════════════════╝

STEP 1: Generating V6 certificate...
  Algorithms: SLH-DSA-256s (sign) + ML-KEM-1024+X448 (encrypt)
  Profile: V6 (RFC 9580)
  Hash: SHA3-512
  ✓ Certificate fingerprint: <fingerprint>
  ✓ Primary key: SLHDSA256s
  ✓ Saved: alice_public.asc
  ✓ Saved: alice_secret.asc

STEP 2: Signing a message...
  Message: "Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s."
  ✓ Using key: SLHDSA256s
  ✓ Saved: message_signed.asc
  ✓ Signature size: ~29 KB (SLH-DSA-256s)
  ✓ Hash algorithm: SHA3-512

STEP 3: Verifying signature...
  ✓ Signature is VALID
  ✓ Signer fingerprint: <fingerprint>
  ✓ Signing algorithm: SLHDSA256s
  ✓ Quantum-resistant: YES (SLH-DSA-256s)
  ✓ Verified message: "Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s."
  ✓ Message integrity: CONFIRMED

╔════════════════════════════════════════════════════════╗
║                    SUCCESS!                            ║
╠════════════════════════════════════════════════════════╣
║  Generated Files:                                      ║
║    • alice_public.asc  - Public key                    ║
║    • alice_secret.asc  - Secret key                    ║
║    • message_signed.asc - Signed message               ║
║                                                        ║
║  What Happened:                                        ║
║    ✓ Generated V6 certificate (SLH-DSA-256s)          ║
║    ✓ Signed message with SHA3-512                     ║
║    ✓ Verified signature successfully                  ║
║    ✓ Quantum-resistant cryptography working!          ║
╚════════════════════════════════════════════════════════╝
```

---

## Option 2: Manual (Step by Step)

### Step 1: Setup Environment

```bash
# macOS
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

### Step 2: Create the example file

Save the "Complete Keygen, Sign, and Verify Example" artifact as:
```
openpgp/examples/Paulsign_verify.rs
```

### Step 3: Build

```bash
cd sequoia

cargo build -p sequoia-openpgp --example Paulsign_verify \
  --no-default-features --features crypto-openssl,compression
```

### Step 4: Run

```bash
cargo run -p sequoia-openpgp --example Paulsign_verify \
  --no-default-features --features crypto-openssl,compression
```

### Step 5: View the results

```bash
# View generated files
ls -lh alice_*.asc message_signed.asc

# View the signed message (human-readable!)
cat message_signed.asc
```

---

## Generated Files

After running, you'll have:

### 1. `alice_public.asc` - Public Key
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

<base64 encoded public key>
-----END PGP PUBLIC KEY BLOCK-----
```

**Size**: ~42 KB  
**Contains**: 
- Primary key: SLH-DSA-256s (64 bytes)
- Signing subkey: SLH-DSA-256s (64 bytes)
- Encryption subkey: ML-KEM-1024+X448 (1624 bytes)

### 2. `alice_secret.asc` - Secret Key
```
-----BEGIN PGP PRIVATE KEY BLOCK-----

<base64 encoded secret key>
-----END PGP PRIVATE KEY BLOCK-----
```

**Size**: ~43 KB  
**Contains**: Same structure but with secret key material

⚠️ **Keep this file secure!** It contains your private keys.

### 3. `message_signed.asc` - Signed Message
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA3-512

Hello, Post-Quantum World! This is a signed message using SLH-DSA-256s.
-----BEGIN PGP SIGNATURE-----

<base64 encoded signature ~29KB>
-----END PGP SIGNATURE-----
```

**Size**: ~30 KB  
**Format**: Cleartext signature (message is human-readable)  
**Hash**: SHA3-512  
**Signature**: SLH-DSA-256s (~29,792 bytes)

---

## What Just Happened?

### 1. Key Generation ✓
- Created a **V6 OpenPGP certificate** (RFC 9580)
- Primary key: **SLH-DSA-256s** for certification and signing
- Subkey 1: **SLH-DSA-256s** for signing
- Subkey 2: **ML-KEM-1024+X448** for encryption
- Exported to ASCII armored `.asc` files

### 2. Signing ✓
- Took your message as input
- Hashed it with **SHA3-512**
- Signed the hash with **SLH-DSA-256s**
- Created a **cleartext signature** (message visible)
- Signature size: **~29 KB** (large, but quantum-resistant!)

### 3. Verification ✓
- Read the signed message
- Extracted the message text
- Extracted the signature
- Verified using the public key
- Confirmed: **VALID signature**
- Confirmed: **Message integrity intact**

---

## Using the Keys

### Sign Another Message

```bash
echo "My secret message" > newmessage.txt

cargo run -p sequoia-sq --no-default-features \
  --features crypto-openssl,compression -- \
  sign --cleartext \
  --signer-key alice_secret.asc \
  newmessage.txt > newmessage_signed.asc
```

### Verify a Signature

```bash
cargo run -p sequoia-sq --no-default-features \
  --features crypto-openssl,compression -- \
  verify \
  --signer-cert alice_public.asc \
  message_signed.asc
```

### Encrypt a Message

```bash
echo "Top secret" > secret.txt

cargo run -p sequoia-sq --no-default-features \
  --features crypto-openssl,compression -- \
  encrypt \
  --recipient-cert alice_public.asc \
  secret.txt > secret_encrypted.asc
```

### Decrypt a Message

```bash
cargo run -p sequoia-sq --no-default-features \
  --features crypto-openssl,compression -- \
  decrypt \
  --recipient-key alice_secret.asc \
  secret_encrypted.asc
```

---

## Sharing Keys

### Share Your Public Key

Send `alice_public.asc` to anyone who needs to:
- ✅ Verify your signatures
- ✅ Encrypt messages to you

### Keep Secret Key Private

**NEVER share** `alice_secret.asc`. This is your private key!

### 

To get your key fingerprint:

```bash
cargo run -p sequoia-sq --no-default-features \
  --features crypto-openssl,compression -- \
  inspect alice_public.asc
```

Share the fingerprint so people can verify they have the correct public key.

---

## Understanding the Output

### Signature Size

**Why so large?** (~29 KB)

SLH-DSA-256s produces large signatures because it's **hash-based**:
- ✅ **Quantum-resistant** through hash function security
- ✅ **Well-understood** security assumptions
- ✅ **Stateless** - no state management needed
- ⚠️ **Large signatures** - trade-off for hash-based security

Compare:
- Ed25519: 64 bytes (NOT quantum-resistant)
- ML-DSA-87: ~4,595 bytes (lattice-based, quantum-resistant)
- **SLH-DSA-256s**: ~29,792 bytes (hash-based, quantum-resistant)

### Hash Algorithm

**SHA3-512** is used because:
- Required by RFC 9580 (V6 profile)
- Quantum-resistant (hash functions survive quantum attacks)
- 512-bit output provides high security margin
- Part of FIPS 202 standard

---

## Troubleshooting

### Build fails

**Error**: `fatal error: 'openssl/core_dispatch.h' file not found`

**Fix**: Set OpenSSL environment variables (see Step 1)

### Wrong algorithms used

**Error**: Certificate uses wrong algorithms (not SLH-DSA-256s)

**Fix**: Make sure you're using the custom example:
```bash
cargo run -p sequoia-openpgp --example Paulsign_verify ...
```

Not the default `sq` tool which uses different algorithms.

### Signature verification fails

**Error**: Signature invalid

**Possible causes**:
- Message was modified after signing
- Wrong public key used
- Corrupted signature file

**Debug**:
```bash
# Check the signed message
cat message_signed.asc

# Verify you're using matching keys
cargo run -p sequoia-sq --inspect alice_public.asc
```

---

## Next Steps

### 1. Generate Your Own Keys

Modify the example to use your name/email:

```rust
let (cert, _revocation) = CertBuilder::new()
    .add_userid("YourName <your@email.com>")  // ← Change this
    // ... rest of the code
```

### 2. Sign Real Documents

```bash
# Sign a PDF
cargo run -p sequoia-sq -- sign --cleartext \
  --signer-key alice_secret.asc \
  document.pdf > document.pdf.asc

# Sign code
cargo run -p sequoia-sq -- sign --detached \
  --signer-key alice_secret.asc \
  mycode.rs > mycode.rs.sig
```

### 3. Integrate with Your Application

Use the code from `Paulsign_verify.rs` as a starting point for your own applications.

### 4. Distribute Public Keys

Share your `alice_public.asc` file:
- Post on your website
- Share via keyserver
- Include in email signature
- Add to GitHub profile

---

## Summary

You've successfully:
- ✅ Generated quantum-resistant keys (SLH-DSA-256s + ML-KEM-1024+X448)
- ✅ Created a V6 OpenPGP certificate (RFC 9580)
- ✅ Signed a message with SHA3-512 hash
- ✅ Verified the signature successfully
- ✅ Exported keys to standard `.asc` format

Your cryptography is now **quantum-resistant**! 🎉
