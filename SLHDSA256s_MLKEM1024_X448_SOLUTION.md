# SLHDSA256s + MLKEM1024_X448 Solution

## Problem Summary

Original error:
```
Error: Invalid operation: Algorithm SLHDSA256s not supported for custom cipher suite with these key flags
```

**Root cause**: Trying to use SLHDSA256s (signing-only algorithm) for encryption subkeys.

## Solution

Use the new `set_signing_algorithm()` and `set_encryption_algorithm()` methods from the `malte/certbuilder_pk_algos` branch:

```rust
let (cert, _) = CertBuilder::new()
    .add_userid("alice@example.com")
    .set_profile(Profile::RFC9580)?  // V6 profile required for PQC
    .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
    // Set SLHDSA256s for all signing operations
    .set_signing_algorithm(PublicKeyAlgorithm::SLHDSA256s, None, None)
    // Set MLKEM1024_X448 for all encryption operations
    .set_encryption_algorithm(PublicKeyAlgorithm::MLKEM1024_X448, None, None)
    .add_signing_subkey()
    .add_storage_encryption_subkey()
    .generate()?;
```

## Generated Certificate Structure

Successfully creates a V6 certificate with:

- **Primary key**: SLHDSA256s (certification + signing)
- **Signing subkey**: SLHDSA256s
- **Encryption subkey**: MLKEM1024_X448

## Usage

### Generate keys:
```bash
./automation_scripts.sh generate "me@paulapplegate.com" "paul"
```

### Output:
- `alice_public.asc` (Public key)
- `alice_secret.asc` (Secret key)

### Key sizes:
- Public key: ~205 KB
- Secret key: ~205 KB
- (Large due to PQC algorithm overhead)

## Branch Information

- **Current branch**: `malte/certbuilder_pk_algos`
- **Commit**: `ddc3006a` - Add set_encryption_algorithm and set_signing_algorithm to CertBuilder
- **Author**: Malte Meiboom
- **Date**: Nov 26, 2025

## Key Features

The new methods allow:
1. Independent control of signing and encryption algorithms
2. Mixing different PQC algorithms (e.g., SLHDSA256s + MLKEM1024_X448)
3. No need for `CipherSuite::Custom` variant

## Files Modified

1. `automation_scripts.sh` - Updated key generation to use new methods
2. `openpgp/examples/slhdsa_mlkem_demo.rs` - Updated demo

## Verification

Keys generated successfully:
```
✓ Generated keys:
  Public: alice_public.asc
  Secret: alice_secret.asc
  Fingerprint: A04A58D59F0E0B2FF4E47D91E2C06D3022D9BA4D1D3FB2C517EDB9ED516D3D39
  Primary key: SLHDSA256s (certification + signing)
  Signing subkey: SLHDSA256s
  Encryption subkey: MLKEM1024_X448
```

## Hash Algorithms with V6 Keys

**Important**: All Version 6 keys automatically use SHA3 for cryptographic operations:

- ✓ SHA3-512: YES (automatic with V6)
- ✓ SLHDSA256s internally uses SHAKE-256 (FIPS 205)
- ✓ OpenPGP V6 signatures can use SHA3-512 hash algorithm

When signing with SLHDSA256s on V6 keys, SHA3-512 is the appropriate hash algorithm choice for OpenPGP signatures, complementing SLHDSA's internal SHAKE-256 usage.

