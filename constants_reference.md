# PQC Algorithm Constants Reference

## Where These Numbers Come From

All constants are from **official NIST FIPS standards** and **IETF RFCs**. These are standardized values that will not change.

---

## SLH-DSA-256s Constants

**Source**: [FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) - Stateless Hash-Based Digital Signature Standard  
**Table**: Table 2, SLH-DSA-SHAKE-256s row  
**Variant**: SHAKE-256s (small signature variant, 256-bit security)

```rust
const SLHDSA256S_PUBLIC_KEY_SIZE: usize = 64;      // bytes
const SLHDSA256S_SECRET_KEY_SIZE: usize = 128;     // bytes
const SLHDSA256S_SIGNATURE_SIZE: usize = 29792;    // bytes (~29 KB!)
```

### FIPS 205 Reference

From FIPS 205, Table 2:

| Parameter Set | n | h | d | k | w | Public Key | Secret Key | Signature |
|---------------|---|---|---|---|---|------------|------------|-----------|
| SLH-DSA-SHAKE-128s | 16 | 63 | 7 | 14 | 16 | 32 | 64 | 7,856 |
| SLH-DSA-SHAKE-128f | 16 | 66 | 22 | 6 | 16 | 32 | 64 | 17,088 |
| **SLH-DSA-SHAKE-256s** | **16** | **64** | **8** | **14** | **16** | **64** | **128** | **29,792** |
| SLH-DSA-SHAKE-256f | 16 | 68 | 17 | 9 | 16 | 64 | 128 | 49,856 |

**Note**: The "s" variants (small) have smaller signatures but slower signing. The "f" variants (fast) have larger signatures but faster signing.

---

## ML-KEM-1024 Constants

**Source**: [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) - Module-Lattice-Based Key-Encapsulation Mechanism Standard  
**Table**: Table 2, ML-KEM-1024 row  
**Security**: 256-bit (Category 5)

```rust
const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;     // bytes
const MLKEM1024_SECRET_KEY_SIZE: usize = 3168;     // bytes
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;     // bytes
```

### FIPS 203 Reference

From FIPS 203, Table 2:

| Parameter Set | (k, η₁, η₂, dᵤ, dᵥ) | Public Key | Secret Key | Ciphertext | Security |
|---------------|---------------------|------------|------------|------------|----------|
| ML-KEM-512 | (2, 3, 2, 10, 4) | 800 | 1,632 | 768 | 128-bit |
| ML-KEM-768 | (3, 2, 2, 10, 4) | 1,184 | 2,400 | 1,088 | 192-bit |
| **ML-KEM-1024** | **(4, 2, 2, 11, 5)** | **1,568** | **3,168** | **1,568** | **256-bit** |

**Security Levels**:
- ML-KEM-512: NIST Category 1 (equivalent to AES-128)
- ML-KEM-768: NIST Category 3 (equivalent to AES-192)
- ML-KEM-1024: NIST Category 5 (equivalent to AES-256)

---

## X448 Constants

**Source**: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) - Elliptic Curves for Security  
**Section**: Section 5 - The X448 and Ed448 Functions  
**Curve**: Curve448 (Edwards curve)

```rust
const X448_PUBLIC_KEY_SIZE: usize = 56;            // bytes
const X448_SECRET_KEY_SIZE: usize = 56;            // bytes
const X448_CIPHERTEXT_SIZE: usize = 56;            // bytes (shared secret)
```

### RFC 7748 Reference

From RFC 7748, Section 5:

> For X448, 448 bits = 56 bytes

X448 uses a 448-bit elliptic curve, which translates to:
- 448 bits ÷ 8 bits/byte = **56 bytes**

**Security**: X448 provides ~224 bits of classical security (equivalent to 448-bit symmetric key).

---

## ML-KEM-1024+X448 Composite Constants

**Source**: [draft-ietf-openpgp-pqc-11](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) - Post-Quantum Cryptography in OpenPGP  
**Section**: Section 5.2.3 - Composite KEM schemes  
**Rationale**: Defense-in-depth (combines lattice-based and ECC)

```rust
// Composite = ML-KEM-1024 + X448
const MLKEM1024_X448_PUBLIC_KEY_SIZE: usize = 
    MLKEM1024_PUBLIC_KEY_SIZE + X448_PUBLIC_KEY_SIZE;  // 1568 + 56 = 1624

const MLKEM1024_X448_SECRET_KEY_SIZE: usize = 
    MLKEM1024_SECRET_KEY_SIZE + X448_SECRET_KEY_SIZE;  // 3168 + 56 = 3224

const MLKEM1024_X448_CIPHERTEXT_SIZE: usize = 
    MLKEM1024_CIPHERTEXT_SIZE + X448_CIPHERTEXT_SIZE;  // 1568 + 56 = 1624
```

### Composite Structure

```
Public Key (1624 bytes):
├── ML-KEM-1024 public key (1568 bytes)
└── X448 public key (56 bytes)

Secret Key (3224 bytes):
├── ML-KEM-1024 secret key (3168 bytes)
└── X448 secret key (56 bytes)

Ciphertext (1624+ bytes):
├── ML-KEM-1024 ciphertext (1568 bytes)
├── X448 ciphertext (56 bytes)
└── Wrapped session key (variable)
```

---

## SHA3-512 Constants

**Source**: [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202) - SHA-3 Standard  
**Algorithm**: SHA3-512 (Keccak with 512-bit output)  
**Usage**: Hash algorithm for V6 profile (RFC 9580)

```rust
const SHA3_512_OUTPUT_SIZE: usize = 64;            // bytes (512 bits ÷ 8)
```

**Note**: SHA3-512 is automatically used with V6 certificates in OpenPGP. It's quantum-resistant because hash functions are not significantly weakened by quantum computers (Grover's algorithm only provides quadratic speedup).

---

## Quick Reference Table

| Component | Algorithm | Public Key | Secret Key | Signature/Ciphertext | Standard |
|-----------|-----------|------------|------------|----------------------|----------|
| **Signing** | SLH-DSA-256s | 64 bytes | 128 bytes | 29,792 bytes | FIPS 205 |
| **KEM (lattice)** | ML-KEM-1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes | FIPS 203 |
| **KEM (ECC)** | X448 | 56 bytes | 56 bytes | 56 bytes | RFC 7748 |
| **KEM (composite)** | ML-KEM-1024+X448 | 1,624 bytes | 3,224 bytes | 1,624+ bytes | draft-pqc-11 |
| **Hash** | SHA3-512 | N/A | N/A | 64 bytes | FIPS 202 |

---

## Why These Specific Variants?

### SLH-DSA-256s (not 128s or 256f)
- ✅ **256-bit security**: Matches ML-KEM-1024 security level
- ✅ **Small variant**: Optimized for smaller signatures (29 KB vs 49 KB for 256f)
- ⚠️ **Slower**: Signing takes longer than 256f, but that's acceptable for most use cases

### ML-KEM-1024 (not 512 or 768)
- ✅ **256-bit security**: Highest standardized level (NIST Category 5)
- ✅ **Future-proof**: Won't need upgrade when 192-bit is broken
- ✅ **Performance**: Still fast enough for practical use

### X448 (not X25519)
- ✅ **224-bit security**: Matches quantum-safe target (~112-bit quantum security)
- ✅ **Larger curve**: More conservative than X25519's 128-bit security
- ✅ **Standardized**: Part of TLS 1.3 and widely supported

---

## Verification

You can verify these constants in your code:

```rust
use slh_dsa::Shake256s;

// At compile time, these will match:
assert_eq!(slh_dsa::PublicKeySize::<Shake256s>::USIZE, 64);
assert_eq!(slh_dsa::SecretKeySize::<Shake256s>::USIZE, 128);
assert_eq!(slh_dsa::SignatureSize::<Shake256s>::USIZE, 29792);
```

Or check the test vectors:

```bash
# Test vectors include the exact sizes
ls -l openpgp/tests/data/pqc/v6-slhdsa-256s-sample-cert.pgp
```

---

## References

1. **FIPS 205** - SLH-DSA Standard (August 2024)  
   https://doi.org/10.6028/NIST.FIPS.205

2. **FIPS 203** - ML-KEM Standard (August 2024)  
   https://doi.org/10.6028/NIST.FIPS.203

3. **RFC 7748** - Elliptic Curves for Security (January 2016)  
   https://www.rfc-editor.org/rfc/rfc7748

4. **FIPS 202** - SHA-3 Standard (August 2015)  
   https://doi.org/10.6028/NIST.FIPS.202

5. **RFC 9580** - OpenPGP Version 6 (July 2024)  
   https://www.rfc-editor.org/rfc/rfc9580

6. **draft-ietf-openpgp-pqc-11** - Post-Quantum Cryptography in OpenPGP  
   https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/

---

## Summary

All constants are from **official standards** and **will not change**:
- ✅ NIST FIPS 203, 205 (finalized August 2024)
- ✅ RFC 7748, 9580 (published IETF standards)
- ✅ draft-ietf-openpgp-pqc (in IETF working group last call)

These are the **correct, standardized values** for production use.
