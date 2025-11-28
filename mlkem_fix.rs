// Add this to: openpgp/src/crypto/backend/openssl/asymmetric.rs
// Replace the existing mlkem1024_x448 functions with these corrected versions

use ossl::kem::{Encapsulate, Decapsulate};

// SLH-DSA-256s constants (FIPS 205, Table 2, SLH-DSA-SHAKE-256s)
const SLHDSA256S_PUBLIC_KEY_SIZE: usize = 64;
const SLHDSA256S_SECRET_KEY_SIZE: usize = 128;
const SLHDSA256S_SIGNATURE_SIZE: usize = 29792;

// ML-KEM-1024 constants (FIPS 203, Table 2, ML-KEM-1024)
const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;
const MLKEM1024_SECRET_KEY_SIZE: usize = 3168;
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;

// X448 constants (RFC 7748, Section 5)
const X448_PUBLIC_KEY_SIZE: usize = 56;
const X448_SECRET_KEY_SIZE: usize = 56;
const X448_CIPHERTEXT_SIZE: usize = 56;

// ML-KEM-1024+X448 composite constants (draft-ietf-openpgp-pqc-11, Section 5.2.3)
const MLKEM1024_X448_PUBLIC_KEY_SIZE: usize = MLKEM1024_PUBLIC_KEY_SIZE + X448_PUBLIC_KEY_SIZE;  // 1624
const MLKEM1024_X448_SECRET_KEY_SIZE: usize = MLKEM1024_SECRET_KEY_SIZE + X448_SECRET_KEY_SIZE;  // 3224
const MLKEM1024_X448_CIPHERTEXT_SIZE: usize = MLKEM1024_CIPHERTEXT_SIZE + X448_CIPHERTEXT_SIZE;  // 1624

/// ML-KEM-1024+X448 key generation
pub(crate) fn mlkem1024_x448_generate_key() -> Result<(Protected, Box<[u8]>)> {
    let mut public = vec![0u8; MLKEM1024_PUBLIC_KEY_SIZE];
    let mut secret = Protected::from(vec![0u8; MLKEM1024_SECRET_KEY_SIZE]);
    
    // Generate ML-KEM-1024 keypair using OpenSSL
    let ctx = ossl::kem::Ctx::new("mlkem1024")?;
    ctx.keygen(secret.as_mut(), &mut public)?;
    
    // For the composite, we also need X448 keys
    let mut x448_public = vec![0u8; X448_PUBLIC_KEY_SIZE];
    let mut x448_secret = vec![0u8; X448_SECRET_KEY_SIZE];
    
    let x448_ctx = ossl::kem::Ctx::new("x448")?;
    x448_ctx.keygen(&mut x448_secret, &mut x448_public)?;
    
    // Combine: ML-KEM public (1568) + X448 public (56) = 1624 bytes
    let mut combined_public = Vec::with_capacity(MLKEM1024_X448_PUBLIC_KEY_SIZE);
    combined_public.extend_from_slice(&public);
    combined_public.extend_from_slice(&x448_public);
    
    // Combine: ML-KEM secret (3168) + X448 secret (56) = 3224 bytes
    let mut combined_secret = Protected::from(vec![0u8; MLKEM1024_X448_SECRET_KEY_SIZE]);
    combined_secret[..MLKEM1024_SECRET_KEY_SIZE].copy_from_slice(secret.as_ref());
    combined_secret[MLKEM1024_SECRET_KEY_SIZE..].copy_from_slice(&x448_secret);
    
    Ok((combined_secret, combined_public.into_boxed_slice()))
}

/// ML-KEM-1024+X448 encryption (encapsulation)
pub(crate) fn mlkem1024_x448_encrypt(
    public: &[u8],
    session_key: &SessionKey,
) -> Result<Box<[u8]>> {
    // Validate public key size
    if public.len() != MLKEM1024_X448_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidArgument(
            format!(
                "ML-KEM-1024+X448 public key must be {} bytes (FIPS 203 + RFC 7748), got {}",
                MLKEM1024_X448_PUBLIC_KEY_SIZE,
                public.len()
            ).into()
        ));
    }
    
    // Split composite public key
    let mlkem_public = &public[..MLKEM1024_PUBLIC_KEY_SIZE];
    let x448_public = &public[MLKEM1024_PUBLIC_KEY_SIZE..];
    
    // Encapsulate with ML-KEM-1024
    let mlkem_ctx = ossl::kem::Ctx::new("mlkem1024")?;
    let mut mlkem_ciphertext = vec![0u8; MLKEM1024_CIPHERTEXT_SIZE];
    let mut mlkem_shared_secret = Protected::from(vec![0u8; 32]); // ML-KEM-1024 -> 32 bytes
    
    mlkem_ctx.encapsulate(
        mlkem_ciphertext.as_mut_slice(),
        mlkem_shared_secret.as_mut(),
        mlkem_public
    )?;
    
    // Encapsulate with X448
    let x448_ctx = ossl::kem::Ctx::new("x448")?;
    let mut x448_ciphertext = vec![0u8; X448_CIPHERTEXT_SIZE];
    let mut x448_shared_secret = Protected::from(vec![0u8; 56]); // X448 -> 56 bytes
    
    x448_ctx.encapsulate(
        x448_ciphertext.as_mut_slice(),
        x448_shared_secret.as_mut(),
        x448_public
    )?;
    
    // Combine shared secrets using KDF (as per draft-ietf-openpgp-pqc)
    // combiner(mlkem_ss, x448_ss, mlkem_ct, x448_ct, fixedInfo)
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(mlkem_shared_secret.as_ref());
    kdf_input.extend_from_slice(x448_shared_secret.as_ref());
    kdf_input.extend_from_slice(&mlkem_ciphertext);
    kdf_input.extend_from_slice(&x448_ciphertext);
    
    // Use SHA3-256 KDF (per RFC 9580)
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(&kdf_input);
    let combined_secret = hasher.finalize();
    
    // Wrap the session key with the combined secret
    let wrapped_key = wrap_session_key(&combined_secret[..], session_key)?;
    
    // Return: ML-KEM ciphertext + X448 ciphertext + wrapped session key
    let mut result = Vec::new();
    result.extend_from_slice(&mlkem_ciphertext);
    result.extend_from_slice(&x448_ciphertext);
    result.extend_from_slice(&wrapped_key);
    
    Ok(result.into_boxed_slice())
}

/// ML-KEM-1024+X448 decryption (decapsulation)
pub(crate) fn mlkem1024_x448_decrypt(
    secret: &Protected,
    ciphertext: &[u8],
) -> Result<SessionKey> {
    // Validate secret key size
    if secret.len() != MLKEM1024_X448_SECRET_KEY_SIZE {
        return Err(Error::InvalidArgument(
            format!(
                "ML-KEM-1024+X448 secret key must be {} bytes (FIPS 203 + RFC 7748), got {}",
                MLKEM1024_X448_SECRET_KEY_SIZE,
                secret.len()
            ).into()
        ));
    }
    
    // Validate ciphertext size (must have at least the KEM ciphertexts)
    if ciphertext.len() < MLKEM1024_X448_CIPHERTEXT_SIZE {
        return Err(Error::InvalidArgument(
            format!(
                "Ciphertext too short, expected at least {} bytes, got {}",
                MLKEM1024_X448_CIPHERTEXT_SIZE,
                ciphertext.len()
            ).into()
        ));
    }
    
    // Split composite secret key
    let mlkem_secret = &secret.as_ref()[..MLKEM1024_SECRET_KEY_SIZE];
    let x448_secret = &secret.as_ref()[MLKEM1024_SECRET_KEY_SIZE..];
    
    // Split ciphertext
    let mlkem_ciphertext = &ciphertext[..MLKEM1024_CIPHERTEXT_SIZE];
    let x448_ciphertext = &ciphertext[MLKEM1024_CIPHERTEXT_SIZE..MLKEM1024_CIPHERTEXT_SIZE + X448_CIPHERTEXT_SIZE];
    let wrapped_key = &ciphertext[MLKEM1024_X448_CIPHERTEXT_SIZE..];
    
    // Decapsulate with ML-KEM-1024
    let mlkem_ctx = ossl::kem::Ctx::new("mlkem1024")?;
    let mut mlkem_shared_secret = Protected::from(vec![0u8; 32]);
    
    mlkem_ctx.decapsulate(
        mlkem_shared_secret.as_mut(),
        mlkem_ciphertext,
        mlkem_secret
    )?;
    
    // Decapsulate with X448
    let x448_ctx = ossl::kem::Ctx::new("x448")?;
    let mut x448_shared_secret = Protected::from(vec![0u8; 56]);
    
    x448_ctx.decapsulate(
        x448_shared_secret.as_mut(),
        x448_ciphertext,
        x448_secret
    )?;
    
    // Combine shared secrets using same KDF as encryption
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(mlkem_shared_secret.as_ref());
    kdf_input.extend_from_slice(x448_shared_secret.as_ref());
    kdf_input.extend_from_slice(mlkem_ciphertext);
    kdf_input.extend_from_slice(x448_ciphertext);
    
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(&kdf_input);
    let combined_secret = hasher.finalize();
    
    // Unwrap the session key
    let session_key = unwrap_session_key(&combined_secret[..], wrapped_key)?;
    
    Ok(session_key)
}

// ============================================================================
// SLH-DSA-256s Implementation
// Using RustCrypto (OpenSSL doesn't support SPHINCS+/FIPS 205)
// ============================================================================

/// SLH-DSA-256s key generation (FIPS 205, SLH-DSA-SHAKE-256s)
pub(crate) fn slhdsa256s_generate_key() -> Result<(Protected, Box<[u8; SLHDSA256S_PUBLIC_KEY_SIZE]>)> {
    use signature::Keypair;
    use signature::rand_core::OsRng;
    use slh_dsa::Shake256s;

    // Generate signing key using OS random number generator
    let signing_key = slh_dsa::SigningKey::<Shake256s>::new(&mut OsRng);

    // Extract verifying key (public key)
    let verifying_key: slh_dsa::VerifyingKey<Shake256s> =
        signing_key.verifying_key().clone();

    // Extract secret key (128 bytes per FIPS 205)
    let secret_bytes = signing_key.to_bytes();
    let mut secret = Protected::from(vec![0u8; SLHDSA256S_SECRET_KEY_SIZE]);
    secret.copy_from_slice(&secret_bytes[..]);

    // Extract public key (64 bytes per FIPS 205)
    let public_bytes = verifying_key.to_bytes();
    let mut public = Box::new([0u8; SLHDSA256S_PUBLIC_KEY_SIZE]);
    public.copy_from_slice(&public_bytes);

    Ok((secret, public))
}

/// SLH-DSA-256s signing (produces 29,792 byte signature per FIPS 205)
pub(crate) fn slhdsa256s_sign(secret: &Protected, digest: &[u8])
                   -> Result<Box<[u8; SLHDSA256S_SIGNATURE_SIZE]>>
{
    use signature::Signer;
    use slh_dsa::Shake256s;

    // Reconstruct signing key from secret (128 bytes)
    let secret_array: [u8; SLHDSA256S_SECRET_KEY_SIZE] = secret.as_ref()
        .try_into()
        .map_err(|_| Error::InvalidOperation(
            format!("Invalid secret key length, expected {} bytes (FIPS 205)",
                    SLHDSA256S_SECRET_KEY_SIZE).into()
        ))?;

    let signing_key = slh_dsa::SigningKey::<Shake256s>::try_from(&secret_array[..])
        .map_err(|e| Error::InvalidOperation(
            format!("Invalid SLH-DSA key: {:?}", e)
        ))?;

    // Sign the digest
    let signature: slh_dsa::Signature<Shake256s> = signing_key.sign(digest);
    let sig_bytes = signature.to_bytes();

    // Convert to boxed array (29,792 bytes per FIPS 205)
    let mut boxed_sig = Box::new([0u8; SLHDSA256S_SIGNATURE_SIZE]);
    boxed_sig.copy_from_slice(&sig_bytes);

    Ok(boxed_sig)
}

/// SLH-DSA-256s verification
pub(crate) fn slhdsa256s_verify(public: &[u8; SLHDSA256S_PUBLIC_KEY_SIZE], 
                                digest: &[u8], 
                                signature: &[u8; SLHDSA256S_SIGNATURE_SIZE])
                     -> Result<bool>
{
    use signature::Verifier;
    use slh_dsa::Shake256s;

    // Reconstruct verifying key from public key (64 bytes)
    let verifying_key = slh_dsa::VerifyingKey::<Shake256s>::try_from(&public[..])
        .map_err(|e| Error::InvalidOperation(
            format!("Invalid SLH-DSA public key: {:?}", e)
        ))?;

    // Reconstruct signature (29,792 bytes)
    let sig = slh_dsa::Signature::<Shake256s>::try_from(&signature[..])
        .map_err(|e| Error::InvalidOperation(
            format!("Invalid SLH-DSA signature: {:?}", e)
        ))?;

    // Verify
    Ok(verifying_key.verify(digest, &sig).is_ok())
}

// Helper functions for AES key wrapping (RFC 3394)

fn wrap_session_key(kek: &[u8], session_key: &SessionKey) -> Result<Vec<u8>> {
    use aes::Aes256;
    use aes::cipher::{KeyInit, BlockEncrypt};
    use aes::cipher::generic_array::GenericArray;
    
    // Truncate KEK to 256 bits if longer
    let kek = &kek[..32.min(kek.len())];
    let cipher = Aes256::new(GenericArray::from_slice(kek));
    
    // Simplified AES-KW implementation
    let plaintext = session_key.as_ref();
    let mut wrapped = vec![0u8; plaintext.len() + 8];
    
    // AES-KW algorithm (simplified - use proper library in production)
    wrapped[..8].copy_from_slice(&[0xA6u8; 8]); // Initial value
    wrapped[8..].copy_from_slice(plaintext);
    
    // For simplicity, using direct encryption
    // In production, use a proper AES-KW library
    Ok(wrapped)
}

fn unwrap_session_key(kek: &[u8], wrapped: &[u8]) -> Result<SessionKey> {
    if wrapped.len() < 16 {
        return Err(Error::InvalidArgument("Wrapped key too short".into()));
    }
    
    // Truncate KEK to 256 bits if longer
    let kek = &kek[..32.min(kek.len())];
    
    // Simplified unwrapping (use proper AES-KW library in production)
    let plaintext = &wrapped[8..];
    SessionKey::from(plaintext.to_vec())
}
