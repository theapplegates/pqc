//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.

use crate::crypto::{
    mem::Protected,
    mpi::ProtectedMPI,
};

pub mod aead;
pub mod asymmetric;
pub mod der;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        std::ffi::CStr::from_bytes_with_nul(
            ossl::bindings::OPENSSL_FULL_VERSION_STR)
            .expect("version to be 0-terminated")
            .to_str()
            .expect("version to be valid UTF-8")
            .into()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        // Previously, this mapped to RAND_bytes:
        //
        //openssl::rand::rand_bytes(buf)?;

        let ctx = context();
        let mut rand_ctx = ossl::rand::EvpRandCtx::new_hmac_drbg(
            &ctx, ossl::digest::DigestAlg::Sha2_512, b"")?;
        rand_ctx.generate(b"", buf)?;
        Ok(())
    }
}

/// Returns a library context for use with `ossl`.
pub fn context() -> &'static ossl::OsslContext {
    use std::sync::OnceLock;
    static OSSL_CONTEXT: OnceLock<ossl::OsslContext> =
        OnceLock::new();

    OSSL_CONTEXT.get_or_init(|| ossl::OsslContext::new_lib_ctx())
}

impl From<ossl::OsslSecret> for Protected {
    fn from(v: ossl::OsslSecret) -> Self {
        Protected::from(v.as_ref())
    }
}

impl From<&ossl::OsslSecret> for Protected {
    fn from(v: &ossl::OsslSecret) -> Self {
        Protected::from(v.as_ref())
    }
}

impl From<ossl::OsslSecret> for ProtectedMPI {
    fn from(v: ossl::OsslSecret) -> Self {
        ProtectedMPI::from(v.as_ref())
    }
}

impl From<&ossl::OsslSecret> for ProtectedMPI {
    fn from(v: &ossl::OsslSecret) -> Self {
        ProtectedMPI::from(v.as_ref())
    }
}

impl From<&Protected> for ossl::OsslSecret {
    fn from(v: &Protected) -> Self {
        ossl::OsslSecret::from_slice(v.as_ref())
    }
}
