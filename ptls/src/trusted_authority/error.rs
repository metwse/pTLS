use crate::crypto::CryptoError;
use rsa::pkcs8::spki::Error as SpkiError;
use std::{error::Error as StdError, fmt::Display};

/// Trusted authority error types.
#[derive(Debug)]
pub enum TrustedAuthorityError {
    /// An error occured during key encoding/decoding.
    Spki(SpkiError),
    /// Errors occured in cryptographic funcitons.
    Crypto(CryptoError),
    /// Trusted authority struct does not capable of signing.
    NoPrivateKey,
}

impl StdError for TrustedAuthorityError {}

impl Display for TrustedAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spki(spki_error) => spki_error.fmt(f),
            Self::Crypto(crypto_error) => crypto_error.fmt(f),
            Self::NoPrivateKey => f.write_str("no private key is given"),
        }
    }
}

error_impl_from!(TrustedAuthorityError; Spki, Crypto);
