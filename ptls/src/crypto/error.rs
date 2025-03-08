use rsa::{signature::Error as SignatureError, Error as RsaError};
use std::{error::Error as StdError, fmt::Display};

/// Crypto error types.
#[derive(Debug)]
pub enum CryptoError {
    HashFunctionOutputTooLarge,
    Rsa(RsaError),
    Signature(SignatureError),
    InvalidHashFunction,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashFunctionOutputTooLarge => f.write_str(
                "output of the hash function is too large to encrypt with the provided public key",
            ),
            Self::Rsa(rsa_error) => rsa_error.fmt(f),
            Self::Signature(signature_error) => signature_error.fmt(f),
            Self::InvalidHashFunction => f.write_str("unknown hash function was provided"),
        }
    }
}

impl StdError for CryptoError {}

error_impl_from!(CryptoError; Rsa, Signature);
