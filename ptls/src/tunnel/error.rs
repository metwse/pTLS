use crate::{
    crypto::CryptoError, io_wrapper::IoWrapperError, sub_protocol::handshake::HandshakeError, trusted_authority::TrustedAuthorityError,
};
use rsa::Error as RsaError;
use std::{error::Error as StdError, fmt::Display};

/// pTLS tunnel error types.
#[derive(Debug)]
pub enum Error {
    Handshake(HandshakeError),
    Crypto(CryptoError),
    IoWrapper(IoWrapperError),
    Rsa(RsaError),
    TrustedAuthority(TrustedAuthorityError),
    InvalidPayload,
    UnexceptedError,
    InvalidPublicKey,
    NoPublicKey,
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(handshake_error) => handshake_error.fmt(f),
            Self::Crypto(crypto_error) => crypto_error.fmt(f),
            Self::IoWrapper(io_wrapper_error) => io_wrapper_error.fmt(f),
            Self::Rsa(rsa_error) => rsa_error.fmt(f),
            Self::TrustedAuthority(trusted_authority_error) => trusted_authority_error.fmt(f),
            Self::InvalidPayload => f.write_str("cannot decode the payload"),
            Self::UnexceptedError => f.write_str("unexcepted error"),
            Self::InvalidPublicKey => f.write_str("cannot decode the provided public key"),
            Self::NoPublicKey => f.write_str("no public key received yet"),
        }
    }
}

error_impl_from!(Error; Handshake, Crypto, IoWrapper, Rsa, TrustedAuthority);
