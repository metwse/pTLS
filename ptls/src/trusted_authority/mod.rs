mod error;
mod signing;

use crate::crypto::{
    hash_functions::{HashFunction, SigningFunction, VerifyingFunction},
    CryptoError,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub use error::TrustedAuthorityError;

/// Wraps the public key that signed by a trusted authority.
#[derive(Serialize, Deserialize)]
pub struct SignedPublicKey {
    pub public_key: RsaPublicKey,
    pub expries_at: i64,
    pub signature: Vec<u8>,
}

/// pTLS trusted authority.
pub struct TrustedAuthority {
    pub(super) signing: Option<SigningFunction>,
    pub(super) verifying: VerifyingFunction,
}

impl TrustedAuthority {
    /// Creates a new `TrustedAuthority`.
    pub fn try_new(
        public_key: RsaPublicKey,
        hash_function: HashFunction,
    ) -> Result<Self, CryptoError> {
        let verifying = VerifyingFunction::try_new(&hash_function, public_key)?;

        Ok(Self {
            signing: None,
            verifying,
        })
    }

    /// Creates a new `TrustedAuthority` capable of signing public keys.
    pub fn try_from_private_key(
        private_key: RsaPrivateKey,
        hash_function: HashFunction,
    ) -> Result<Self, CryptoError> {
        let public_key = RsaPublicKey::from(&private_key);
        let verifying = VerifyingFunction::try_new(&hash_function, public_key)?;
        let signing = Some(SigningFunction::try_new(&hash_function, private_key)?);

        Ok(Self { signing, verifying })
    }
}
