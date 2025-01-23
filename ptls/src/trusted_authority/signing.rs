use super::{SignedPublicKey, TrustedAuthority, TrustedAuthorityError};
use rsa::{pkcs8::EncodePublicKey, RsaPublicKey};

impl TrustedAuthority {
    /// Signs given public key.
    pub fn sign(
        &self,
        public_key: RsaPublicKey,
        expries_at: i64,
    ) -> Result<SignedPublicKey, TrustedAuthorityError> {
        let mut payload = public_key.to_public_key_der()?.to_vec();
        payload.extend_from_slice(&expries_at.to_le_bytes());

        let signature = self
            .signing
            .as_ref()
            .ok_or(TrustedAuthorityError::NoPrivateKey)?
            .sign(&payload);

        Ok(SignedPublicKey {
            public_key,
            expries_at,
            signature,
        })
    }

    /// Verifies provided signed public key.
    pub fn verify(&self, signed_public_key: &SignedPublicKey) -> Result<(), TrustedAuthorityError> {
        let mut payload = signed_public_key.public_key.to_public_key_der()?.to_vec();
        payload.extend_from_slice(&signed_public_key.expries_at.to_le_bytes());

        self.verifying.verify(&payload, &signed_public_key.signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_functions::HashFunction;

    #[test]
    fn signing() {
        let trusted_authority = TrustedAuthority::try_from_private_key(random_private_key!(), HashFunction::Sha256).unwrap();

        trusted_authority.sign(random_public_key!(), 0).unwrap();
    }

    #[test]
    fn verifying() {
        let trusted_authority = TrustedAuthority::try_from_private_key(random_private_key!(), HashFunction::Sha256).unwrap();

        let public_key = random_public_key!();
        let signed_key = trusted_authority.sign(public_key.clone(), 0).unwrap();

        trusted_authority.verify(&signed_key).unwrap();
        assert_eq!(signed_key.public_key, public_key);
        assert_eq!(signed_key.expries_at, 0)
    }
}
