use super::CryptoError;
use rand::rngs::OsRng;
use rsa::{
    pss::{BlindedSigningKey, Signature, VerifyingKey},
    sha2::{digest::FixedOutputReset, Digest},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};

/// Signing using PSS.
pub struct Signing<H>
where
    H: Digest + FixedOutputReset,
{
    pub signing_key: BlindedSigningKey<H>,
}

/// Signature verification using PSS.
pub struct Verifying<H>
where
    H: Digest + FixedOutputReset,
{
    pub verifying_key: VerifyingKey<H>,
}

impl<H> Signing<H>
where
    H: Digest + FixedOutputReset,
{
    /// Creates a new [`Signing`].
    pub fn try_new(private_key: RsaPrivateKey) -> Result<Self, CryptoError> {
        if private_key.n().bits() / 8 <= <H as Digest>::output_size() * 2 + 2 {
            return Err(CryptoError::HashFunctionOutputTooLarge);
        }

        Ok(Self {
            signing_key: BlindedSigningKey::<H>::new(private_key),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign_with_rng(&mut OsRng, msg).to_vec()
    }
}

impl<H> Verifying<H>
where
    H: Digest + FixedOutputReset,
{
    /// Creates a new [`Verifying`].
    pub fn try_new(public_key: RsaPublicKey) -> Result<Self, CryptoError> {
        if public_key.n().bits() / 8 <= <H as Digest>::output_size() * 2 + 2 {
            return Err(CryptoError::HashFunctionOutputTooLarge);
        }

        Ok(Self {
            verifying_key: VerifyingKey::new(public_key),
        })
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.verifying_key
            .verify(msg, &Signature::try_from(signature)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rsa::sha2::{Sha256, Sha512};

    #[test]
    fn sign_verify() {
        let private_key = random_private_key!();
        let public_key = RsaPublicKey::from(&private_key);

        let signing = Signing::<Sha256>::try_new(private_key).unwrap();
        let verifying = Verifying::<Sha256>::try_new(public_key).unwrap();

        let payload = [0, 1, 2, 3, 4, 5, 6, 7].repeat(64);
        let signature = signing.sign(&payload);

        verifying.verify(&payload, &signature).unwrap();
    }

    #[test]
    #[should_panic]
    fn excessive_hash_function() {
        Signing::<Sha512>::try_new(random_private_key!(512)).unwrap();
    }
}
