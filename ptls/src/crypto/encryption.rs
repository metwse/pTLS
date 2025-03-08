use super::error::CryptoError;
use rand::rngs::OsRng;
use rsa::{
    sha2::digest::{Digest, DynDigest},
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use std::marker::PhantomData;

/// Encryption using OAEP padding.
pub struct Encrypt<H> {
    pub public_key: RsaPublicKey,
    block_size: usize,
    available_block_size: usize,
    hash_function: PhantomData<H>,
}

/// Decryption using OAEP padding.
pub struct Decrypt<H> {
    pub private_key: RsaPrivateKey,
    block_size: usize,
    available_block_size: usize,
    hash_function: PhantomData<H>,
}

impl<H> Encrypt<H>
where
    H: 'static + Digest + DynDigest + Send + Sync,
{
    /// Creates a new [`Encrypt`].
    pub fn try_new(public_key: RsaPublicKey) -> Result<Self, CryptoError> {
        // OAEP padding adds an overhead of 2 * hash_output_size + 2 bytes.
        let overhead = <H as Digest>::output_size() * 2 + 2;
        // RSA encryption is limited to the key size in bytes.
        let block_size = public_key.n().bits() / 8;
        // It is impossible to encrypt when OAEP overhead exceeds RSA size.
        if overhead >= block_size {
            return Err(CryptoError::HashFunctionOutputTooLarge);
        }

        Ok(Self {
            public_key,
            block_size,
            available_block_size: block_size - overhead,
            hash_function: PhantomData,
        })
    }

    /// Encrypts the payload.
    pub fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let block_count = payload.len().div_ceil(self.available_block_size);
        let mut encrypted = Vec::with_capacity(block_count * self.block_size);

        for i in (0..payload.len()).step_by(self.available_block_size) {
            encrypted.append(&mut self.public_key.encrypt(
                &mut OsRng,
                Oaep::new::<H>(),
                &payload[i..(i + self.available_block_size).min(payload.len())],
            )?)
        }

        Ok(encrypted)
    }
}

impl<H> Decrypt<H>
where
    H: 'static + Digest + DynDigest + Send + Sync,
{
    /// Creates a new [`Decrypt`].
    pub fn try_new(private_key: RsaPrivateKey) -> Result<Self, CryptoError> {
        let overhead = <H as Digest>::output_size() * 2 + 2;
        let block_size = private_key.n().bits() / 8;
        if overhead >= block_size {
            return Err(CryptoError::HashFunctionOutputTooLarge);
        }

        Ok(Self {
            private_key,
            block_size,
            available_block_size: block_size - overhead,
            hash_function: PhantomData,
        })
    }

    /// Decrypts the payload and overwrites the original data.
    pub fn decrypt_owned(&self, payload: &mut Vec<u8>) -> Result<(), CryptoError> {
        let block_count = payload.len().div_ceil(self.block_size);

        let mut total_len = 0;
        for i in 0..block_count {
            let decrypted = self.private_key.decrypt(
                Oaep::new::<H>(),
                &payload[i * self.block_size..(i + 1) * self.block_size],
            )?;
            total_len += decrypted.len();
            payload[i * self.available_block_size..i * self.available_block_size + decrypted.len()]
                .copy_from_slice(&decrypted)
        }

        payload.truncate(total_len);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rsa::sha2::Sha256;

    use super::*;

    #[test]
    fn encrypt_decrypt() {
        let private_key = random_private_key!();
        let public_key = RsaPublicKey::from(&private_key);

        let encrypt = Encrypt::<Sha256>::try_new(public_key).unwrap();
        let decrypt = Decrypt::<Sha256>::try_new(private_key).unwrap();

        let payload = [0, 1, 2, 3, 4, 5, 6, 7].repeat(64);

        let mut new_payload = encrypt.encrypt(&payload).unwrap();
        decrypt.decrypt_owned(&mut new_payload).unwrap();

        assert_eq!(payload, *new_payload)
    }

    #[test]
    #[should_panic]
    fn excessive_padding_decrpytor() {
        Decrypt::<Sha256>::try_new(random_private_key!(512)).unwrap();
    }

    #[test]
    #[should_panic]
    fn excessive_padding_encrypt() {
        Encrypt::<Sha256>::try_new(RsaPublicKey::from(random_private_key!(512))).unwrap();
    }
}
