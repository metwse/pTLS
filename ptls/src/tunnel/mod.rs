#[macro_use]
mod macros;

mod encrypted_tunnel;
mod error;
mod handshake_subprotocol;
#[cfg(test)]
mod tests;

use crate::{crypto::hash_functions::*, io_wrapper::IoWrapper};
use rsa::RsaPublicKey;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use error::Error;

/// State of the pTLS tunnel.
pub enum TunnelState {
    /// A tunnel that has not yet completed the pTLS handshake.
    Handshake,
    /// The tunnel has successfully established a secure pTLS connection.
    Application,
    /// The connection has been terminated, typically due to a fatal alert,
    /// network corruption, or a network attack.
    Terminated,
    /// Indicates that the connection was closed gracefully.
    GracefullyDisconnected,
}

/// Wraps the public key that signed by a trusted authority.
pub struct SignedPublicKey {
    pub public_key: RsaPublicKey,
    pub expries_at: i64,
    pub trusted_authority_id: u64,
    pub signature: Vec<u8>,
}

/// An encrypted tunnel that implements pTLS methods and manages connection states.
#[allow(unused)]
pub struct Tunnel<R, W> {
    io_wrapper: IoWrapper<R, W>,
    signed_public: Option<Arc<SignedPublicKey>>,
    local_decrypt: Arc<DecryptFunction>,
    local_signing: Arc<SigningFunction>,
    peer_encrypt: Option<EncryptFunction>,
    peer_verifying: Option<VerifyingFunction>,
    state: TunnelState,
}

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt,
    W: AsyncWriteExt,
{
    /// Creates a new pTLS tunnel.
    pub fn new(
        (r, w): (R, W),
        local_decrypt: Arc<DecryptFunction>,
        local_signing: Arc<SigningFunction>,
    ) -> Self {
        Self {
            io_wrapper: IoWrapper::new((r, w)),
            signed_public: None,
            local_decrypt,
            local_signing,
            peer_encrypt: None,
            peer_verifying: None,
            state: TunnelState::Handshake,
        }
    }

    /// Crates [`EncryptFunction`] and [`VerifyingFunction`] for peer with the
    /// provided public key.
    pub fn set_peer_public_key(
        &mut self,
        public_key: RsaPublicKey,
        padding_hf: &HashFunction,
        signature_hf: &HashFunction,
    ) -> Result<(), Error> {
        self.peer_encrypt = Some(EncryptFunction::try_new(signature_hf, public_key.clone())?);
        self.peer_verifying = Some(VerifyingFunction::try_new(padding_hf, public_key)?);
        Ok(())
    }

    /// Sets the signted public key.
    pub fn set_signed_public_key(&mut self, signed_public_key: Arc<SignedPublicKey>) {
        self.signed_public = Some(signed_public_key);
    }
}
