//!
//! Figure below shows the full pTLS handshake:
//! ```text
//!        Client                                           Server
//!
//! Key  ^ ClientHello
//! Exch |    public_key
//!      |    signature_hf
//!      v    padding_hf           ------->
//!
//!                                                 [ServerHello]  ^ Key
//!                                                  public_key    | Exch
//!                                                  expries_at    |
//!                                                signature_hf    |
//!                                                  padding_hf    |
//!                                       thrusted_authority_id    |
//!                                <-------           signature    v
//!
//! Auth ^ {Finished}
//!      |   random
//!      v   random_signature      ------->
//!
//!        {ApplicationData}       <------>       [ApplicationData]
//!
//!
//!     [] Indicates messages protected using client's public key.
//!     {} Indicates messages protected using server's public key.
//! ```
//!
//! The full handshake can be thought of as having two phases (indicated in
//! diagram above):
//!
//! - `Key Exchange`: Establish shared keying material. Everything after this
//!   phase is encrypted.
//!
//! - `Authentication`: Authenticate the server and provide message confirmation
//!   random.
//!
//! In the `Key Exchange` phase, the client sends a [`ClientHello`] message,
//! which includes its public key. The server processes the [`ClientHello`] and
//! responds with a [`ServerHello`] containing its public key. Finally, the
//! client and server exchange a [`Finished`] message during the
//! `Authentication` phase. This [`Finished`] message includes a random used to
//! prevent message forgery.
//!
//!
//! Figure below shows the basic pTLS handshake:
//! ```text
//!        Client                                           Server
//!
//! Key  ^ {EncryptedClientHello}
//! Exch |    public_key
//!      |    signature_hf
//!      v    padding_hf
//! Auth ^    random
//!      v    random_signature     ------->
//!
//!        {ApplicationData}       <------>       [ApplicationData]
//! ```
//!
//! The basic handshake is a streamlined version of the full handshake,
//! recommended when the server's public key is already known. It establishes
//! a connection with a single [`EncryptedClientHello`] message, expediting
//! both the `Key Exchange` and `Authentication` phases.
//! [`EncryptedClientHello`] combines the [`ClientHello`] and [`Finished`]
//! messages into a single package.
//!
//! Typically, the basic handshake is used for reconnecting.
//!
//! [`ClientHello`]: handshake::ClientHello
//! [`ServerHello`]: handshake::ServerHello
//! [`Finished`]: handshake::Finished
//! [`EncryptedClientHello`]: handshake::EncryptedClientHello

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// When a client first connects to a server, it is required to send the
/// `ClientHello` or `EncryptedClientHello` as its first pTLS message.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub public_key: Vec<u8>,
    /// Signature hash function.
    pub signature_hf: u8,
    /// Padding hash function.
    pub padding_hf: u8,
}

/// This is an encrypted version of the `ClientHello`. Combines the
/// properties of `Finished` and `ClientHello`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedClientHello {
    pub public_key: Vec<u8>,
    pub signature_hf: u8,
    pub padding_hf: u8,
    pub random: Vec<u8>,
    pub random_signature: Vec<u8>,
}

/// The server will send this message in response to a ClientHello message
/// to proceed with the handshake.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub public_key: Vec<u8>,
    /// Unix timestamp that indicates public_key's expriation time.
    pub expries_at: i64,
    pub signature_hf: u8,
    pub padding_hf: u8,
    /// The signature provided by trusted authority for verifying the
    /// public_key and its expriation timestamp.
    pub signature: Vec<u8>,
}

/// The `Finished` message concludes the `Handshake` phase. After sending a
/// `Finished` message, the peer or the server can start sending
/// `ApplicationData`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Finished {
    /// A random 64-bit integer used to prevent message forgery. The client
    /// must include this value with `ApplicationData`.
    pub random: Vec<u8>,
    /// The random should signed by public key of the peer.
    pub random_signature: Vec<u8>,
}

/// Errors may occur during the `handshake` sub-protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// The public key provided by peer is not a valid PKCS8 key in DER
    /// format.
    InappropriatePublicKey,

    /// The certificate authority is not a known certificate issuer.
    UnknownCa,

    /// The signature provided by peer is not valid.
    InvalidSignature,

    /// The random sent by peer is not valid.
    InvalidRandom,

    /// Message sent with invalid content type.
    InvalidContentType,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCa => f.write_str("unknown ca"),
            Self::InvalidSignature => f.write_str("signature invalid"),
            Self::InvalidRandom => f.write_str("random invalid"),
            Self::InappropriatePublicKey => f.write_str("cannot parse public key"),
            Self::InvalidContentType => f.write_str("provided content type is not known"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Common handshake payload methods.
pub trait HandshakePayload {
    fn content_type() -> HandshakeContentType;
}

macro_rules! impl_handshake_payload {
    ($( ($struct:ident, $content_type:expr ) ),*) => {
        /// Numeric content type ids of the handshake messages.
        #[derive(Debug, Eq, PartialEq)]
        pub enum HandshakeContentType {
            $(
                $struct = $content_type
            ),*
        }

        impl TryFrom<u8> for HandshakeContentType {
            type Error = HandshakeError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $content_type => Ok(Self::$struct),
                    )*
                    _ => Err(HandshakeError::InvalidContentType)
                }
            }
        }

        $(
            impl HandshakePayload for $struct {
                fn content_type() -> HandshakeContentType {
                    HandshakeContentType::$struct
                }
            }
        )*
    };
}

impl_handshake_payload!(
    (ClientHello, 0),
    (EncryptedClientHello, 1),
    (ServerHello, 2),
    (Finished, 3)
);
