//!
//! pTLS provided an [`Alert`] protocol to indicate key update, closure
//! information and errors. Unlike [`ApplicationData`], alert messages may not
//! encrypted.
//!
//! Alert messages describe the alert and include an 8-bit integer indicating
//! whether the error is fatal and if the message is encrypted.
//!
//! Alerts sent before the `handshake` phase are unencrypted, while errors
//! after the `handshake` phase must be sent encrypted. All unencrypted alerts
//! are ignored after a successful [`Finished`] or [`EncryptedClientHello`]
//! phase in the `handshake`.
//!
//! [`Finished`]: handshake::Finished
//! [`EncryptedClientHello`]: handshake::EncryptedClientHello

use super::{handshake::HandshakeError, ContentType};

/// Message types are sent in the `alert` sub-protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum Alert {
    /// Error occuring during the `handshake` phase, are always fatal.
    HandshakeError(HandshakeError),

    /// The random sent in [`ApplicationData`] or [`Alert`] itself is not
    /// valid.
    ///
    /// [`ApplicationData`]: super::ApplicationData
    InvalidRandom,

    /// An invalid message was received. This should not occur in properly
    /// implemented pTLS systems.
    DecryptError,

    /// Received a pTLS message that is not valid right now.
    InappropriateMessage {
        expected_types: Vec<ContentType>,
        got: ContentType,
    },
}
