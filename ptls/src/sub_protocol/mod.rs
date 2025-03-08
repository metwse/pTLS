//!
//! pTLS provides three sub-protocols for categorizing and handling messages.
//!
//! Typically, during a pTLS connection, [`ApplicationData`] protocols follow
//! the [`handshake`] phase. [`Alert`] messages are sent if an error occurs,
//! though this should not happen with properly implemented pTLS in stable
//! networks.
//!
//! [`handshake`]: sub_protocol::handshake
//! [`ApplicationData`]: sub_protocol::ApplicationData
//! [`Alert`]: sub_protocol::Alert

/// The alerting sub-protocol notifies the client of errors.
pub mod alert;
/// The application layer of pTLS.
pub mod application_data;
/// A sub-protocol for key exchange.
pub mod handshake;

pub use alert::Alert;
pub use application_data::ApplicationData;

/// Content type of the message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContentType {
    /// The first byte of the message contains content type. Handshake
    /// sub-protocol has its own contentent types for the udnerlying data.
    ///
    /// ```text
    ///  0: content_type
    ///
    ///  ..payload
    /// ```
    Handshake = 0,
    /// Application-specific data that is always encrypted.
    ApplicationData = 1,
    /// First byte of this variant contains flags.
    ///
    /// ```text
    ///  0:
    ///     0 is_encrypted
    ///     1 is_fatal
    ///   2-7 reserved
    ///
    ///  ..payload
    /// ```
    Alert = 2,
}

impl TryFrom<u8> for ContentType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Handshake),
            1 => Ok(Self::ApplicationData),
            2 => Ok(Self::Alert),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
#[test]
fn alert_equality() {
    use handshake::HandshakeError;
    use Alert::*;

    assert_eq!(InvalidRandom, InvalidRandom);
    assert_eq!(
        InappropriateMessage {
            expected_types: vec![ContentType::Handshake],
            got: ContentType::ApplicationData
        },
        InappropriateMessage {
            expected_types: vec![ContentType::Handshake],
            got: ContentType::ApplicationData
        },
    );
    assert_eq!(
        HandshakeError(HandshakeError::InvalidRandom),
        HandshakeError(HandshakeError::InvalidRandom)
    );
}
