use crate::sub_protocol::ContentType;

/// Maximum length of the payload
pub const MAX_PAYLOAD_LENGTH: u16 = u16::MAX - std::mem::size_of::<Header>() as u16 + 1_u16;

/// pTLS payload header, standard across all versions.
#[derive(Clone)]
pub struct Header {
    pub version: u16,
    /// Indicates the sub-protocol which the message belongs to.
    pub content_type: ContentType,
    pub length: u16,
}

/// pTLS payload.
pub struct Payload<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Owned variant of pTLS payload.
pub struct OwnedPayload {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Payload<'_> {
    /// Consumes `Payload`, returning `OwnedPayload`.
    pub fn into_owned(self) -> OwnedPayload {
        OwnedPayload {
            header: self.header,
            payload: self.payload.to_owned(),
        }
    }
}
