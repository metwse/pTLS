use super::{IoWrapper, IoWrapperError};
use crate::{payload::MAX_PAYLOAD_LENGTH, sub_protocol::ContentType, PTLS_VERSION};
use tokio::io::AsyncWriteExt;

impl<R, W> IoWrapper<R, W>
where
    W: AsyncWriteExt + Unpin,
{
    /// Writes a raw pTLS payload to `write` buffer.
    pub async fn send(
        &self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<(), IoWrapperError> {
        let length = match payload.len() {
            // This code errors should be unreachable in proper implementations
            // of `IoWrapper`.
            length if length > MAX_PAYLOAD_LENGTH as usize => {
                return Err(IoWrapperError::MessageTooLong(length))
            }
            0 => return Err(IoWrapperError::NoPayload),
            length => length as u16,
        };

        let write = &mut *self.write.lock().await;

        write.write_u16(PTLS_VERSION).await?;
        write.write_u8(content_type as u8).await?;
        write.write_u16(length).await?;

        write.write_all(payload).await?;

        Ok(())
    }
}

#[cfg(test)]
mod err_tests {
    use super::*;
    use std::sync::Arc;

    // Creates a mock tunnel and sends the specified `payload` to it.
    async fn test_payload(content_type: ContentType, payload: &[u8]) -> Result<(), IoWrapperError> {
        let (r, mut w) = tokio::io::simplex(u16::MAX as usize);

        w.write_all(payload).await.unwrap();
        w.flush().await.unwrap();

        let tunnel = Arc::new(IoWrapper::new((r, w)));

        tunnel.send(content_type, payload).await
    }

    #[tokio::test]
    async fn no_payload() {
        assert!(matches!(
            test_payload(ContentType::Handshake, &[]).await,
            Err(IoWrapperError::NoPayload),
        ));
    }

    #[tokio::test]
    async fn message_too_long() {
        assert!(matches!(
            test_payload(ContentType::Handshake, &vec![0; u16::MAX as usize]).await,
            Err(IoWrapperError::MessageTooLong(_)),
        ));
    }
}
