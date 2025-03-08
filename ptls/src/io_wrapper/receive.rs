use super::{IoWrapper, IoWrapperError};
use crate::{payload::MAX_PAYLOAD_LENGTH, sub_protocol::ContentType, PTLS_VERSION};
use tokio::io::AsyncReadExt;

impl<R, W> IoWrapper<R, W>
where
    R: AsyncReadExt + Unpin,
{
    /// Reads a raw pTLS payload from `read` buffer.
    pub async fn receive(&self) -> Result<(ContentType, Vec<u8>), IoWrapperError> {
        let read = &mut *self.read.lock().await;

        let version = read.read_u16().await?;
        let content_type = read.read_u8().await?;
        let length = read.read_u16().await?;

        match length {
            0 => return Err(IoWrapperError::NoPayload),
            _ if length > MAX_PAYLOAD_LENGTH => {
                return Err(IoWrapperError::MessageTooLong(length as usize))
            }
            _ => (),
        };

        if version != PTLS_VERSION {
            return Err(IoWrapperError::InappropriateVersion(version));
        }

        let mut payload_reader = read.take(length as u64);

        // Check whether the content type indicates a valid type.
        let content_type = if let Ok(content_type) = ContentType::try_from(content_type) {
            content_type
        } else {
            tokio::io::copy(&mut payload_reader, &mut tokio::io::sink()).await?;
            return Err(IoWrapperError::UnknownContentType(content_type));
        };

        let mut encrypted_payload = Vec::with_capacity(length as usize);
        payload_reader.read_to_end(&mut encrypted_payload).await?;

        Ok((content_type, encrypted_payload))
    }
}

#[cfg(test)]
mod err_tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    // Creates a mock tunnel and receives the specified `payload` from it.
    async fn test_payload(payload: &[u8]) -> Result<(ContentType, Vec<u8>), IoWrapperError> {
        let (r, mut w) = tokio::io::simplex(512);

        w.write_all(payload).await.unwrap();
        w.flush().await.unwrap();

        let tunnel = IoWrapper::new((r, w));

        tunnel.receive().await
    }

    #[tokio::test]
    async fn invalid_content_type() {
        assert!(matches!(
            test_payload(&[0, 0, 255, 0, 1, 123]).await,
            Err(IoWrapperError::UnknownContentType(255))
        ));
    }

    #[tokio::test]
    async fn no_payload() {
        assert!(matches!(
            test_payload(&[0, 0, 1, 0, 0]).await,
            Err(IoWrapperError::NoPayload)
        ));
    }

    #[tokio::test]
    async fn message_too_long() {
        assert!(matches!(
            test_payload(&[0, 0, 1, 255, 255]).await,
            Err(IoWrapperError::MessageTooLong(length)) if length as u16 == u16::MAX
        ));
    }

    #[tokio::test]
    async fn version_not_supported() {
        assert!(matches!(
            test_payload(&[0, 1, 1, 0, 1, 123]).await,
            Err(IoWrapperError::InappropriateVersion(version)) if version == 1
        ));
    }
}
