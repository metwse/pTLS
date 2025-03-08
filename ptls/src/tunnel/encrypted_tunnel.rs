use super::{Error, Tunnel};
use crate::sub_protocol::ContentType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    /// Encrypts the payload and sends it to the peer.
    pub async fn send_internal(
        &self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<(), Error> {
        let encrypted_payload = self
            .peer_encrypt
            .as_ref()
            .ok_or(Error::NoPublicKey)?
            .encrypt(payload)?;

        self.io_wrapper
            .send(content_type, &encrypted_payload)
            .await?;

        Ok(())
    }

    /// Receives a payload and decrypts it.
    pub async fn receive_internal(&self) -> Result<(ContentType, Vec<u8>), Error> {
        let (content_type, mut payload) = self.io_wrapper.receive().await?;

        self.local_decrypt.decrypt_owned(&mut payload)?;

        Ok((content_type, payload))
    }
}

#[cfg(test)]
#[tokio::test]
async fn encrypted_tunnel() -> Result<(), super::Error> {
    use crate::sub_protocol::ContentType;
    let (server, peer) = tunnel_pair!(auth);

    let (content_type, payload) = (ContentType::Handshake, vec![1, 2, 3, 4, 5]);

    server.send_internal(content_type.clone(), &payload).await?;
    assert_eq!(peer.receive_internal().await?, (content_type, payload));

    Ok(())
}

#[cfg(test)]
#[tokio::test]
async fn encrypted_recursive_tunnel() -> Result<(), super::Error> {
    use crate::sub_protocol::ContentType;
    let tunnel = recursive_tunnel!(auth);

    let (content_type, payload) = (ContentType::Handshake, vec![1, 2, 3, 4, 5]);

    tunnel.send_internal(content_type.clone(), &payload).await?;
    assert_eq!(tunnel.receive_internal().await?, (content_type, payload));

    Ok(())
}
