//!
//! WARNING: The [`send`] and [`receive`] objects are considered
//! unstable. Do not use those internal functions if you are not willing to
//! have changes.
//!
//! [`send`]: io_wrapper::IoWrapper::send
//! [`receive`]: io_wrapper::IoWrapper::receive

mod error;
mod receive;
mod send;

use tokio::sync::Mutex;

pub use error::IoWrapperError;

/// An unencrypted wrapper implementing functions to send/receive raw packets.
pub struct IoWrapper<R, W> {
    pub(crate) read: Mutex<R>,
    pub(crate) write: Mutex<W>,
}

impl<R, W> IoWrapper<R, W> {
    /// Creates a pTLS tunnel over provided `read` and `write` buffers.
    pub fn new((r, w): (R, W)) -> Self {
        Self {
            read: Mutex::new(r),
            write: Mutex::new(w),
        }
    }

    /// Consumes `IoWrapper`, returning underlying buffers.
    pub fn into_inner(self) -> (R, W) {
        (self.read.into_inner(), self.write.into_inner())
    }
}

#[cfg(test)]
mod test {
    use crate::sub_protocol::ContentType;

    use super::*;
    use tokio::io::{simplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn io_wrapper_into_inner() {
        let tunnel = IoWrapper::new(simplex(512));

        let (mut r, mut w) = tunnel.into_inner();

        let data = 110;

        w.write_u8(data).await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(r.read_u8().await.unwrap(), data);
    }

    #[tokio::test]
    async fn io_wrapper() {
        let tunnel = IoWrapper::new(simplex(4096));

        let payload = b"abcdefghijklmnopqrstuvwxyz1234567890987654321".repeat(64);

        tunnel
            .send(ContentType::ApplicationData, &payload)
            .await
            .unwrap();
        let (received_content_type, received_payload) = tunnel.receive().await.unwrap();

        assert_eq!(received_content_type, ContentType::ApplicationData);
        assert_eq!(received_payload, payload);
    }
}
