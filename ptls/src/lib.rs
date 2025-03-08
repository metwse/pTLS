#[macro_use]
mod macros;

/// pTLS protocol version
pub const PTLS_VERSION: u16 = 0;

/// Encryption/decryption and signing/signature verifying items.
pub mod crypto;

/// pTLS tunnel that wraps a connection.
pub mod tunnel;

/// Simple IO wrapper.
pub mod io_wrapper;

/// Sub-protocol messages and error types.
pub mod sub_protocol;

/// Items used for payload sending or receiving.
pub mod payload;

/// Items used for signing/verifying public keys.
pub mod trusted_authority;

#[doc(inline)]
pub use payload::MAX_PAYLOAD_LENGTH;
