# pTLS
> **Development paused** — this project is currently on hold.
> Work on `pTLS` will resume once the foundational `e2ee` crate is completed.

This project is not abandoned - just deferred. Active development is focused on
the shared core (`e2ee`) at this time.\
[`e2ee`](https://crates.io/crates/e2ee) — a flexible, protocol-agnostic
end-to-end encryption library for Rust.

## Status
pTLS is currently unstable. The 0.1.x versions will include both API changes
and bug fixes. In version 0.2.y, the handshake sub-protocol will be updated,
and elliptic curve key agreement will be implemented.

Currently, pTLS uses only the [RustCrypto](https://github.com/rustcrypto)
provider. Adding [OpenSSL](https://crates.io/crates/openssl) as another
provider is planned for version 0.3.
