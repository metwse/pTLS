#[tokio::test]
async fn full_handshake() {
    use super::*;

    let trusted_authority_private_key = random_private_key!();
    let trusted_authority = trusted_authority!(trusted_authority_private_key);
    let (mut server, mut peer) = tunnel_pair!(trusted_authority);

    let server_private_key = (*server.local_decrypt).as_ref();
    let server_public_key = RsaPublicKey::from(server_private_key);

    server.set_signed_public_key(Arc::new(
        trusted_authority.sign(server_public_key, i64::MAX).unwrap(),
    ));

    tokio::select! {
        result = peer.full_handshake() => result.unwrap(),
        result = server.server_handshake() => result.unwrap()
    };
}
