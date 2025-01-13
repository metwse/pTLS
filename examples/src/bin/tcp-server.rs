use ptls::Ptls;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load server private key
    let server_private = RsaPrivateKey::read_pkcs1_pem_file("./certs/private.pem")
        .expect("Cannot read private key");

    // Start TCP listener
    let listener = TcpListener::bind("localhost:7811").await?;

    println!("Server is running on localhost:7811");

    loop {
        if let Ok((peer, addr)) = listener.accept().await {
            println!("Accepted connection from {addr}");

            // Spawn a task to handle the connection
            tokio::spawn(handle_connection(peer, server_private.clone()));
        } else {
            eprintln!("Failed to accept connection");
        }
    }
}

async fn handle_connection(
    mut peer: tokio::net::TcpStream,
    server_private: RsaPrivateKey,
) {
    let mut server_ptls = Ptls::new(peer.split(), server_private);

    if let Err(e) = server_ptls.handshake().await {
        eprintln!("Handshake failed: {e}");
        return;
    }

    println!("Handshake successful");

    while let Ok(data) = server_ptls.receive().await {
        match std::str::from_utf8(&data) {
            Ok(message) => println!("Received: {message}"),
            Err(_) => println!("Received non-UTF8 data: {data:?}"),
        }
    }
}
