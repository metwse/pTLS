use ptls::Ptls;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load server public key
    let server_public = RsaPublicKey::read_pkcs1_pem_file("./certs/public.pem")
        .expect("Cannot read public key");

    // Generate a new private key for the client
    let private_key = RsaPrivateKey::new(&mut thread_rng(), 512)?;

    // Connect to the server
    let mut client = tokio::net::TcpStream::connect("localhost:7811").await?;

    // Upgrade the TCP connection to a pTLS-encrypted tunnel
    let mut client_ptls = Ptls::new(client.split(), private_key);
    client_ptls.set_public_key(server_public);
    client_ptls.send_public_key().await?;

    let mut counter: i64 = 0;

    loop {
        counter += 1;
        let message = format!("Hello from client! {counter}");

        if let Err(e) = client_ptls.send(message.as_bytes()).await {
            eprintln!("Error sending message: {e}");
            break;
        }

        println!("Sent: {message}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}