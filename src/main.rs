use std::env;
use std::error::Error;

mod rsa;
mod protocol;
mod client;
mod server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: rsa-chat <server|client> [address:port]");
        eprintln!("Example (server): rsa-chat server 127.0.0.1:8080");
        eprintln!("Example (client): rsa-chat client 127.0.0.1:8080");
        return Ok(());
    }

    let mode = &args[1];
    let address = if args.len() > 2 { &args[2] } else { "127.0.0.1:8080" };

    match mode.as_str() {
        "server" => {
            println!("Starting server mode...");
            server::run_server(address).await?;
        }
        "client" => {
            println!("Starting client mode...");
            client::run_client(address).await?;
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'.");
        }
    }

    Ok(())
}