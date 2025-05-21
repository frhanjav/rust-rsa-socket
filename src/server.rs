use crate::rsa::{generate_keypair, encrypt, decrypt, KeyPair}; // Removed PublicKey, not directly typed by var
use crate::protocol::{send_public_key, receive_public_key, send_encrypted_message, receive_encrypted_message};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader, BufWriter as TokioBufWriter}; // Added AsyncWriteExt
use std::error::Error;
use std::sync::Arc;
use crate::protocol::BoxedError;

const KEY_BITS: u64 = 256; 

pub async fn run_server(addr: &str) -> Result<(), Box<dyn Error>> {
    println!("Generating server RSA keypair ({} bits)...", KEY_BITS * 2);
    let server_keys = Arc::new(generate_keypair(KEY_BITS));
    println!("Client 2 keypair generated. Public key: e={}, n_bits={}", server_keys.public.e, server_keys.public.n.bits());

    let listener = TcpListener::bind(addr).await?;
    println!("Client 2 listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                println!("Accepted connection from: {}", client_addr);
                let server_keys_clone = Arc::clone(&server_keys);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, server_keys_clone, client_addr.to_string()).await {
                        eprintln!("Error handling client {}: {}", client_addr, e);
                    }
                    println!("Connection with {} closed.", client_addr);
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_client(stream: TcpStream, server_keys: Arc<KeyPair>, client_id: String) -> Result<(), Box<dyn Error>> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);
    let mut writer = TokioBufWriter::new(write_half);

    println!("[{}] Waiting for client public key...", client_id);
    let client_public_key = Arc::new(
      receive_public_key(&mut reader)
          .await
          .map_err(|e: BoxedError| e as Box<dyn Error>)?, // Explicit conversion
    );

    println!("[{}] Client public key received: e={}, n_bits={}", client_id, client_public_key.e, client_public_key.n.bits());

    println!("[{}] Sending server public key to client...", client_id);
    send_public_key(&mut writer, &server_keys.public)
      .await
      .map_err(|e: BoxedError| e as Box<dyn Error>)?;

    println!("[{}] Client 2 public key sent.", client_id);

    let server_keys_reader_clone = Arc::clone(&server_keys);
    let client_public_key_sender_clone = Arc::clone(&client_public_key);
    let client_id_clone = client_id.clone();

    let mut read_task = tokio::spawn(async move { // make it mutable for select!
        loop {
            match receive_encrypted_message(&mut reader).await {
                Ok(encrypted_chunks) => {
                    if encrypted_chunks.is_empty() {
                        println!("\n[{}] Client closed the connection or sent empty message signal.", client_id_clone);
                        break;
                    }
                    match decrypt(&encrypted_chunks, &server_keys_reader_clone.private) {
                        Ok(decrypted_bytes) => {
                            let message = String::from_utf8_lossy(&decrypted_bytes);
                            tokio::task::yield_now().await;
                            println!("\r[{}] Client: {}                                  ", client_id_clone, message); // Clear line
                            print!("[{}] Client 2 Response: ", client_id_clone); 
                            io::stdout().flush().await.unwrap_or_default();
                        }
                        Err(e) => {
                            eprintln!("\n[{}] Error decrypting client message: {}", client_id_clone, e);
                        }
                    }
                }
                Err(e) => {
                     if e.downcast_ref::<io::Error>().map_or(false, |io_err| io_err.kind() == io::ErrorKind::UnexpectedEof) {
                        println!("\n[{}] Client disconnected.", client_id_clone);
                    } else if e.downcast_ref::<io::Error>().map_or(false, |io_err| io_err.kind() == io::ErrorKind::BrokenPipe) {
                         println!("\n[{}] Connection to client lost (broken pipe).", client_id_clone);
                    }
                    else {
                        eprintln!("\n[{}] Error receiving message from client: {}", client_id_clone, e);
                    }
                    break;
                }
            }
        }
    });

    let mut stdin_reader = TokioBufReader::new(io::stdin());
    loop {
        print!("[{}] Client 2 Response: ", client_id);
        io::stdout().flush().await?;
        
        let mut line = String::new();

        tokio::select! {
            biased;
            _ = &mut read_task => {
                println!("\n[{}] Client connection handler finished. Stopping server input for this client.", client_id);
                break;
            }
            result = stdin_reader.read_line(&mut line) => {
                match result {
                    Ok(0) => { 
                        println!("[{}] Exiting server message loop for this client (stdin EOF)...", client_id);
                        break;
                    }
                    Ok(_) => {
                        let message_to_send = line.trim();
                        if message_to_send.is_empty() { continue; }
                        if message_to_send.eq_ignore_ascii_case("exit") {
                            println!("[{}] Exiting server message loop for this client (typed exit)...", client_id);
                            break;
                        }

                        let encrypted_output = encrypt(message_to_send.as_bytes(), &client_public_key_sender_clone);
                        if let Err(e) = send_encrypted_message(&mut writer, &encrypted_output).await {
                            eprintln!("[{}] Failed to send message to client: {}", client_id, e);
                            break; 
                        }
                    }
                    Err(e) => {
                        eprintln!("[{}] Error reading from server stdin: {}", client_id, e);
                        break;
                    }
                }
            }
        }
    }

    if !read_task.is_finished() {
        read_task.abort();
    }
    Ok(())
}