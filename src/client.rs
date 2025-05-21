use crate::rsa::{generate_keypair, encrypt, decrypt}; // Removed KeyPair, not directly typed
use crate::protocol::{send_public_key, receive_public_key, send_encrypted_message, receive_encrypted_message};
use tokio::net::TcpStream;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader, BufWriter as TokioBufWriter}; // Added AsyncWriteExt
use std::error::Error;
use std::sync::Arc;
use crate::protocol::BoxedError;

const KEY_BITS: u64 = 256; 

pub async fn run_client(server_addr: &str) -> Result<(), Box<dyn Error>> {
    println!("Generating client RSA keypair ({} bits)...", KEY_BITS * 2);
    let client_keys = Arc::new(generate_keypair(KEY_BITS));
    println!("Client keypair generated. Public key: e={}, n_bits={}", client_keys.public.e, client_keys.public.n.bits());


    println!("Connecting to server at {}...", server_addr);
    // When stream is split, reader and writer are OwnedReadHalf and OwnedWriteHalf
    // These implement AsyncRead and AsyncWrite respectively.
    // Our protocol functions are now generic over W: AsyncWrite and R: AsyncRead.
    let stream = TcpStream::connect(server_addr).await?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);
    let mut writer = TokioBufWriter::new(write_half);
    println!("Connected.");

    // 1. Send client's public key to server
    println!("Sending client public key to server...");
    send_public_key(&mut writer, &client_keys.public)
      .await
      .map_err(|e: BoxedError| e as Box<dyn Error>)?;

    println!("Client public key sent.");

    // 2. Receive server's public key
    println!("Waiting for server public key...");
    let server_public_key = Arc::new(
      receive_public_key(&mut reader)
          .await
          .map_err(|e: BoxedError| e as Box<dyn Error>)?, // Explicit conversion
  );

    println!("Client 2 public key received: e={}, n_bits={}", server_public_key.e, server_public_key.n.bits());

    let reader_client_keys = Arc::clone(&client_keys);
    // let reader_server_public_key = Arc::clone(&server_public_key); // Not used in read_task
    
    let mut read_task = tokio::spawn(async move {
        loop {
            match receive_encrypted_message(&mut reader).await {
                Ok(encrypted_chunks) => {
                    if encrypted_chunks.is_empty() {
                        println!("\nClient 2 closed the connection or sent empty message signal.");
                        break;
                    }
                    match decrypt(&encrypted_chunks, &reader_client_keys.private) {
                        Ok(decrypted_bytes) => {
                            let message = String::from_utf8_lossy(&decrypted_bytes);
                            // Ensure prompt is not overwritten by async message
                            tokio::task::yield_now().await; // Give pending I/O (like prompt writing) a chance
                            println!("\rClient 2: {}                                ", message); // Clear line
                            print!("You: ");
                            io::stdout().flush().await.unwrap_or_default();
                        }
                        Err(e) => {
                            eprintln!("\nError decrypting server message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    if e.downcast_ref::<io::Error>().map_or(false, |io_err| io_err.kind() == io::ErrorKind::UnexpectedEof) {
                        println!("\nClient 2 disconnected.");
                    } else if e.downcast_ref::<io::Error>().map_or(false, |io_err| io_err.kind() == io::ErrorKind::BrokenPipe) {
                         println!("\nConnection to server lost (broken pipe).");
                    }
                    else {
                        eprintln!("\nError receiving message from server: {}", e);
                    }
                    break;
                }
            }
        }
    });

    let mut stdin_reader = TokioBufReader::new(io::stdin());
    loop {
        print!("You: ");
        io::stdout().flush().await?; 

        let mut line = String::new();
        // Check if the read_task (server connection) is finished
        if read_task.is_finished() {
            println!("Connection to server closed. Exiting input loop.");
            break;
        }

        tokio::select! {
            biased; // Prefer checking read_task completion
            _ = &mut read_task => { // Note: &mut read_task makes it reusable in select!
                println!("\nClient 2 connection handler finished. Exiting.");
                break;
            }
            result = stdin_reader.read_line(&mut line) => {
                match result {
                    Ok(0) => { 
                        println!("Exiting...");
                        break;
                    }
                    Ok(_) => {
                        let message_to_send = line.trim();
                        if message_to_send.is_empty() { continue; }
                        if message_to_send.eq_ignore_ascii_case("exit") {
                            println!("Exiting...");
                            break;
                        }

                        let encrypted_output = encrypt(message_to_send.as_bytes(), &server_public_key);
                        if let Err(e) = send_encrypted_message(&mut writer, &encrypted_output).await {
                            eprintln!("Failed to send message: {}", e);
                            break; 
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from stdin: {}", e);
                        break;
                    }
                }
            }
        }
    }
    
    // Ensure read_task is properly handled on exit.
    // If we break from the loop, read_task might still be running.
    // We can try to abort it or just let it finish.
    // If main exits, tokio runtime shuts down tasks.
    if !read_task.is_finished() {
        read_task.abort(); // Explicitly stop it if not done.
    }

    Ok(())
}