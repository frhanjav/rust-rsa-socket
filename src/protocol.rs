use crate::rsa::PublicKey;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use std::error::Error; // Keep this for general Error trait usage

// Define a type alias for our Send + Sync error box
pub type BoxedError = Box<dyn Error + Send + Sync>;

pub async fn send_public_key<W>(stream: &mut BufWriter<W>, key: &PublicKey) -> Result<(), BoxedError> // Use BoxedError
where
    W: AsyncWrite + Unpin,
{
    let key_json = serde_json::to_string(key)?;
    let key_bytes = key_json.as_bytes();
    stream.write_u32(key_bytes.len() as u32).await?;
    stream.write_all(key_bytes).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn receive_public_key<R>(stream: &mut BufReader<R>) -> Result<PublicKey, BoxedError> // Use BoxedError
where
    R: AsyncRead + Unpin,
{
    let len = stream.read_u32().await? as usize;
    let mut buffer = vec![0; len];
    stream.read_exact(&mut buffer).await?;
    let key_json = String::from_utf8(buffer)?;
    let key: PublicKey = serde_json::from_str(&key_json)?;
    Ok(key)
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedMessage {
    chunks: Vec<Vec<u8>>,
}

pub async fn send_encrypted_message<W>(
    stream: &mut BufWriter<W>,
    encrypted_chunks: &[BigUint],
) -> Result<(), BoxedError> // Use BoxedError
where
    W: AsyncWrite + Unpin,
{
    let msg_to_send = EncryptedMessage {
        chunks: encrypted_chunks.iter().map(|bu| bu.to_bytes_be()).collect(),
    };
    let serialized_msg = serde_json::to_vec(&msg_to_send)?;

    stream.write_u32(serialized_msg.len() as u32).await?;
    stream.write_all(&serialized_msg).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn receive_encrypted_message<R>(
    stream: &mut BufReader<R>,
) -> Result<Vec<BigUint>, BoxedError> // Use BoxedError
where
    R: AsyncRead + Unpin,
{
    let len = stream.read_u32().await? as usize;
    if len == 0 {
        // Consider if this should be an error or a specific signal
        // For now, returning an empty Vec which client/server interpret as connection closed.
        return Ok(Vec::new());
    }
    let mut buffer = vec![0; len];
    stream.read_exact(&mut buffer).await?; // This can return io::Error

    let deserialized_msg: EncryptedMessage = serde_json::from_slice(&buffer)?; // This can return serde_json::Error

    let biguint_chunks = deserialized_msg
        .chunks
        .into_iter()
        .map(|chunk_vec| BigUint::from_bytes_be(&chunk_vec))
        .collect();
    Ok(biguint_chunks)
}


#[allow(dead_code)]
pub async fn send_plain_text<W>(stream: &mut BufWriter<W>, text: &str) -> Result<(), BoxedError> // Use BoxedError
where
    W: AsyncWrite + Unpin,
{
    let bytes = text.as_bytes();
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn receive_plain_text<R>(stream: &mut BufReader<R>) -> Result<String, BoxedError> // Use BoxedError
where
    R: AsyncRead + Unpin,
{
    let len = stream.read_u32().await? as usize;
    if len == 0 {
        return Ok(String::new());
    }
    let mut buffer = vec![0; len];
    stream.read_exact(&mut buffer).await?;
    String::from_utf8(buffer).map_err(|e| Box::new(e) as BoxedError) // Ensure FromUtf8Error is boxed as BoxedError
}