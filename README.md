# RSA Encrypted Chat Application - Documentation

## 1. Overview

This project implements a client-server chat application where all communication is encrypted using RSA. The RSA algorithm itself is implemented from scratch for educational purposes, avoiding reliance on external cryptography libraries for the core RSA logic. The application uses asynchronous sockets (via Tokio) for network communication.

The primary goal is to demonstrate the mechanics of RSA encryption/decryption and its application in a networked environment. Each participant (client and server) generates their own RSA key pair. They exchange public keys, and then all subsequent messages are encrypted with the recipient's public key, ensuring only the recipient (holder of the corresponding private key) can decrypt and read the message.

---

**IMPORTANT SECURITY DISCLAIMER:**

This implementation of RSA is for **EDUCATIONAL PURPOSES ONLY**. It is a "textbook" RSA implementation and **LACKS CRUCIAL SECURITY FEATURES** found in production-grade cryptographic libraries. Specifically:
*   **No Padding Scheme:** It does not use standard padding schemes like OAEP or PKCS#1 v1.5. Textbook RSA without padding is vulnerable to various attacks (e.g., chosen-ciphertext attacks, attacks based on message structure).
*   **Potential Timing Vulnerabilities:** Operations like modular exponentiation might not be constant-time, potentially leaking information through timing side channels.
*   **Basic Primality Testing:** While Miller-Rabin is a good probabilistic test, production libraries use more rigorous checks and specific prime generation techniques (e.g., provable primes or strong primes).
*   **Random Number Generation:** Relies on `rand::thread_rng()`. For cryptographic purposes, a cryptographically secure pseudo-random number generator (CSPRNG) with proper seeding is paramount.
*   **Key Management:** This example simplifies key exchange. Real-world scenarios require robust key management, including certificate authorities or PGP-like trust models to prevent man-in-the-middle attacks during public key exchange.

**DO NOT USE THIS CODE FOR SECURING SENSITIVE INFORMATION IN A REAL-WORLD APPLICATION.**
Always use well-vetted, standard cryptographic libraries like `RustCrypto`, OpenSSL, or your platform's native crypto APIs for production systems.

---

## 2. Project Structure

```
rsa-chat/
├── Cargo.toml # Project dependencies and metadata
└── src/
├── rsa.rs # Core RSA algorithm implementation (key generation, encrypt, decrypt)
├── protocol.rs # Defines message structures and (de)serialization for network
├── client.rs # Client-side application logic
├── server.rs # Server-side application logic
└── main.rs # Main entry point, parses arguments and starts client/server
```

## 3. Core Components

### 3.1. `rsa.rs` - RSA Cryptography

This module contains the from-scratch implementation of the RSA algorithm.

**Key Structs:**
*   `PublicKey { e: BigUint, n: BigUint }`: Represents the public part of an RSA key.
    *   `e`: Public exponent (commonly 65537).
    *   `n`: Modulus (product of two large primes p and q).
*   `PrivateKey { d: BigUint, n: BigUint }`: Represents the private part of an RSA key.
    *   `d`: Private exponent (modular multiplicative inverse of `e` modulo `phi_n`).
    *   `n`: Modulus (same as in the public key).
*   `KeyPair { public: PublicKey, private: PrivateKey }`: A container for a public-private key pair.

**Key Functions:**
*   `generate_keypair(bits: u64) -> KeyPair`:
    1.  Generates two distinct large prime numbers, `p` and `q`, each of approximately `bits` length using `generate_large_prime`.
    2.  Computes the modulus `n = p * q`.
    3.  Computes Euler's totient function `phi_n = (p-1) * (q-1)`.
    4.  Selects a public exponent `e` (hardcoded to 65537). It should be coprime to `phi_n`.
    5.  Computes the private exponent `d` such that `d * e ≡ 1 (mod phi_n)` using `mod_inverse`.
    6.  Returns the `KeyPair`.
*   `encrypt(message: &[u8], public_key: &PublicKey) -> Vec<BigUint>`:
    1.  **Chunking:** The input `message` (byte slice) is too large to be encrypted as a single number if it's numerically greater than `n-1`.
        *   It calculates `max_chunk_size` based on the bit size of `n`. A chunk of bytes must form a number smaller than `n`. Typically, this is `(n.bits() / 8) - 1` bytes or similar.
        *   The message is split into chunks of this `max_chunk_size`.
    2.  For each chunk:
        *   Converts the byte chunk to a `BigUint` (`m`).
        *   Computes the ciphertext `c = m^e mod n`.
    3.  Returns a `Vec<BigUint>`, where each `BigUint` is an encrypted chunk.
*   `decrypt(ciphertext_chunks: &[BigUint], private_key: &PrivateKey) -> Result<Vec<u8>, String>`:
    1.  For each encrypted `BigUint` chunk (`c`) in `ciphertext_chunks`:
        *   Computes the original message chunk `m = c^d mod n`.
        *   Converts `m` back to bytes.
    2.  Concatenates all decrypted byte chunks to form the original message.
    3.  Returns the decrypted message as `Vec<u8>`.

**Helper Functions:**
*   `is_prime(n: &BigUint, k: usize) -> bool`: Implements the Miller-Rabin probabilistic primality test with `k` iterations.
*   `generate_large_prime(bits: u64) -> BigUint`: Generates a random odd number of `bits` length and tests it for primality using `is_prime` until a prime is found.
*   `extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt)`: Implements the Extended Euclidean Algorithm to find `x` and `y` such that `ax + by = gcd(a, b)`. Used by `mod_inverse`. Note the use of `BigInt` for intermediate potentially negative coefficients.
*   `mod_inverse(e: &BigUint, phi_n: &BigUint) -> Option<BigUint>`: Calculates the modular multiplicative inverse of `e` modulo `phi_n`. This is crucial for finding `d`.

**Constants:**
*   `MILLER_RABIN_ITERATIONS`: Number of iterations for the Miller-Rabin test (e.g., 20). Higher means lower probability of a composite being falsely identified as prime.
*   `KEY_BITS` (defined in `client.rs` and `server.rs`): Determines the bit length of `p` and `q`. The resulting RSA key modulus `n` will have approximately `2 * KEY_BITS` length. For testing, smaller values (e.g., 256 for a 512-bit RSA key) are used for speed.

### 3.2. `protocol.rs` - Network Protocol & Serialization

This module handles the serialization of keys and encrypted messages for transmission over the network, as well as defining a simple framing protocol.

**Error Handling:**
*   `pub type BoxedError = Box<dyn Error + Send + Sync>;`
    *   A type alias for boxed trait objects representing errors. It's crucial that these errors are `Send + Sync` because they might be propagated across threads in the `tokio::spawn`ed tasks.

**Key/Message Exchange Functions:**
All send/receive functions are generic over `AsyncWrite + Unpin` and `AsyncRead + Unpin` to work with Tokio's split stream halves. They use a simple length-prefix framing: a `u32` indicating the length of the subsequent data is sent before the data itself.

*   `send_public_key<W>(stream: &mut BufWriter<W>, key: &PublicKey) -> Result<(), BoxedError>`:
    1.  Serializes the `PublicKey` struct into a JSON string.
    2.  Sends the length of the JSON string as a `u32`.
    3.  Sends the JSON string bytes.
*   `receive_public_key<R>(stream: &mut BufReader<R>) -> Result<PublicKey, BoxedError>`:
    1.  Reads the `u32` length.
    2.  Reads that many bytes into a buffer.
    3.  Deserializes the JSON string from the buffer back into a `PublicKey` struct.
*   `send_encrypted_message<W>(stream: &mut BufWriter<W>, encrypted_chunks: &[BigUint]) -> Result<(), BoxedError>`:
    1.  Converts each `BigUint` in `encrypted_chunks` to its big-endian byte representation (`Vec<u8>`).
    2.  Wraps this `Vec<Vec<u8>>` in an `EncryptedMessage` struct.
    3.  Serializes the `EncryptedMessage` struct into JSON bytes.
    4.  Sends the length of the JSON bytes as a `u32`.
    5.  Sends the JSON bytes.
*   `receive_encrypted_message<R>(stream: &mut BufReader<R>) -> Result<Vec<BigUint>, BoxedError>`:
    1.  Reads the `u32` length.
    2.  Reads JSON bytes.
    3.  Deserializes into `EncryptedMessage`.
    4.  Converts each inner `Vec<u8>` back to a `BigUint`.
    5.  Returns the `Vec<BigUint>`.

**Serialization Choice:**
*   Public keys and the `EncryptedMessage` wrapper are serialized using `serde_json`. JSON is human-readable and easy to work with for structs. `BigUint` itself has `serde` support enabled via a feature flag in `Cargo.toml`, allowing it to be part of serializable structs (though in `EncryptedMessage`, we convert `BigUint` to `Vec<u8>` first before JSON serialization of the wrapper).

### 3.3. `client.rs` - Client Application

Handles the client-side logic of the chat.

**Key Operations:**
1.  **Initialization:**
    *   Generates its own RSA `KeyPair` using `rsa::generate_keypair(KEY_BITS)`.
2.  **Connection:**
    *   Connects to the server address using `TcpStream::connect`.
    *   Splits the `TcpStream` into an `OwnedReadHalf` and `OwnedWriteHalf`, wrapped in `TokioBufReader` and `TokioBufWriter` respectively.
3.  **Key Exchange:**
    *   Sends its `PublicKey` to the server using `protocol::send_public_key`.
    *   Receives the server's `PublicKey` using `protocol::receive_public_key`.
4.  **Concurrent Communication:**
    *   **Receiving Messages:** A `tokio::spawn`ed task continuously listens for incoming encrypted messages from the server using `protocol::receive_encrypted_message`.
        *   Upon receiving chunks, it decrypts them using its own `PrivateKey` via `rsa::decrypt`.
        *   Prints the decrypted message to the console.
        *   Handles server disconnection or errors.
    *   **Sending Messages:** The main loop reads lines from `stdin`.
        *   For each line, it encrypts the message using the *server's* `PublicKey` via `rsa::encrypt`.
        *   Sends the encrypted chunks to the server using `protocol::send_encrypted_message`.
        *   The `tokio::select!` macro is used to concurrently await user input and monitor the status of the receiving task (to exit if the server disconnects).
5.  **Shutdown:**
    *   Typing "exit" or encountering EOF (Ctrl+D) on stdin will terminate the client.
    *   If the server disconnects, the receiving task will end, which will also lead to the client shutting down its input loop.

### 3.4. `server.rs` - Server Application

Handles the server-side logic, listening for multiple clients.

**Key Operations:**
1.  **Initialization:**
    *   Generates its own RSA `KeyPair` using `rsa::generate_keypair(KEY_BITS)`.
2.  **Listening:**
    *   Binds a `TcpListener` to the specified address and port.
    *   Enters a loop, accepting incoming client connections via `listener.accept()`.
3.  **Client Handling:**
    *   For each accepted `TcpStream`:
        *   A new asynchronous task is `tokio::spawn`ed to handle this client independently using the `handle_client` function.
        *   The server's `KeyPair` (specifically, an `Arc` to it) is passed to `handle_client`.
4.  **`handle_client` Function:** This function mirrors the client's communication logic but from the server's perspective for a single connected client.
    *   **Key Exchange:**
        *   Receives the client's `PublicKey` using `protocol::receive_public_key`.
        *   Sends its own `PublicKey` to the client using `protocol::send_public_key`.
    *   **Concurrent Communication:**
        *   **Receiving Messages:** A `tokio::spawn`ed sub-task continuously listens for incoming encrypted messages from this specific client.
            *   Decrypts them using the server's `PrivateKey`.
            *   Prints the decrypted message (prefixed with client ID).
        *   **Sending Messages:** The main loop within `handle_client` reads lines from the server's `stdin` (allowing the server admin to type responses).
            *   Encrypts the response using *that specific client's* `PublicKey`.
            *   Sends the encrypted response to that client.
            *   `tokio::select!` is used similarly to the client.
5.  **Multi-Client:** The server can handle multiple clients concurrently because each client connection is managed in its own Tokio task.

### 3.5. `main.rs` - Entry Point

*   Parses command-line arguments to determine whether to run in "server" or "client" mode.
*   Takes an optional address:port argument (defaults to "127.0.0.1:8080").
*   Calls `server::run_server(address).await?` or `client::run_client(address).await?` accordingly.
*   The `#[tokio::main]` macro sets up the Tokio runtime.

## 4. Communication Protocol Summary

1.  **Client Connects to Server.**
2.  **Client Key Exchange:**
    *   Client sends its `PublicKey` to Server.
    *   Server receives Client's `PublicKey`.
3.  **Server Key Exchange:**
    *   Server sends its `PublicKey` to Client.
    *   Client receives Server's `PublicKey`.
4.  **Encrypted Chat:**
    *   **Client to Server:** Client encrypts message with Server's `PublicKey` and sends. Server decrypts with its `PrivateKey`.
    *   **Server to Client:** Server encrypts message with Client's `PublicKey` and sends. Client decrypts with its `PrivateKey`.
5.  **Message Framing:** All network messages (serialized keys or encrypted data) are prefixed with a `u32` indicating the byte length of the upcoming data.

## 5. How to Build and Run

1.  **Prerequisites:**
    *   Rust programming language and Cargo (Rust's package manager). Install from [rustup.rs](https://rustup.rs/).
2.  **Build:**
    *   Navigate to the project root directory (`rsa-chat/`).
    *   Run: `cargo build` (for debug build) or `cargo build --release` (for optimized build).
3.  **Run Server:**
    *   Open a terminal.
    *   Navigate to the project root.
    *   Run: `cargo run server` (uses default address 127.0.0.1:8080)
    *   Or: `cargo run server <ip_address>:<port>` (e.g., `cargo run server 0.0.0.0:12345`)
    *   The server will print that it's generating keys (this might take a few seconds) and then indicate it's listening.
4.  **Run Client:**
    *   Open another terminal.
    *   Navigate to the project root.
    *   Run: `cargo run client` (connects to default 127.0.0.1:8080)
    *   Or: `cargo run client <server_ip_address>:<server_port>` (e.g., `cargo run client 127.0.0.1:12345`)
    *   The client will also generate keys and then attempt to connect.
5.  **Chat:**
    *   Once connected and keys are exchanged, you can type messages in the client terminal.
    *   The server admin can type messages in the server terminal to respond to the connected client.
    *   Type "exit" in either client or server input prompt to close that side of the connection for that specific chat. The server itself will continue running to accept new clients.

## 6. Dependencies (`Cargo.toml`)

*   `num-bigint = { version = "0.4", features = ["rand", "serde"] }`: For arbitrary-precision integer arithmetic, essential for RSA.
    *   `rand` feature: For generating random `BigUint`s (used in prime generation).
    *   `serde` feature: For allowing `BigUint` to be (de)serialized if it's part of a struct derived with Serde (though we manually convert to `Vec<u8>` for `EncryptedMessage`).
*   `num-traits = "0.2"`: Provides traits for numeric types (like `One`, `Zero`).
*   `rand = "0.8"`: For random number generation (used in prime finding).
*   `serde = { version = "1.0", features = ["derive"] }`: For serializing and deserializing data structures (like `PublicKey` and `EncryptedMessage`).
    *   `derive` feature: To automatically generate (de)serialization code for structs.
*   `serde_json = "1.0"`: For JSON serialization format.
*   `tokio = { version = "1", features = ["full"] }`: Asynchronous runtime for network I/O and concurrent tasks.
    *   `full` feature: Enables all Tokio features, including `net` (sockets), `io`, `macros`, `rt` (runtime).
*   `hex = "0.4"`: For converting byte slices to hexadecimal strings (used for debugging/printing parts of large numbers).

## 7. Potential Improvements / Further Development

*   **Implement Secure Padding:** Add OAEP (Optimal Asymmetric Encryption Padding) or PKCS#1 v1.5 padding to the RSA encryption/decryption to mitigate attacks against textbook RSA.
*   **Hybrid Encryption:** For long messages or frequent communication, RSA is slow. A common practice is to use RSA to encrypt a symmetric key (e.g., AES), and then use the symmetric key to encrypt the actual data. This is hybrid encryption.
*   **More Robust Key Exchange:** Implement a secure key exchange mechanism to prevent Man-in-the-Middle (MitM) attacks (e.g., Diffie-Hellman for establishing a shared secret, or using certificates).
*   **Error Handling:** More granular error types instead of `Box<dyn Error>` could improve debugging and program control flow.
*   **User Interface:** A graphical user interface (GUI) or a more advanced terminal user interface (TUI) would improve usability.
*   **Persistent Keys:** Allow users to save and load their RSA key pairs instead of generating new ones each time. Secure storage of private keys is critical.
*   **Server-Side Multi-User Management:** More sophisticated handling of multiple users on the server, including broadcasting messages or private user-to-user chats if desired.
*   **Constant-Time Operations:** Investigate and implement cryptographic operations (especially modular exponentiation) in constant time to prevent timing side-channel attacks. This is very complex.
*   **Configuration File:** For server address, port, key sizes, etc.
Use code with caution.


rsa-chat/
├── Cargo.toml # Project dependencies and metadata
└── src/
├── rsa.rs # Core RSA algorithm implementation (key generation, encrypt, decrypt)
├── protocol.rs # Defines message structures and (de)serialization for network
├── client.rs # Client-side application logic
├── server.rs # Server-side application logic
└── main.rs # Main entry point, parses arguments and starts client/server

## 3. Core Components

### 3.1. `rsa.rs` - RSA Cryptography

This module contains the from-scratch implementation of the RSA algorithm.

**Key Structs:**
*   `PublicKey { e: BigUint, n: BigUint }`: Represents the public part of an RSA key.
    *   `e`: Public exponent (commonly 65537).
    *   `n`: Modulus (product of two large primes p and q).
*   `PrivateKey { d: BigUint, n: BigUint }`: Represents the private part of an RSA key.
    *   `d`: Private exponent (modular multiplicative inverse of `e` modulo `phi_n`).
    *   `n`: Modulus (same as in the public key).
*   `KeyPair { public: PublicKey, private: PrivateKey }`: A container for a public-private key pair.

**Key Functions:**
*   `generate_keypair(bits: u64) -> KeyPair`:
    1.  Generates two distinct large prime numbers, `p` and `q`, each of approximately `bits` length using `generate_large_prime`.
    2.  Computes the modulus `n = p * q`.
    3.  Computes Euler's totient function `phi_n = (p-1) * (q-1)`.
    4.  Selects a public exponent `e` (hardcoded to 65537). It should be coprime to `phi_n`.
    5.  Computes the private exponent `d` such that `d * e ≡ 1 (mod phi_n)` using `mod_inverse`.
    6.  Returns the `KeyPair`.
*   `encrypt(message: &[u8], public_key: &PublicKey) -> Vec<BigUint>`:
    1.  **Chunking:** The input `message` (byte slice) is too large to be encrypted as a single number if it's numerically greater than `n-1`.
        *   It calculates `max_chunk_size` based on the bit size of `n`. A chunk of bytes must form a number smaller than `n`. Typically, this is `(n.bits() / 8) - 1` bytes or similar.
        *   The message is split into chunks of this `max_chunk_size`.
    2.  For each chunk:
        *   Converts the byte chunk to a `BigUint` (`m`).
        *   Computes the ciphertext `c = m^e mod n`.
    3.  Returns a `Vec<BigUint>`, where each `BigUint` is an encrypted chunk.
*   `decrypt(ciphertext_chunks: &[BigUint], private_key: &PrivateKey) -> Result<Vec<u8>, String>`:
    1.  For each encrypted `BigUint` chunk (`c`) in `ciphertext_chunks`:
        *   Computes the original message chunk `m = c^d mod n`.
        *   Converts `m` back to bytes.
    2.  Concatenates all decrypted byte chunks to form the original message.
    3.  Returns the decrypted message as `Vec<u8>`.

**Helper Functions:**
*   `is_prime(n: &BigUint, k: usize) -> bool`: Implements the Miller-Rabin probabilistic primality test with `k` iterations.
*   `generate_large_prime(bits: u64) -> BigUint`: Generates a random odd number of `bits` length and tests it for primality using `is_prime` until a prime is found.
*   `extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt)`: Implements the Extended Euclidean Algorithm to find `x` and `y` such that `ax + by = gcd(a, b)`. Used by `mod_inverse`. Note the use of `BigInt` for intermediate potentially negative coefficients.
*   `mod_inverse(e: &BigUint, phi_n: &BigUint) -> Option<BigUint>`: Calculates the modular multiplicative inverse of `e` modulo `phi_n`. This is crucial for finding `d`.

**Constants:**
*   `MILLER_RABIN_ITERATIONS`: Number of iterations for the Miller-Rabin test (e.g., 20). Higher means lower probability of a composite being falsely identified as prime.
*   `KEY_BITS` (defined in `client.rs` and `server.rs`): Determines the bit length of `p` and `q`. The resulting RSA key modulus `n` will have approximately `2 * KEY_BITS` length. For testing, smaller values (e.g., 256 for a 512-bit RSA key) are used for speed.

### 3.2. `protocol.rs` - Network Protocol & Serialization

This module handles the serialization of keys and encrypted messages for transmission over the network, as well as defining a simple framing protocol.

**Error Handling:**
*   `pub type BoxedError = Box<dyn Error + Send + Sync>;`
    *   A type alias for boxed trait objects representing errors. It's crucial that these errors are `Send + Sync` because they might be propagated across threads in the `tokio::spawn`ed tasks.

**Key/Message Exchange Functions:**
All send/receive functions are generic over `AsyncWrite + Unpin` and `AsyncRead + Unpin` to work with Tokio's split stream halves. They use a simple length-prefix framing: a `u32` indicating the length of the subsequent data is sent before the data itself.

*   `send_public_key<W>(stream: &mut BufWriter<W>, key: &PublicKey) -> Result<(), BoxedError>`:
    1.  Serializes the `PublicKey` struct into a JSON string.
    2.  Sends the length of the JSON string as a `u32`.
    3.  Sends the JSON string bytes.
*   `receive_public_key<R>(stream: &mut BufReader<R>) -> Result<PublicKey, BoxedError>`:
    1.  Reads the `u32` length.
    2.  Reads that many bytes into a buffer.
    3.  Deserializes the JSON string from the buffer back into a `PublicKey` struct.
*   `send_encrypted_message<W>(stream: &mut BufWriter<W>, encrypted_chunks: &[BigUint]) -> Result<(), BoxedError>`:
    1.  Converts each `BigUint` in `encrypted_chunks` to its big-endian byte representation (`Vec<u8>`).
    2.  Wraps this `Vec<Vec<u8>>` in an `EncryptedMessage` struct.
    3.  Serializes the `EncryptedMessage` struct into JSON bytes.
    4.  Sends the length of the JSON bytes as a `u32`.
    5.  Sends the JSON bytes.
*   `receive_encrypted_message<R>(stream: &mut BufReader<R>) -> Result<Vec<BigUint>, BoxedError>`:
    1.  Reads the `u32` length.
    2.  Reads JSON bytes.
    3.  Deserializes into `EncryptedMessage`.
    4.  Converts each inner `Vec<u8>` back to a `BigUint`.
    5.  Returns the `Vec<BigUint>`.

**Serialization Choice:**
*   Public keys and the `EncryptedMessage` wrapper are serialized using `serde_json`. JSON is human-readable and easy to work with for structs. `BigUint` itself has `serde` support enabled via a feature flag in `Cargo.toml`, allowing it to be part of serializable structs (though in `EncryptedMessage`, we convert `BigUint` to `Vec<u8>` first before JSON serialization of the wrapper).

### 3.3. `client.rs` - Client Application

Handles the client-side logic of the chat.

**Key Operations:**
1.  **Initialization:**
    *   Generates its own RSA `KeyPair` using `rsa::generate_keypair(KEY_BITS)`.
2.  **Connection:**
    *   Connects to the server address using `TcpStream::connect`.
    *   Splits the `TcpStream` into an `OwnedReadHalf` and `OwnedWriteHalf`, wrapped in `TokioBufReader` and `TokioBufWriter` respectively.
3.  **Key Exchange:**
    *   Sends its `PublicKey` to the server using `protocol::send_public_key`.
    *   Receives the server's `PublicKey` using `protocol::receive_public_key`.
4.  **Concurrent Communication:**
    *   **Receiving Messages:** A `tokio::spawn`ed task continuously listens for incoming encrypted messages from the server using `protocol::receive_encrypted_message`.
        *   Upon receiving chunks, it decrypts them using its own `PrivateKey` via `rsa::decrypt`.
        *   Prints the decrypted message to the console.
        *   Handles server disconnection or errors.
    *   **Sending Messages:** The main loop reads lines from `stdin`.
        *   For each line, it encrypts the message using the *server's* `PublicKey` via `rsa::encrypt`.
        *   Sends the encrypted chunks to the server using `protocol::send_encrypted_message`.
        *   The `tokio::select!` macro is used to concurrently await user input and monitor the status of the receiving task (to exit if the server disconnects).
5.  **Shutdown:**
    *   Typing "exit" or encountering EOF (Ctrl+D) on stdin will terminate the client.
    *   If the server disconnects, the receiving task will end, which will also lead to the client shutting down its input loop.

### 3.4. `server.rs` - Server Application

Handles the server-side logic, listening for multiple clients.

**Key Operations:**
1.  **Initialization:**
    *   Generates its own RSA `KeyPair` using `rsa::generate_keypair(KEY_BITS)`.
2.  **Listening:**
    *   Binds a `TcpListener` to the specified address and port.
    *   Enters a loop, accepting incoming client connections via `listener.accept()`.
3.  **Client Handling:**
    *   For each accepted `TcpStream`:
        *   A new asynchronous task is `tokio::spawn`ed to handle this client independently using the `handle_client` function.
        *   The server's `KeyPair` (specifically, an `Arc` to it) is passed to `handle_client`.
4.  **`handle_client` Function:** This function mirrors the client's communication logic but from the server's perspective for a single connected client.
    *   **Key Exchange:**
        *   Receives the client's `PublicKey` using `protocol::receive_public_key`.
        *   Sends its own `PublicKey` to the client using `protocol::send_public_key`.
    *   **Concurrent Communication:**
        *   **Receiving Messages:** A `tokio::spawn`ed sub-task continuously listens for incoming encrypted messages from this specific client.
            *   Decrypts them using the server's `PrivateKey`.
            *   Prints the decrypted message (prefixed with client ID).
        *   **Sending Messages:** The main loop within `handle_client` reads lines from the server's `stdin` (allowing the server admin to type responses).
            *   Encrypts the response using *that specific client's* `PublicKey`.
            *   Sends the encrypted response to that client.
            *   `tokio::select!` is used similarly to the client.
5.  **Multi-Client:** The server can handle multiple clients concurrently because each client connection is managed in its own Tokio task.

### 3.5. `main.rs` - Entry Point

*   Parses command-line arguments to determine whether to run in "server" or "client" mode.
*   Takes an optional address:port argument (defaults to "127.0.0.1:8080").
*   Calls `server::run_server(address).await?` or `client::run_client(address).await?` accordingly.
*   The `#[tokio::main]` macro sets up the Tokio runtime.

## 4. Communication Protocol Summary

1.  **Client Connects to Server.**
2.  **Client Key Exchange:**
    *   Client sends its `PublicKey` to Server.
    *   Server receives Client's `PublicKey`.
3.  **Server Key Exchange:**
    *   Server sends its `PublicKey` to Client.
    *   Client receives Server's `PublicKey`.
4.  **Encrypted Chat:**
    *   **Client to Server:** Client encrypts message with Server's `PublicKey` and sends. Server decrypts with its `PrivateKey`.
    *   **Server to Client:** Server encrypts message with Client's `PublicKey` and sends. Client decrypts with its `PrivateKey`.
5.  **Message Framing:** All network messages (serialized keys or encrypted data) are prefixed with a `u32` indicating the byte length of the upcoming data.

## 5. How to Build and Run

1.  **Prerequisites:**
    *   Rust programming language and Cargo (Rust's package manager). Install from [rustup.rs](https://rustup.rs/).
2.  **Build:**
    *   Navigate to the project root directory (`rsa-chat/`).
    *   Run: `cargo build` (for debug build) or `cargo build --release` (for optimized build).
3.  **Run Server:**
    *   Open a terminal.
    *   Navigate to the project root.
    *   Run: `cargo run server` (uses default address 127.0.0.1:8080)
    *   Or: `cargo run server <ip_address>:<port>` (e.g., `cargo run server 0.0.0.0:12345`)
    *   The server will print that it's generating keys (this might take a few seconds) and then indicate it's listening.
4.  **Run Client:**
    *   Open another terminal.
    *   Navigate to the project root.
    *   Run: `cargo run client` (connects to default 127.0.0.1:8080)
    *   Or: `cargo run client <server_ip_address>:<server_port>` (e.g., `cargo run client 127.0.0.1:12345`)
    *   The client will also generate keys and then attempt to connect.
5.  **Chat:**
    *   Once connected and keys are exchanged, you can type messages in the client terminal.
    *   The server admin can type messages in the server terminal to respond to the connected client.
    *   Type "exit" in either client or server input prompt to close that side of the connection for that specific chat. The server itself will continue running to accept new clients.

## 6. Dependencies (`Cargo.toml`)

*   `num-bigint = { version = "0.4", features = ["rand", "serde"] }`: For arbitrary-precision integer arithmetic, essential for RSA.
    *   `rand` feature: For generating random `BigUint`s (used in prime generation).
    *   `serde` feature: For allowing `BigUint` to be (de)serialized if it's part of a struct derived with Serde (though we manually convert to `Vec<u8>` for `EncryptedMessage`).
*   `num-traits = "0.2"`: Provides traits for numeric types (like `One`, `Zero`).
*   `rand = "0.8"`: For random number generation (used in prime finding).
*   `serde = { version = "1.0", features = ["derive"] }`: For serializing and deserializing data structures (like `PublicKey` and `EncryptedMessage`).
    *   `derive` feature: To automatically generate (de)serialization code for structs.
*   `serde_json = "1.0"`: For JSON serialization format.
*   `tokio = { version = "1", features = ["full"] }`: Asynchronous runtime for network I/O and concurrent tasks.
    *   `full` feature: Enables all Tokio features, including `net` (sockets), `io`, `macros`, `rt` (runtime).
*   `hex = "0.4"`: For converting byte slices to hexadecimal strings (used for debugging/printing parts of large numbers).

## 7. Potential Improvements / Further Development

*   **Implement Secure Padding:** Add OAEP (Optimal Asymmetric Encryption Padding) or PKCS#1 v1.5 padding to the RSA encryption/decryption to mitigate attacks against textbook RSA.
*   **Hybrid Encryption:** For long messages or frequent communication, RSA is slow. A common practice is to use RSA to encrypt a symmetric key (e.g., AES), and then use the symmetric key to encrypt the actual data. This is hybrid encryption.
*   **More Robust Key Exchange:** Implement a secure key exchange mechanism to prevent Man-in-the-Middle (MitM) attacks (e.g., Diffie-Hellman for establishing a shared secret, or using certificates).
*   **Error Handling:** More granular error types instead of `Box<dyn Error>` could improve debugging and program control flow.
*   **User Interface:** A graphical user interface (GUI) or a more advanced terminal user interface (TUI) would improve usability.
*   **Persistent Keys:** Allow users to save and load their RSA key pairs instead of generating new ones each time. Secure storage of private keys is critical.
*   **Server-Side Multi-User Management:** More sophisticated handling of multiple users on the server, including broadcasting messages or private user-to-user chats if desired.
*   **Constant-Time Operations:** Investigate and implement cryptographic operations (especially modular exponentiation) in constant time to prevent timing side-channel attacks. This is very complex.
*   **Configuration File:** For server address, port, key sizes, etc.