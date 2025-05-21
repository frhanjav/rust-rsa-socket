use num_bigint::{BigUint, BigInt, RandBigInt, ToBigUint}; // Added BigInt
use num_traits::{One, Zero}; // Removed Pow, it's not used directly from here
use rand::thread_rng;
use serde::{Serialize, Deserialize};

const MILLER_RABIN_ITERATIONS: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub e: BigUint,
    pub n: BigUint,
}

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub d: BigUint,
    pub n: BigUint,
}

pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    // use num_bigint::BigInt; // Already imported at the top

    if *a == BigUint::zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }

    let (gcd, x1, y1) = extended_gcd(&(b % a), a); // b % a returns BigUint

    let a_bi = BigInt::from(a.clone());
    let b_bi = BigInt::from(b.clone());

    let x = y1 - (&b_bi / &a_bi) * &x1; // Ensure BigInt division
    let y = x1;

    (gcd, x, y)
}

fn mod_inverse(e: &BigUint, phi_n: &BigUint) -> Option<BigUint> {
    let (gcd, x, _) = extended_gcd(e, phi_n);
    if gcd != BigUint::one() {
        return None;
    }
    let phi_n_bi = num_bigint::BigInt::from(phi_n.clone());
    // Ensure x is positive: (x mod phi_n + phi_n) mod phi_n
    // x might be negative from extended_gcd
    let d_bi = (x % &phi_n_bi + &phi_n_bi) % phi_n_bi;
    d_bi.to_biguint()
}

fn is_prime(n: &BigUint, k: usize) -> bool {
    if *n <= BigUint::one() { return false; }
    let two = 2u32.to_biguint().unwrap();
    let three = 3u32.to_biguint().unwrap();
    if *n == two || *n == three { return true; }
    if n % &two == BigUint::zero() { return false; } // n is &BigUint, % with &BigUint

    let mut rng = thread_rng();
    let n_minus_1 = n - BigUint::one(); // n is &BigUint, n_minus_1 is BigUint

    // Write n-1 as 2^s * d
    let mut s: usize = 0;
    let mut d = n_minus_1.clone(); // d is BigUint
    
    while &d % &two == BigUint::zero() { // Use ref for d in LHS of %
        d /= &two; // d is BigUint, op DivAssign<&BigUint>
        s += 1;
    }

    let n_minus_one_for_check = n - BigUint::one(); // Used for x == n-1 check, this is BigUint

    for _ in 0..k {
        // Pick a random 'a' in [2, n-2]. gen_biguint_range is [low, high)
        // So high should be n-1.
        let high_bound_for_a = n - BigUint::one(); // n is &BigUint, so this is BigUint
                                                    // This makes range [2, n-1), so a is in [2, n-2]
        if high_bound_for_a <= two { // Avoid panic if n is too small (e.g., n=2 or n=3, though already handled)
             // This case should not be reached if n > 3
             continue;
        }
        let a = rng.gen_biguint_range(&two, &high_bound_for_a);
        
        let mut x = a.modpow(&d, n); // d is BigUint, pass &d. n is &BigUint.

        if x == BigUint::one() || x == n_minus_one_for_check {
            continue;
        }

        let mut found_n_minus_1_in_loop = false;
        for _r_idx in 0..s { // s is usize
             x = x.modpow(&two, n); // x is BigUint. two is BigUint. n is &BigUint.
             if x == n_minus_one_for_check {
                 found_n_minus_1_in_loop = true;
                 break;
             }
        }
        if !found_n_minus_1_in_loop { return false; } // composite
    }
    true // probably prime
}


fn generate_large_prime(bits: u64) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let mut p = rng.gen_biguint(bits);
        if p.bit(0) == false { // Ensure odd
            p += BigUint::one();
        }
        // Ensure p is large enough, e.g. p > 3
        if p <= 3u32.to_biguint().unwrap() {
            p = 5u32.to_biguint().unwrap(); // or regenerate
        }
        if is_prime(&p, MILLER_RABIN_ITERATIONS) {
            return p;
        }
    }
}

pub fn generate_keypair(bits: u64) -> KeyPair {
    println!("Generating {}-bit RSA keypair. This may take a moment...", bits * 2);
    // let mut rng = thread_rng(); // rng is not used directly here, generate_large_prime creates its own

    let p = generate_large_prime(bits);
    println!("Generated p: {}... ({} bits)", hex::encode(&p.to_bytes_be()[0..std::cmp::min(4, p.to_bytes_be().len())]), p.bits());
    let q = loop {
        let q_candidate = generate_large_prime(bits);
        if q_candidate != p { break q_candidate; }
    };
    println!("Generated q: {}... ({} bits)", hex::encode(&q.to_bytes_be()[0..std::cmp::min(4, q.to_bytes_be().len())]), q.bits());

    // Use references for arithmetic to avoid moving p and q
    let n = &p * &q;
    println!("Calculated n ({} bits)", n.bits());

    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let phi_n = &p_minus_1 * &q_minus_1;
    println!("Calculated phi_n ({} bits)", phi_n.bits());

    let e = 65537u32.to_biguint().unwrap();

    let d = mod_inverse(&e, &phi_n)
        .expect("Modular inverse does not exist. This shouldn't happen with distinct large primes p, q and standard e.");
    println!("Calculated d ({} bits)", d.bits());
    println!("Key generation complete.");

    KeyPair {
        public: PublicKey { e, n: n.clone() }, // n is BigUint, clone it for PublicKey
        private: PrivateKey { d, n },      // n can be moved here
    }
}

pub fn encrypt(message: &[u8], public_key: &PublicKey) -> Vec<BigUint> {
    // Max (plaintext) bytes per chunk must result in a number < n.
    // n.bits() is the number of bits in n. (n.bits() - 1) / 8 is a safe byte count.
    // If n.bits() is, say, 512, then a number with 511 bits is guaranteed to be < n.
    // (511 / 8) = 63 bytes.
    // A stricter rule: chunk < n. If chunk is k bytes, 2^(8k) > n is possible.
    // So, 8k < n.bits(), or k < n.bits()/8.
    // A chunk of (n.bits()/8 - 1) bytes will be safe. If n.bits() isn't a multiple of 8,
    // then (n.bits() - 1) / 8 is better.
    let n_bytes = (public_key.n.bits() + 7) / 8; // Number of bytes to represent n
    let max_chunk_size = if n_bytes > 1 { n_bytes as usize - 1 } else { 1 }; // Ensure message bytes < n

    if max_chunk_size == 0 {
        // This can happen if n is extremely small (e.g. n < 256, so n_bytes = 1)
        // For RSA, n should be large.
        panic!("RSA modulus 'n' is too small for encryption chunking. n_bytes: {}, n.bits(): {}", n_bytes, public_key.n.bits());
    }
    
    message.chunks(max_chunk_size).map(|chunk_bytes| {
        let m_biguint = BigUint::from_bytes_be(chunk_bytes);
        // It's crucial that m_biguint < public_key.n. Our chunking tries to ensure this.
        // A direct check is good practice, though textbook RSA assumes m < n.
        if m_biguint >= public_key.n {
             // This means our max_chunk_size logic is flawed or message is unusual.
             // For textbook RSA, message itself (as a number) must be < n.
             // If chunking, each chunk (as a number) must be < n.
            panic!(
                "Plaintext chunk as number ({}) is >= modulus n ({}). Chunk size: {} bytes. Max_chunk_size: {}. n.bits: {}",
                m_biguint, public_key.n, chunk_bytes.len(), max_chunk_size, public_key.n.bits()
            );
        }
        m_biguint.modpow(&public_key.e, &public_key.n)
    }).collect()
}

pub fn decrypt(ciphertext_chunks: &[BigUint], private_key: &PrivateKey) -> Result<Vec<u8>, String> {
    let mut decrypted_bytes = Vec::new();
    for c_biguint in ciphertext_chunks {
        if *c_biguint >= private_key.n {
            // This should not happen if encryption was done correctly with the corresponding public key
            return Err(format!("Ciphertext chunk {} is larger than or equal to modulus {}. Decryption impossible.", c_biguint, private_key.n));
        }
        let m_biguint = c_biguint.modpow(&private_key.d, &private_key.n);
        decrypted_bytes.extend_from_slice(&m_biguint.to_bytes_be());
    }
    Ok(decrypted_bytes)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_encryption_decryption_small() {
        let p = 61u32.to_biguint().unwrap();
        let q = 53u32.to_biguint().unwrap();
        let n_val = &p * &q;
        let phi_n_val = (&p - BigUint::one()) * (&q - BigUint::one());
        let e_val = 17u32.to_biguint().unwrap();
        let d_val = mod_inverse(&e_val, &phi_n_val).unwrap();
        
        let public_key = PublicKey { e: e_val.clone(), n: n_val.clone() };
        let private_key = PrivateKey { d: d_val.clone(), n: n_val.clone() };

        let message_str = "Hello RSA!";
        let message_bytes = message_str.as_bytes();

        println!("Original message: {}", message_str);
        println!("Message bytes: {:?}", message_bytes);
        println!("Public key: e={}, n={}", public_key.e, public_key.n);
        println!("n bits: {}", public_key.n.bits());


        let encrypted_chunks = encrypt(message_bytes, &public_key);
        println!("Encrypted chunks: {:?}", encrypted_chunks.iter().map(|c| c.to_string()).collect::<Vec<_>>());
        
        let decrypted_bytes = decrypt(&encrypted_chunks, &private_key).unwrap();
        let decrypted_str = String::from_utf8(decrypted_bytes).unwrap();
        println!("Decrypted message: {}", decrypted_str);

        assert_eq!(message_str, decrypted_str);
    }

    #[test]
    fn test_rsa_key_generation_and_cycle() {
        let key_pair = generate_keypair(64); // 128-bit key
        let message = b"This is a test message for RSA encryption and decryption.";

        let encrypted = encrypt(message, &key_pair.public);
        let decrypted = decrypt(&encrypted, &key_pair.private).expect("Decryption failed");
        
        assert_eq!(message.to_vec(), decrypted);
        println!("128-bit RSA cycle test passed. N bits: {}", key_pair.public.n.bits());
    }

    #[test]
    fn test_large_message_chunking() {
        let key_pair = generate_keypair(128); // 256-bit key
        let message_string = "This is a fairly long message that will definitely need to be chunked for RSA encryption, especially with a modest key size like 256 bits. Let's make it even longer to be sure. Testing chunking functionality is crucial for practical RSA usage.";
        let message = message_string.as_bytes();
        
        let encrypted = encrypt(message, &key_pair.public);
        assert!(encrypted.len() > 1, "Message should have been chunked. Got {} chunks.", encrypted.len());

        let decrypted = decrypt(&encrypted, &key_pair.private).expect("Decryption failed");
        
        assert_eq!(message.to_vec(), decrypted);
        println!("Large message chunking test passed for {}-bit key. N bits: {}", message_string.len(), key_pair.public.n.bits());
    }
}