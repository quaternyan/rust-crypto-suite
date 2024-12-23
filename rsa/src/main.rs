use std::io::{self, Write};
use num_bigint::{BigUint};
use num_traits::{Zero, One};
use num_primes::Generator;

// Compute m^pow mod n
fn power_mod(m: BigUint, n: BigUint, pow: BigUint) -> BigUint {
     let mut exp = pow;
     let mut base = m % n.clone();
     let mut result = BigUint::one();
     while exp > BigUint::zero() {
         if &exp % 2u32 == BigUint::one() {
            result = (result * &base) % &n
         }

         base = (&base * &base) % &n;
         exp /= 2u32;
     }
     result
}

// Gets the multiplicative inverse of e mod n
fn mod_inverse(e: &BigUint, n: &BigUint) -> Option<BigUint> {
    let mut t = BigUint::zero();
    let mut tt = BigUint::one();
    let mut r = n.clone();
    let mut rr = e.clone();

    while rr != BigUint::zero() {
        let q = &r / &rr;
        t = &t - &q * &tt;
        r = &r - &q * &rr;

        std::mem::swap(&mut t, &mut tt);
        std::mem::swap(&mut r, &mut rr);
    }

    // Return the inverse or None if no inverse exists
    if r > BigUint::one() {
        None
    } else {
        if t < BigUint::zero() {
            t = t + n;
        }
        Some(t)
    }
}

// Generate a key randomly
fn key_gen(e: BigUint) -> (BigUint, BigUint, BigUint) {
    let bits = 1024;
    let temp_p: num_primes::BigUint = Generator::new_prime(bits);
    let temp_q: num_primes::BigUint = Generator::new_prime(bits);
    let p = BigUint::from_bytes_be(&temp_p.to_bytes_be());
    let q = BigUint::from_bytes_be(&temp_q.to_bytes_be());
    let n = &p *& q;
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
    let d = mod_inverse(&e, &phi_n).expect("Failed to calcuate mod inverse.");
    (n, d, phi_n)
}

// Compute ciphertext c from message m by computing m^e mod n
fn enc(m: BigUint, e: BigUint, n: BigUint) -> BigUint {
    power_mod(m, n, e)
}

// Retrieve message m from ciphertext c by computing c^d mod n
fn dec(c: BigUint, d: BigUint, n: BigUint, _phi_n: BigUint) -> BigUint {
    power_mod(c, n, d)
}

fn main() {
    // Request input from the user
    print!("Enter the message to encrypt: ");
    io::stdout().flush().unwrap();

    // Get user input
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line.");
    let input = input.trim();

    // Convert the input to an integer
    let m = if let Ok(num) = input.parse::<u32>() {
        // If the input is numeric, use it directly
        BigUint::from(num)
    } else {
        // If the input is text, convert it to a big integer
        let bytes = input.as_bytes(); // Get the byte representation
        BigUint::from_bytes_be(bytes) // Convert bytes to BigUint
    };

    // Generate a key randomly
    let e = BigUint::from(65537u32);
    let key = key_gen(e.clone());
    let (n, _, _) = key;
    let (_, d, _) = key;
    let (_, _, phi_n) = key;

    // Compute the ciphertext
    let c = enc(m.clone(), e.clone(), n.clone());

    // Verify that the ciphertext decrypts to the message again
    let ptxt = dec(c.clone(), d, n, phi_n);

    assert!(ptxt == m);
    println!("Encryption successful!");
    println!("Ciphertext: {}", c);
    println!("Decrypted plaintext: {}", String::from_utf8_lossy(&ptxt.to_bytes_be()));
}

