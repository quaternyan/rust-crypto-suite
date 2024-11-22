use std::io::{self, Write};
use rand::Rng;
use num_bigint::{BigUint, RandBigInt};
use num_prime::is_prime;

// Compute m^pow mod n
fn power_mod(m, n, pow) -> BigUint {
     let mut exp = pow;
     let mut base = m % n;
     let mut result = 1;
     while exp > 0 {
         if exp % 2 == 1 {
            result = (result * base) % n
         }

         base = (base * base) % n;
         exp /= 2;
     }
     result
}

// Gets the multiplicative inverse of e mod n
fn mod_inverse(e: &BigUint, n: &BigUint) -> Option<BigUint> {
    None
}

// Generates a random prime number and returns it
fn rand_prime(bits: usize) -> BigUint {
    loop {
        let randp = rng.gen_biguint(bits);
        if is_prime(&randp) {
            return randp;
        }
    }
}

// Generate a key randomly
fn key_gen(e) -> (BigUint, BigUint) {
    let bits = 1024;
    let p = rand_prime(bits);
    let q = rand_prime(bits);
    let n = p * q;
    let phi_n = (p - 1) * (q - 1);
    let d = mod_inverse(e, phi_n);
    (n, d, phi_n)
}

// Compute ciphertext c from message m by computing m^e mod n
fn enc(m, e, n) -> BigUint {
    let c = power_mod(m, n, e);
    c
}

// Retrieve message m from ciphertext c by computing c^d mod n
fn dec(c, d, n, phi_n) -> BigUint {
    m = power_mod(c, n, d);
    m
}

fn main() {
    // Request input from the user
    print!("Enter the message to encrypt: ");
    io::stdout().flush().unwrap();

    // Get user input
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line.");

    // Parse an integer from the input
    let m: i32 = input.parse().expect("Please enter an integer.");

    // Generate a key randomly
    let key = key_gen(e);
    let e = 65537;
    let (n, _, _) = key;
    let (_, d, _) = key;
    let (_, _, phi_n) = key;

    // Compute the ciphertext
    let c = enc(m, e, n);

    // Verify that the ciphertext decrypts to the message again
    let ptxt = dec(c, d, n, phi_n);
    assert!(ptxt == m);
}
