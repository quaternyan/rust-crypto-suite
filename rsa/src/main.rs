use std::io::{self, Write};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One, ToPrimitive};
use primes::is_prime;

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

// Generates a random prime number and returns it
fn rand_prime(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    loop {
        let randp = rng.gen_biguint(bits as u64);
        let mut u64randp: u64 = 0;
        match randp.to_u64() {
            Some(value) => u64randp = value,
            None => println!("Value is too large to fit into a u64."),
        }
        if is_prime(u64randp) {
            return randp;
        }
    }
}

// Generate a key randomly
fn key_gen(e: BigUint) -> (BigUint, BigUint, BigUint) {
    let bits = 1024;
    let p = rand_prime(bits);
    let q = rand_prime(bits);
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

    // Parse an integer from the input
    let m: u32 = input.parse().expect("Please enter an integer.");
    let m = BigUint::from(m);

    // Generate a key randomly
    let e = BigUint::from(65537u32);
    let key = key_gen(e.clone());
    let (n, _, _) = key;
    let (_, d, _) = key;
    let (_, _, phi_n) = key;

    // Compute the ciphertext
    let c = enc(m.clone(), e.clone(), n.clone());

    // Verify that the ciphertext decrypts to the message again
    let ptxt = dec(c, d, n, phi_n);
    assert!(ptxt == m);
}
