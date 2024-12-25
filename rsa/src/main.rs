use std::io::{self, Write};
use num_bigint::{RandBigInt, BigUint, BigInt, ToBigUint, Sign};
use num_traits::{Zero, One};

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
    let mut t: BigInt = Zero::zero();
    let mut tt: BigInt = One::one();
    let mut r = n.clone();
    let mut rr = e.clone();

    while rr != Zero::zero() {
        let q = &r - (&r / &rr) * (&rr);
        let v = &t - BigInt::from_biguint(Sign::Plus, &r/&rr) * &tt;
        r = rr;
        rr = q;
        t = tt;
        tt = v;
    }

    // Return the inverse or None if no inverse exists
    if r > One::one() {
        None
    } else {
        if t < Zero::zero() {
            t = t + BigInt::from_biguint(Sign::Plus, n.clone());
        }
        Some(t.to_biguint().expect("Error converting to BigUint"))
    }
}

// Returns true if a BigUint is prime, false if not
fn is_prime(n: &BigUint) -> bool{
    if n & 1_u8.to_biguint().unwrap() == 0_u8.to_biguint().unwrap() {
        return false;
    }

    // Runs Fermat's test 10 times to determine if an int is prime
    // The chance that the resulting int is not prime is less than 0.0001%
    for _i in 0..10 {
        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint_range(&0_u8.to_biguint().unwrap(), &(n-1u32));
        let result = a.modpow(&(n-1u32), n);
        if result != 1_u8.to_biguint().unwrap() {
            return false;
        }
    }
    return true;
}

// Get a random prime of size bits
fn get_rand_prime(bits: u64, lbound: u64) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut a = rng.gen_biguint(bits);

    while !is_prime(&(&a+lbound)) {
        a = rng.gen_biguint(bits);
    }
    a+lbound
}

// Generate a key randomly
fn key_gen(e: BigUint) -> (BigUint, BigUint, BigUint) {
    let bits: u64 = 1024;
    let lbound: u64 = 2u64.pow(32);
    let p = get_rand_prime(bits, lbound);
    let q = get_rand_prime(bits, lbound);
    let n = &p * &q;
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
    let ptxt = dec(c.clone(), d.clone(), n.clone(), phi_n.clone());

    assert!(ptxt == m);
    println!("Encryption successful!");
    println!("Ciphertext: {}", c);
    println!("Decrypted plaintext: {}", String::from_utf8_lossy(&ptxt.to_bytes_be()));
}

