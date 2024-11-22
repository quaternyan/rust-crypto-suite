use std::io::{self, Write};
use rand;

// Compute m^pow mod n
fn power_mod(m, n, pow) {
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

// Generate a key randomly
fn key_gen() {


// Compute ciphertext c from message m by computing m^e mod n
fn enc(m, e, n) {
    let c = power_mod(m, n, e);
    c
}

// Retrieve message m from ciphertext c by computing c^d mod n
fn dec(c, d, n) {
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
    let key = key_gen();

    // Compute the ciphertext
    let c = enc(
}
