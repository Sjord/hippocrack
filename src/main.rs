use std::env;
use std::io::{self, BufRead};
use base64;
use sha2::{Sha256, Digest};

const DIGEST_ITERATIONS : i32 = 1039;

fn get_digest(password : &[u8], salt : &[u8]) -> String {
    let mut hasher = Sha256::default();
    hasher.input(salt);
    hasher.input(password);
    let mut digest = hasher.result();

    for _ in 0..DIGEST_ITERATIONS {
        hasher = Sha256::default();
        hasher.input(digest);
        digest = hasher.result();
    }
    return base64::encode(digest);
}

fn crack(hash: String) {
    let mut split = hash.split("$");
    split.next();
    let algo = split.next().unwrap();
    assert!(algo == "SHA-256");
    let salt = base64::decode(split.next().unwrap()).unwrap();
    let hash = split.next().unwrap();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let password = line.unwrap();
        let p_hash = get_digest(&password.as_bytes(), &salt);
        if p_hash == hash {
            println!("{}", password);
            return;
        }
    }
}
    
fn main() {
    if let Some(hash) = env::args().nth(1) {
        crack(hash);
    } else {
        println!("Usage: hippocrack '$SHA-256$...$...=' < dict.txt");
    }
}
