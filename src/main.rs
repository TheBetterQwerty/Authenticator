use std::{
    env, time::{SystemTime, UNIX_EPOCH}
};
use hmac::{ Mac, Hmac, digest::KeyInit as Keyinitl };
use sha1::Sha1;
use base32::decode;

const STEP: u64 = 30;

type HmacSha1 = Hmac<Sha1>;

fn main() {
    let data = parse_qr_code().expect("[!] Error: incorrect link");
    let code = get_code(&data);

    println!("[CODE] {code:0>6}");
}

fn parse_qr_code() -> Option<Vec<u8>> {
    /* TODO: Add picture to qr code */
    let url = env::args()
        .nth(1)
        .expect("[!] Error: please enter a arg")
        .clone();

    let mut x = url.split('=');
    let second = x.nth(1)?;
    let secret = second.split('&').nth(0)?; // lol

    match decode(base32::Alphabet::Rfc4648 { padding: false }, secret) {
        Some(x) => return Some(x),
        None => {
            println!("[!] Error: base32 decoding");
            return None;
        }
    }
}

fn get_code(key: &[u8]) -> u32 {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[!] Error finding time!")
        .as_secs();

    let step_time_count = (current_time / STEP).to_be_bytes();

    let mut hmac = <HmacSha1 as Keyinitl>::new_from_slice(key).expect("[!] Error in hmac");
    hmac.update(&step_time_count);
    let total_hash = hmac.finalize().into_bytes();

    let last_bytes_hash = total_hash.last().cloned().unwrap();

    let offset = (last_bytes_hash & 0x0F) as usize;

    if offset > total_hash.len() || offset + 4 > total_hash.len() {
        eprintln!("[!] Error: hash is too small to find length");
        eprintln!("Len: {}", total_hash.len());
        return 0u32;
    }

    let trucated_bytes: [u8; 4] = total_hash[offset..offset+4].try_into().unwrap();
    let req_num = u32::from_be_bytes(trucated_bytes); // big endian

    let truncated_byte = req_num & 0x7FFF_FFFF; // bitmask for removing the first bit
    let required = truncated_byte % 1_000_000; // round up

    required
}
