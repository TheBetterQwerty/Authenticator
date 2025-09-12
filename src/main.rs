use std::{
    env, time::{SystemTime, UNIX_EPOCH}, fs
};
use hmac::{ Mac, Hmac, digest::KeyInit as Keyinitl };
use sha1::Sha1;
use base32::decode;
use image::open;
use serde::{Serialize, Deserialize};

const STEP: u64 = 30;
const PATH: &str = ""; // path

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Map {
    site: String,
    link: String,
}

fn main() {
    let data = argparse();
    let code = get_code(&data);

    println!("[CODE] {code:0>6}");
}

fn argparse() -> Vec<u8> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[?] Usage: {} [--link/--code/-s] <link/path>", args[0]);
        std::process::exit(0);
    }

    match args[1].as_str() {
        // if link or code save the link too in json
        "--link" => {

            if let Some(x) = parse_link_code(args[2].clone()) {
                return x;
            }
            std::process::exit(0);
        },
        "--code" => {
            if let Some(x) = parse_qr_code(args[2].clone()) {
                return x;
            }
            std::process::exit(0);
        },
        "-s" => {
            if !std::fs::exists(PATH).unwrap() {
                eprintln!("[!] Error: file not created!");
                std::process::exit(0);
            }

            let data: String = match fs::read_to_string(PATH) {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("[!] Error: Reading from file {err}");
                    std::process::exit(0);
                }
            };

            if data.len() == 0 {
                eprintln!("[!] Error: File is empty!");
                std::process::exit(0);
            }

            let records: Vec<Map> = serde_json::from_str(&data).unwrap();
            let search = &args[3];

            for record in records {
                if record.site.eq_ignore_ascii_case(search) {
                    if let Some(x) = parse_link_code(record.link) {
                        return x;
                    }
                }
            }

            eprintln!("[!] Error: No records was found!");
            std::process::exit(0);
        },
        unknown => {
            println!("{}", unknown);
            std::process::exit(0);
        }
    }
}

fn parse_qr_code(path: String) -> Option<Vec<u8>> {
    let img = open(&path).unwrap().to_luma8();
    let mut img = rqrr::PreparedImage::prepare(img);
    let grid = img.detect_grids();

    let (_, content) = grid[0].decode().unwrap();

    println!("{}", content);

    parse_link_code(content)
}

fn parse_link_code(url: String) -> Option<Vec<u8>> {
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
