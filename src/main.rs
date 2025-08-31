#![allow(unused)]
use std::{
    env, time::{SystemTime, UNIX_EPOCH}
};
use hmac::{Mac, Hmac, digest::KeyInit as Keyinitl};
use sha1::{Sha1, Digest};

const STEP: u128 = 30;

type HmacSha1 = Hmac<Sha1>;

fn main() {
    let key = b"Hello world";

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[!] Error finding time!")
        .as_nanos();

    let step_time_count = (current_time / STEP).to_be_bytes();

    let mut hmac = <HmacSha1 as Keyinitl>::new_from_slice(key).expect("[!] Error in hmac");
    hmac.update(&step_time_count);
}
