use std::ops::{Rem, Shl};
use crate::SHAs;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use hmac::{Hmac, Mac};
use std::time::{SystemTime, UNIX_EPOCH};

const STEP: u64 = 30;

pub fn totp(key: &[u8], digits: u8, sha: SHAs) -> i32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => totp_int(key, duration.as_secs(), STEP, digits, sha),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

fn totp_int(key: &[u8], time_since_t0: u64, time_step: u64, digits: u8, sha: SHAs) -> i32 {
    let count = time_since_t0 / time_step;
    let counter: [u8; 8] = count.to_be_bytes();
    hotp(key, &counter, digits, sha)
}

fn hotp(key: &[u8], counter: &[u8; 8], digits: u8, sha: SHAs) -> i32 {
    match sha {
        SHAs::SHA1 => hotp_sha1(key, counter, digits),
        SHAs::SHA256 => hotp_sha256(key, counter, digits),
        SHAs::SHA512 => hotp_sha512(key, counter, digits)
    }
}

fn hotp_sha1(key: &[u8], counter: &[u8; 8], digits: u8) -> i32 {
    let hmac_len = 20;
    let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect(format!("Couldn't create an HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(10_i32.pow(digits as u32))
}

fn hotp_sha256(key: &[u8], counter: &[u8; 8], digits: u8) -> i32 {
    let hmac_len = 32;
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect(format!("Couldn't create ne HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(10_i32.pow(digits as u32))
}

fn hotp_sha512(key: &[u8], counter: &[u8; 8], digits: u8) -> i32 {
    let hmac_len = 64;
    let mut hmac = Hmac::<Sha512>::new_from_slice(key).expect(format!("Couldn't create ne HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(10_i32.pow(digits as u32))
}