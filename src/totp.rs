use std::ops::{Rem, Shl};
use crate::SHAs;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use hmac::{Hmac, Mac};

pub fn hotp(key: &[u8], counter: &[u8; 8], sha: SHAs) -> i32 {
    match sha {
        SHAs::SHA1 => hotp_sha1(key, counter),
        SHAs::SHA256 => hotp_sha256(key, counter),
        SHAs::SHA512 => hotp_sha512(key, counter)
    }
}

fn hotp_sha1(key: &[u8], counter: &[u8; 8]) -> i32 {
    let hmac_len = 20;
    let mut hmac = Hmac::<Sha1>::new_from_slice(key).expect(format!("Couldn't create an HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(1_000_000)
}

fn hotp_sha256(key: &[u8], counter: &[u8; 8]) -> i32 {
    let hmac_len = 32;
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect(format!("Couldn't create ne HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(1_000_000)
}

fn hotp_sha512(key: &[u8], counter: &[u8; 8]) -> i32 {
    let hmac_len = 64;
    let mut hmac = Hmac::<Sha512>::new_from_slice(key).expect(format!("Couldn't create ne HMAC context from the key {:?}\n", key).as_str());
    hmac.update(counter);
    let hmac = hmac.finalize().into_bytes();
    let offset = (hmac[hmac_len - 1] & 0xf) as usize;
    let code: i32 = ((hmac[offset] as i32) & 0x7f).shl(24) |
        ((hmac[offset + 1] as i32) & 0xff).shl(16) |
        ((hmac[offset + 2] as i32) & 0xff).shl(8) |
        ((hmac[offset + 3] as i32) & 0xff);
    code.rem(1_000_000)
}