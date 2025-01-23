mod totp;

#[allow(dead_code)]
enum SHAs {
    SHA1,
    SHA256,
    SHA512
}

fn main() {
    let key_sha1 = "12345678901234567890".as_bytes();
    let key_sha256 = "12345678901234567890123456789012".as_bytes();
    let key_sha512 = "1234567890123456789012345678901234567890123456789012345678901234".as_bytes();
    let step = 30;
    let time = 59;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
    let time = 1111111109;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
    let time = 1111111111;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
    let time = 1234567890;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
    let time = 2000000000;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
    let time = 20000000000;
    println!("{:08}", totp::totp(key_sha1, time, step, 8, SHAs::SHA1));
    println!("{:08}", totp::totp(key_sha256, time, step, 8, SHAs::SHA256));
    println!("{:08}", totp::totp(key_sha512, time, step, 8, SHAs::SHA512));
}
