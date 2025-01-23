mod totp;

#[allow(dead_code)]
enum SHAs {
    SHA1,
    SHA256,
    SHA512
}

fn main() {
    let key = "12345678901234567890".as_bytes();
    let mut counter: [u8; 8] = [0; 8];
    for _ in 0..=9 {
        println!("{}", totp::hotp(&key, &counter, SHAs::SHA1));
        counter[7] += 1;
    }
}
