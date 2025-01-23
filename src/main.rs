mod totp;

use clap;
use base32;
#[allow(dead_code)]
enum SHAs {
    SHA1,
    SHA256,
    SHA512
}

fn main() {
    let args = clap::App::new("TOTP generator")
        .settings(&[clap::AppSettings::ArgRequiredElseHelp, clap::AppSettings::ColoredHelp])
        .version("0.1.0")
        .author("Daniel Trędewicz <danieltredewicz@proton.me>")
        .arg(clap::Arg::with_name("secret")
            .index(1)
            .help("Shared secret in base32.")
            .required(true))
        .get_matches();

    if let Some(secret) = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, args.value_of("secret").expect("No secret provided!")) {
        println!("{}", totp::totp(secret.as_slice(), 6, SHAs::SHA1));
    }
    else {
        println!("base32 couldn't decode :(");
    }
}