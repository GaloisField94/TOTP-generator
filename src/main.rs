mod totp;

use clap::{self, ArgMatches};
use base32;
use serde::{Serialize, Deserialize};
use std::{fs::File, io::{stdin, Read, Write}, process::exit};

#[allow(dead_code)]
enum SHAs {
    SHA1,
    SHA256,
    SHA512
}

#[derive(Serialize, Deserialize, Debug)]
struct Record {
    service: String,
    secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Records {
    records: Vec<Record>,
}

fn main() {
    let args = clap::App::new("TOTP generator")
        .settings(&[clap::AppSettings::ArgRequiredElseHelp, clap::AppSettings::ColoredHelp])
        .version("0.1.0")
        .author("Daniel Trędewicz <danieltredewicz@proton.me>")
        .arg(clap::Arg::with_name("records_file")
            .index(1)
            .help("Your private file for records storage.")
            .required(true))
        .get_matches();
    
    loop {
        print_menu();
        handle_user_choice(&args);
    }
}

fn print_menu() {
    println!("1. Generate TOTP.");
    println!("2. Add service.");
    println!("3. Quit.")
}

fn handle_user_choice(args: &ArgMatches) {
    let mut user_choice = String::new();
    stdin().read_line(&mut user_choice).expect("stdin failed to read a line.");
    let user_choice: u8 = match user_choice.trim().parse() {
        Ok(x) => x,
        Err(_) => {
            println!("Can't parse your input!");
            return;
        },
    };
    match user_choice {
        1 => {
            let filename = args.value_of("records_file").expect("No filename provided!");
            generate_totp(filename);
            return;
        },
        2 => {
            let filename = args.value_of("records_file").expect("No filename provided!");
            add_service(filename);
            return;
        },
        3 => {
            println!("Bye!");
            exit(0);
        },
        _ => {
            println!("Invalid choice, please try again!");
            return;
        }
    }
}

fn generate_totp(filename: &str) {
    let mut file = File::open(filename).expect(format!("Can't open file {}", filename).as_str());
    let mut file_content = String::new();
    file.read_to_string(&mut file_content).expect("Couldn't read file content!");
    let records: Records = serde_json::from_str(&file_content).expect("Couldn't deserialize file!");
    println!("Connected services (input the number):");
    for (i, record) in records.records.iter().enumerate() {
        println!("{}. {}", i+1, record.service);
    }
    let mut choice = String::new();
    stdin().read_line(&mut choice).expect("stdin failed to read a line.");
    let choice: usize = match choice.trim().parse() {
        Ok(x) => x,
        Err(_) => {
            println!("Can't parse your input!");
            return;
        },
    };
    match base32::decode(base32::Alphabet::Rfc4648 { padding:false }, records.records[choice - 1].secret.as_ref()) {
        Some(secret) => {
            println!("\nTOTP: {}", totp::totp(secret.as_slice(), 6, SHAs::SHA1));
            println!("Seconds to use: {}\n", totp::seconds_left_to_use());
        }
        None => println!("Couldn't decode secret as base32!"),
    }   
}

fn add_service(filename: &str) {
    let mut file = File::open(filename).expect(format!("Can't open file {}", filename).as_str());
    let mut file_content = String::new();
    file.read_to_string(&mut file_content).expect("Couldn't read file content!");
    // drop(file);
    let mut records: Records = if file_content.len() > 0 {
        serde_json::from_str(&file_content).expect("Couldn't deserialize file!")
    } else {
        Records {records: vec![]}
    };
    println!("Already connected services:");
    for (i, record) in records.records.iter().enumerate() {
        println!("{}. {}", i+1, record.service);
    }
    println!("\nPlease provide a service name.");
    let mut new_service = String::new();
    stdin().read_line(&mut new_service).expect("stdin failed to read a line.");
    println!("Please provide a service secret (base32 encoded).");
    let mut secret = String::new();
    stdin().read_line(&mut secret).expect("stdin failed to read a line.");
    let new_record = Record {
        service: new_service.trim().into(),
        secret: secret.trim().into(),
    };
    records.records.push(new_record);
    let records = serde_json::to_string(&records).expect("Couldn't serialize records!");
    println!("{}", records);
    let mut file = File::create(filename).expect(format!("Can't open file {}", filename).as_str());
    file.write(records.as_bytes()).expect("Couldn't write to file!");
}