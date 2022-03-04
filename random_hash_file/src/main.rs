use rand::prelude::SliceRandom;
use rand::thread_rng;
use std::{env, hash};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::path::Path;

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use whirlpool::Whirlpool;

enum HashAlg {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Whirlpool,
}

fn write_file(passwords: &[String]) -> Result<(), io::Error> {
    let path = Path::new("crackme.txt");
    let mut file = File::create(&path)?;

    for i in passwords {
        writeln!(file, "{}", i)?;
    }
    Ok(())
}

fn parse_wordlist(path: &str) -> Result<Vec<String>, io::Error> {
    let mut words = Vec::new();
    let file = File::open(path)?;
    let rdr = BufReader::new(file);

    for lines in rdr.lines() {
        for word in lines.unwrap().split_whitespace() {
            words.push(word.to_string());
        }
    }
    Ok(words)
}

// Hashes the strings based on the alorithm selected (can find a better way to do this probably)
impl HashAlg {
    fn create_hash(&self, in_pass: &str, in_salt: &str) -> String {
        match self {
            HashAlg::Md5 => {
                let hash = Md5::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Sha1 => {
                let hash = Sha1::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Sha224 => {
                let hash = Sha224::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Sha256 => {
                let hash = Sha256::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Sha384 => {
                let hash = Sha384::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Sha512 => {
                let hash = Sha512::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
            HashAlg::Whirlpool => {
                let hash = Whirlpool::new()
                    .chain_update(in_pass)
                    .chain_update(in_salt)
                    .finalize();
                return format!("{:x}", hash);
            }
        }
    }
}

fn hash_passwords(alg: &HashAlg, words: &[String], num: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let hashes: Vec<String> = words
        .choose_multiple(&mut rng, num)
        .map(|x| alg.create_hash(x, words.choose(&mut rng).unwrap()))
        .collect();
    hashes
}

fn main() {
    let word_path = env::args().nth(1).expect("Word file not found!");
    let num_passwords = env::args()
        .nth(2)
        .expect("Couldn't get num")
        .parse::<usize>()
        .expect("Couldn't parse num");
    let algorithm = env::args()
        .nth(3)
        .unwrap_or_else(|| "random".to_string());
    let words = parse_wordlist(&word_path).unwrap();

    let algs: Vec<HashAlg> = vec![
        HashAlg::Md5,
        HashAlg::Sha1,
        HashAlg::Sha224,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
        HashAlg::Whirlpool,
    ]; // Vec of Hashing Algorithms

    let i = match algorithm.to_lowercase().as_str() {
        "md5" => hash_passwords(&HashAlg::Md5, &words, num_passwords),
        "sha1" => hash_passwords(&HashAlg::Sha1, &words, num_passwords),
        "sha224" => hash_passwords(&HashAlg::Sha224, &words, num_passwords),
        "sha256" => hash_passwords(&HashAlg::Sha256, &words, num_passwords),
        "sha384" => hash_passwords(&HashAlg::Sha384, &words, num_passwords),
        "sha512" => hash_passwords(&HashAlg::Sha512, &words, num_passwords),
        "whirlpool" => hash_passwords(&HashAlg::Whirlpool, &words, num_passwords),
        "random" => hash_passwords(
            algs.choose(&mut thread_rng()).unwrap(),
            &words,
            num_passwords,
        ),
        _ => panic!("Bad algorithm!"),
    };
    //let i = hash_passwords(&words, num_passwords);

    match write_file(&i) {
        Err(why) => panic!("Error: {}", why),
        Ok(_) => println!("All done!"),
    }
}

#[test]
fn md5_hash() {
    let word: Vec<String> = vec!["a".to_string()];
    assert_eq!(
        "4124bc0a9335c27f086f24ba207a4912",
        hash_passwords(&HashAlg::Md5, &word, 1)[0]
    )
}

#[test]
fn sha1_hash() {
    let word: Vec<String> = vec!["a".to_string()];
    assert_eq!(
        "e0c9035898dd52fc65c41454cec9c4d2611bfb37",
        hash_passwords(&HashAlg::Sha1, &word, 1)[0]
    )
}
