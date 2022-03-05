use rayon::prelude::*;
use std::collections::{HashSet, HashMap};
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;
use std::{env, fmt, io};

use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use whirlpool::Whirlpool;

#[derive(Debug, Clone, Hash)]
struct Info {
    pass: String,
    salt: String,
}

// Hashing algorithms that are supported currently
#[derive(Clone)]
enum HashAlg {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Whirlpool,
}

// Implement display for Hashing Algorithms
impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HashAlg::Md5 => write!(f, "Md5"),
            HashAlg::Sha1 => write!(f, "Sha1"),
            HashAlg::Sha224 => write!(f, "Sha224"),
            HashAlg::Sha256 => write!(f, "Sha256"),
            HashAlg::Sha384 => write!(f, "Sha384"),
            HashAlg::Sha512 => write!(f, "Sha512"),
            HashAlg::Whirlpool => write!(f, "Whirlpool"),
        }
    }
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

// Parse a file into a Hash Set
fn parse_file(path: &str) -> Result<HashSet<String>, io::Error> {
    let mut content = HashSet::new();
    let file = File::open(path)?;
    let rdr = BufReader::new(file);

    rdr.lines().for_each(|lines| {
        for word in lines.unwrap().split_whitespace() {
            content.insert(word.to_string());
        }
    });
    Ok(content)
}

// Crack the hashes
fn cracking_time(alg: &HashAlg, hashes: &HashSet<String>, words: &HashSet<String>) -> HashMap<String, Info> {
    let cracked: Arc<Mutex<HashMap<String, Info>>> = Arc::new(Mutex::new(HashMap::new()));
    words.par_iter().for_each(|pass| {
        // Parallel for loop (outer, password)
        words.par_iter().for_each(|salt| {
            // Parallel for loop (inner, salt)
            let temp = cracked.clone();
            let hash = hashes.get(&alg.create_hash(pass, salt)); // if hash in list of hashes, returns the hash
            if hash.is_some() {
                // If hash was found, print
                temp.lock().unwrap().insert(hash.unwrap().to_string(), Info {pass: pass.to_string(), salt: salt.to_string()});
                //println!("{} -> {} + {}", hash.unwrap(), pass, salt);
            }
        })
    });

    let ret = cracked.lock().unwrap();
    ret.to_owned()
}

// Find the algorithm used if not given by the user
fn find_alg(hashes: &HashSet<String>, words: &HashSet<String>) -> HashAlg {
    let algorithm = words.par_iter().find_map_any(|pass| {
        words.par_iter().find_map_any(|salt| {
            if hashes.get(&HashAlg::Md5.create_hash(pass, salt)).is_some() {
                Some(HashAlg::Md5)
            } else if hashes.get(&HashAlg::Sha1.create_hash(pass, salt)).is_some() {
                Some(HashAlg::Sha1)
            } else if hashes
                .get(&HashAlg::Sha224.create_hash(pass, salt))
                .is_some()
            {
                Some(HashAlg::Sha224)
            } else if hashes
                .get(&HashAlg::Sha256.create_hash(pass, salt))
                .is_some()
            {
                Some(HashAlg::Sha256)
            } else if hashes
                .get(&HashAlg::Sha384.create_hash(pass, salt))
                .is_some()
            {
                Some(HashAlg::Sha384)
            } else if hashes
                .get(&HashAlg::Sha512.create_hash(pass, salt))
                .is_some()
            {
                Some(HashAlg::Sha512)
            } else if hashes
                .get(&HashAlg::Whirlpool.create_hash(pass, salt))
                .is_some()
            {
                Some(HashAlg::Whirlpool)
            } else {
                None
            }
        })
    });

    algorithm.unwrap()
}

fn main() {
    let algorithm = env::args().nth(3).unwrap_or_else(|| "none".to_string()); // Get optional alg from user
    let words_path = env::args().nth(2).expect("Word file not found!"); // Get wordlist from user
    let hash_path = env::args().nth(1).expect("Hash file not found!"); // Get hash list from user

    print!("Loading files... ");
    let mut now = Instant::now(); // Start timer
    let words = parse_file(&words_path).expect("Couldn't parse wordlist!"); // Parse words into a Hash Set
    let hashes = parse_file(&hash_path).expect("Couldn't parse hashfile!"); // Parse hashes into a Hash Set
    let mut elapsed = now.elapsed(); // Take current time
    println!("Files loaded in {:.2?}", elapsed);

    print!("Finding hash algorithm... ");
    now = Instant::now(); // Start timer
    let i = match algorithm.to_lowercase().as_str() {
        // let i = the hashing alg
        "md5" => HashAlg::Md5,
        "sha1" => HashAlg::Sha1,
        "sha224" => HashAlg::Sha224,
        "sha256" => HashAlg::Sha256,
        "sha384" => HashAlg::Sha384,
        "sha512" => HashAlg::Sha512,
        "whirlpool" => HashAlg::Whirlpool,
        "none" => find_alg(&hashes, &words), // Find hash alg if not provided by user
        //"none" => find_alg(&algs, &hashes, &words), // Find hash alg if not provided by user
        _ => panic!("Error finding algorithm!"),
    };
    elapsed = now.elapsed(); // Take current time
    println!("{} algorithm found in {:.2?}", i, elapsed);

    println!("Cracking {} hashes!\n", hashes.len());
    now = Instant::now(); // Start timer
    let cracked = cracking_time(&i, &hashes, &words); // Crack the hashes
    elapsed = now.elapsed(); // End timer

    println!("{:#?}", cracked);

    println!("\nCracked in: {:.2?}", elapsed);
    println!(
        "Average time per hash: {:.2?}",
        elapsed / hashes.len().try_into().unwrap()
    );
    println!(
        "Hashes per second: {:.2}",
        hashes.len() as f64 / elapsed.as_secs_f64()
    );
    println!("All Done!");
}
