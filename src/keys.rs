extern crate ring;
extern crate rpassword;

use untrusted;
use self::rpassword::prompt_password_stderr;
use self::ring::rand::{SecureRandom,SystemRandom};
use std::path::{Path,PathBuf};
use std::io::{Read,Write};
use std::io;
use std::fs;
use std::error;
use std::fmt;

const SALT_LENGTH: usize = 256;
const PBKDF2_ITERATIONS: u32 = 100000;
static DIGEST_ALG: &'static ring::digest::Algorithm = &ring::digest::SHA256;

#[derive(Debug)]
pub enum Error {
    PasswordError,
    InvalidKeystore,
    CryptoError,
    NotFound,
    IOError(io::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Error::PasswordError    => write!(f, "Invalid password"),
            &Error::InvalidKeystore  => write!(f, "Invalid keystore"),
            &Error::CryptoError      => write!(f, "Cryptographic error"),
            &Error::NotFound         => write!(f, "Not found"),
            &Error::IOError(ref e)   => {
                write!(f, "I/O Error: ");
                e.fmt(f)
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::PasswordError   => "Invalid password",
            &Error::InvalidKeystore => "Invalid keystore",
            &Error::CryptoError     => "Cryptographic error",
            &Error::NotFound        => "Not found",
            &Error::IOError(ref e)  => "I/O error"
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::IOError(e) }
}

#[derive(PartialEq,Copy,Clone)]
pub enum KeyType {
    Symm, Asymm
}

impl KeyType {
    pub fn describe(&self) -> &str {
        match self {
            &KeyType::Symm => "symm",
            &KeyType::Asymm => "asymm"
        }
    }
}

pub enum Key {
    Symmetric(String, Vec<u8>), // CHACHA20_POLY1305 key length
    Asymmetric(String, ring::signature::Ed25519KeyPair) // asymmetric keys
}

//ring::aead::CHACHA20_POLY1305.key_len()

pub struct Keystore {
    /// The location of the keystore's location on disk
    loc: PathBuf,
    index: Vec<(String, KeyType)>
}

impl Keystore {
    /// Create a new local keystore at the given path.
    /// 
    /// Prompt the user for a password to use when encrypting the given keystore
    pub fn create(p: &Path) -> Result<Self, Error> {
        // create a directory there
        fs::create_dir(p)?;

        // derive a root key
        let passwd = prompt_password_stderr("New keystore password: ")?;
        let passwd_conf = prompt_password_stderr("Confirm keystore password: ")?;
        if passwd != passwd_conf {
            writeln!(io::stderr(), "Error: passwords do not match");
            return Err(Error::PasswordError);
        }

        let mut buf = [0u8; ring::digest::SHA256_OUTPUT_LEN];
        let mut salt = [0u8; SALT_LENGTH];
        SystemRandom::new().fill(&mut salt);
        ring::pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERATIONS, &salt,
                             passwd.as_bytes(), &mut buf);

        // write the master key into the keystore, for sync support
        // note that this CANNOT be sent to remotes
        let meta_path = p.join("metadata");
        {
            let mut outfile = fs::File::create(&meta_path)?;
            outfile.write(&buf);
            outfile.sync_all();
        }

        Ok(Keystore {
            loc: p.to_path_buf(),
            index: Vec::new()
        })
    }

    /// Open the keystore located at a given local path
    /// 
    /// Since local keystores are unencrypted, this doesn't ask for a password
    pub fn open(p: &Path) -> Result<Keystore, Error> {
        let cpath = fs::canonicalize(p)?;
        let metapath = cpath.join("metadata");

        // verify keystore
        let root_meta = fs::metadata(&cpath)?;
        let meta_meta = fs::metadata(&metapath)?;

        if !root_meta.is_dir() { return Err(Error::InvalidKeystore); }
        if !meta_meta.is_file() { return Err(Error::InvalidKeystore); }

        // populate key index
        let entries = fs::read_dir(&p)?;
        let mut index = Vec::new();
        
        for e in entries {
            let e = e?;
            if let Some(s) = e.file_name().to_str() {
                if s.ends_with(".asymm") {
                    index.push((s.trim_right_matches(".asymm").to_owned(), KeyType::Asymm));
                    continue;
                }
                if s.ends_with(".symm") {
                    index.push((s.trim_right_matches(".symm").to_owned(), KeyType::Symm));
                    continue;
                }
            }
        }

        Ok(Keystore {
            loc: p.to_path_buf(),
            index: index
        })
    }

    /// Return a list of the valid keys and information about them
    pub fn list_keys(&self) -> Result<&Vec<(String, KeyType)>, Error> {
        Ok(&self.index)
    }

    /// Create a new symmetric/asymmetric key
    pub fn new_key(&mut self, name: &str, t: KeyType) -> Result<Key, Error> {
        let mut rand = SystemRandom::new();
        match t {
            KeyType::Symm => {
                let mut key = [0u8; ring::digest::SHA256_OUTPUT_LEN];
                rand.fill(&mut key);

                // store the key on disk
                {
                    let keypath = self.loc.join(format!("{}.symm", name));
                    let mut f = fs::File::create(&keypath)?;
                    f.write(&key)?;
                    f.sync_all()?;
                }

                // return the result
                self.index.push((name.to_owned(), t));
                Ok(Key::Symmetric(name.to_owned(), key.to_vec()))
            },
            KeyType::Asymm => {
                let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&rand);
                if key.is_err() { return Err(Error::CryptoError); }
                let key = key.unwrap();

                // store the key on disk
                {
                    let keypath = self.loc.join(format!("{}.asymm", name));
                    let mut f = fs::OpenOptions::new()
                        .write(true).create_new(true).open(&keypath)?;
                    f.write(&key)?;
                    f.sync_all()?;
                }

                let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&key)).unwrap();
                self.index.push((name.to_owned(), t));
                Ok(Key::Asymmetric(name.to_owned(), keypair))
            }
        }
    }

    /// Read a named key from the keystore
    pub fn read_key(&self, name: &str, t: KeyType) -> Result<Key, Error> {
        let found = self.index.iter().find(|&&(ref n,t_)| n == name && t_ == t);
        if found.is_none() { return Err(Error::NotFound); }

        // build a path and read the key
        let pth = self.loc.join(format!("{}.{}", name, t.describe()));

        let content = {
            let mut buf = Vec::new();
            let mut f = fs::File::open(pth)?;
            f.read_to_end(&mut buf)?;
            buf
        };

        // try to parse the key
        match t {
            KeyType::Asymm => ring::signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&content))
                .map(|r| Key::Asymmetric(name.to_owned(), r))
                .map_err(|e| Error::CryptoError),
            KeyType::Symm => {
                if content.len() != ring::digest::SHA256_OUTPUT_LEN {
                    Err(Error::CryptoError)
                } else {
                    Ok(Key::Symmetric(name.to_owned(), content))
                }
            }
        }
    }
}
