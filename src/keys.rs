extern crate ring;
extern crate rpassword;
extern crate interfaces;

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
const AEAD_KEY_LENGTH: usize = 32; // 256 bits
static DIGEST_ALG: &'static ring::digest::Algorithm = &ring::digest::SHA256;

#[derive(Debug)]
pub enum Error {
    PasswordError,
    InvalidKeystore,
    CryptoError,
    NotFound,
    IOError(io::Error),
    Unsupported
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
            },
            &Error::Unsupported      => write!(f, "Unsupported operation")
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::PasswordError    => "Invalid password",
            &Error::InvalidKeystore  => "Invalid keystore",
            &Error::CryptoError      => "Cryptographic error",
            &Error::NotFound         => "Not found",
            &Error::IOError(ref e)   => "I/O error",
            &Error::Unsupported      => "Unsupported operation",
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::IOError(e) }
}

impl From<interfaces::InterfacesError> for Error {
    fn from(e: interfaces::InterfacesError) -> Error { Error::Unsupported }
}

/// Find the lowest-numbered MAC address of a local network interface
fn find_mac_addr() -> Result<[u8; 6], Error> {
    use self::interfaces::{Interface, InterfacesError, HardwareAddr};

    let ifaces = Interface::get_all()?.into_iter().filter(|x| {!x.is_loopback()});
    let macs: Result<Vec<HardwareAddr>, InterfacesError> = ifaces
        .map(|x| {x.hardware_addr()}).collect();
    let mut macs: Vec<HardwareAddr> = macs?;
    macs.sort_by_key(|&x| x.as_bare_string());
    if macs.len() == 0 {
        Err(Error::Unsupported)
    } else {
        let mut arr = [0u8; 6];
        let data = macs[0].as_bytes();
        for i in 0..6 { arr[i] = data[i]; }
        Ok(arr)
    }
}

pub struct MetaKey {
    data: [u8; AEAD_KEY_LENGTH]
}

pub struct DataKey {
    data: [u8; AEAD_KEY_LENGTH],
    rname: String
}

impl MetaKey {
}

// Note on Nonce Generation for ChaCha20-Poly1305:
//
// With this cryptosystem, nonces must be unique or all confidentiality will be
// lost. Since there's no good way to generate a unique counter for data keys,
// which are used on multiple systems at once, the 96-bit nonce is constructed
// via the following method:
//
// [48-bit MAC address] [48-bit random value]
//
// Using the terminology from NIST Special Publication 800-38D, section 8, the
// 48-bit MAC address field is the "fixed field" of the deterministic
// construction algorithm. The 48-bit random value forms the invocation field.
// If the system has multiple NICs (aside from the loopback interface), the
// lowest nonzero MAC is used.
//
// This algorithm explicitly *does not* require that the nonces are secret, so
// they are prepended to the message after encryption.
impl DataKey {
    /// Decrypt the data block in place
    fn decrypt_inplace(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let key = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305,
                                              &self.data).unwrap();

        // pull the top 12 bytes of nonce out
        let (mut nonce, mut body) = data.split_at_mut(12);
        if nonce.len() < 12 {
            return Err(Error::CryptoError);
        }

        let res = ring::aead::open_in_place(&key,
                                            &nonce,
                                            self.rname.as_bytes(),
                                            0, // no prefix
                                            &mut body);
        match res {
            Err(_) => Err(Error::CryptoError),
            Ok(pt) => Ok(pt.iter().cloned().collect())
        }
    }

    /// Encrypt the data block in place
    fn encrypt_inplace(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        // generate nonce
        let mac: [u8; 6] = find_mac_addr()?;
        let mut nonce: [u8; 12] = [0u8; 12];
        SystemRandom::new().fill(&mut nonce);
        for i in 0..6 { nonce[i] = mac[i]; }

        // insert the nonce at the beginning of the output
        let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
        let mut out = Vec::new();
        out.extend_from_slice(&nonce);
        out.resize(12+data.len()+tag_len, 0);

        // build the key and encode the data
        let key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305,
                                              &self.data).unwrap();
        let res = ring::aead::seal_in_place(&key,
                                            &nonce,
                                            self.rname.as_bytes(),
                                            &mut out[12..], tag_len);
        match res {
            Ok(sz) => {
                out.resize(12+sz, 0);
                Ok(out)
            },
            Err(_) => Err(Error::CryptoError)
        }
    }
}

#[derive(Clone)]
pub struct Keystore {
    /// The location of the keystore's location on disk
    loc: PathBuf,
}

impl Keystore {
    /// Create a new local keystore at the given path.
    /// 
    /// Prompt the user for a password to use when encrypting the given keystore
    pub fn create(p: &Path) -> Result<Self, Error> {
        // create a directory there
        fs::create_dir(p)?;

        // create subdirectories
        fs::create_dir(p.join("meta"))?;
        fs::create_dir(p.join("data"))?;

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
        // note that this CANNOT be sent to remotes or exported
        let meta_path = p.join("metadata");
        {
            let mut outfile = fs::File::create(&meta_path)?;
            outfile.write(&buf);
            outfile.sync_all();
        }

        Ok(Keystore {
            loc: p.to_path_buf()
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

        Ok(Keystore {
            loc: p.to_path_buf()
        })
    }

    /// Create a new metadata key
    pub fn new_meta_key(&mut self, nodename: &str) -> Result<MetaKey, Error> {
        let mut rand = SystemRandom::new();
        let mut key = [0u8; AEAD_KEY_LENGTH];
        SystemRandom::new().fill(&mut key);

        // store the key on disk
        let meta_loc = self.loc.join("meta");
        {
            let keypath = meta_loc.join(nodename);
            let mut f = fs::File::create(&keypath)?;
            f.write(&key)?;
            f.sync_all()?;
        }

        Ok(MetaKey { data: key })
    }

    /// Create a new data block key
    pub fn new_data_key(&mut self, remote: &str) -> Result<DataKey, Error> {
        let mut rand = SystemRandom::new();
        let mut key = [0u8; AEAD_KEY_LENGTH];
        SystemRandom::new().fill(&mut key);

        let mut buf = [0u8; ring::digest::SHA256_OUTPUT_LEN];

        // store the key on disk
        let data_loc = self.loc.join("data");
        {
            let keypath = data_loc.join(remote);
            let mut f = fs::File::create(&keypath)?;
            f.write(&key)?;
            f.sync_all()?;
        }

        Ok(DataKey {
            data: key,
            rname: remote.to_owned()
        })
    }

    /// Read a given metadata key
    pub fn read_meta_key(&self, nodename: &str) -> Result<MetaKey, Error> {
        let meta_loc = self.loc.join("meta");
        let keypath = meta_loc.join(nodename);

        let content = {
            let mut buf = Vec::new();
            let mut f = fs::File::open(keypath)?;
            f.read_to_end(&mut buf)?;
            buf
        };

        // try to parse the key
        if content.len() != AEAD_KEY_LENGTH {
            Err(Error::CryptoError)
        } else {
            let mut arr = [0u8; AEAD_KEY_LENGTH];
            for i in 0..AEAD_KEY_LENGTH { arr[i] = content[i]; }
            Ok(MetaKey { data: arr })
        }
    }

    /// Read a given data block key
    pub fn read_data_key(&self, remote: &str) -> Result<DataKey, Error> {
        let data_loc = self.loc.join("data");
        let keypath = data_loc.join(remote);

        let content = {
            let mut buf = Vec::new();
            let mut f = fs::File::open(keypath)?;
            f.read_to_end(&mut buf)?;
            buf
        };

        // try to parse the key
        if content.len() != AEAD_KEY_LENGTH {
            Err(Error::CryptoError)
        } else {
            let mut arr = [0u8; AEAD_KEY_LENGTH];
            for i in 0..AEAD_KEY_LENGTH { arr[i] = content[i]; }
            Ok(DataKey { data: arr, rname: remote.to_owned() })
        }
    }
}
