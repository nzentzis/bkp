extern crate ring;
extern crate rpassword;
extern crate interfaces;
extern crate byteorder;

use untrusted;
use self::byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::{Read,Write};

use self::rpassword::prompt_password_stderr;
use self::ring::rand::{SecureRandom,SystemRandom};
use std::path::{Path,PathBuf};
use std::io;
use std::fs;
use std::error;
use std::fmt;
use std::cell;

const SALT_LENGTH: usize = 256;
const PBKDF2_ITERATIONS: u32 = 100000;
const AEAD_KEY_LENGTH: usize = 32; // 256 bits
static DIGEST_ALG: &'static ring::digest::Algorithm = &ring::digest::SHA256;

const KEY_FMT_VERSION: u16 = 1;

#[derive(Debug)]
pub enum Error {
    PasswordError,
    InvalidKeystore,
    CryptoError,
    NotFound,
    WrongFormat,
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
            &Error::WrongFormat      => write!(f, "Wrong format"),
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
            &Error::WrongFormat      => "Wrong format",
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

/// Decrypt some data in place
fn decrypt_inplace(key: &[u8; AEAD_KEY_LENGTH],
                   name: &str,
                   mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let key = ring::aead::OpeningKey::new(&ring::aead::CHACHA20_POLY1305,
                                          key).unwrap();

    // pull the top 12 bytes of nonce out
    let (mut nonce, mut body) = data.split_at_mut(12);
    if nonce.len() < 12 {
        return Err(Error::CryptoError);
    }

    let res = ring::aead::open_in_place(&key, &nonce,
                                        name.as_bytes(),
                                        0, // no prefix
                                        &mut body);
    match res {
        Err(_) => Err(Error::CryptoError),
        Ok(pt) => Ok(pt.iter().cloned().collect())
    }
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
fn gen_nonce() -> Result<[u8; 12], Error> {
    // generate nonce
    let mac: [u8; 6] = find_mac_addr()?;
    let mut nonce: [u8; 12] = [0u8; 12];
    SystemRandom::new().fill(&mut nonce);
    for i in 0..6 { nonce[i] = mac[i]; }

    Ok(nonce)
}

/// Encrypt the data block in place
fn encrypt_inplace(key: &[u8; AEAD_KEY_LENGTH],
                   name: &str,
                   mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let nonce = gen_nonce()?;

    // insert the nonce at the beginning of the output
    let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.resize(12+data.len()+tag_len, 0);

    // build the key and encode the data
    let key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305,
                                          key).unwrap();
    let res = ring::aead::seal_in_place(&key, &nonce,
                                        name.as_bytes(),
                                        &mut out[12..], tag_len);
    match res {
        Ok(sz) => {
            out.resize(12+sz, 0);
            Ok(out)
        },
        Err(_) => Err(Error::CryptoError)
    }
}

pub struct MetaKey {
    data: [u8; AEAD_KEY_LENGTH],
    nname: String
}

pub struct DataKey {
    data: [u8; AEAD_KEY_LENGTH],
    rname: String
}

impl MetaKey {
    /// Decrypt the data block
    pub fn decrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        decrypt_inplace(&self.data, &self.nname, data)
    }

    /// Encrypt the data block
    pub fn encrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        encrypt_inplace(&self.data, &self.nname, data)
    }

    /// Write the data key in secure format to a given target stream
    pub fn write<W: WriteBytesExt>(&self,
                                   ks: &Keystore,
                                   s: &mut W) -> Result<(), Error> {
        s.write_u16::<BigEndian>(KEY_FMT_VERSION)?;

        // encode the key to a vector before encrypting
        let mut vkey = Vec::new();
        vkey.write_u16::<BigEndian>(self.nname.as_bytes().len() as u16)?;
        vkey.write_all(self.nname.as_bytes())?;
        vkey.write_all(&self.data)?;

        // encrypt the key and write the nonce into the file
        let nonce = gen_nonce()?;
        s.write_all(&nonce);
        let enc = ks.encrypt_master(vkey, &nonce)?;
        s.write_all(&enc)?;

        Ok(())
    }

    /// Read a securely-encoded key from a target stream and verify it
    pub fn read<R: ReadBytesExt>(&self,
                                 ks: &Keystore,
                                 s: &mut R) -> Result<MetaKey, Error> {
        let vsn = s.read_u16::<BigEndian>()?;
        if vsn > KEY_FMT_VERSION {
            return Err(Error::WrongFormat);
        }

        // read the nonce
        let mut nonce = [0u8; 12];
        s.read_exact(&mut nonce);

        // read the rest of the decrypted data
        let mut crypted = Vec::new();
        s.read_to_end(&mut crypted);

        // decrypt it
        let mut data = io::Cursor::new(ks.decrypt_master(crypted, &nonce)?);

        // read the nname and data
        let nname = {
            let l = data.read_u16::<BigEndian>()?;
            let mut buf = Vec::new();
            buf.resize(l as usize, 0);
            data.read_exact(&mut buf);
            String::from_utf8(buf).map_err(|_| {Error::InvalidKeystore})?
        };

        let mut key = [0u8; AEAD_KEY_LENGTH];
        data.read_exact(&mut key)?;

        Ok(MetaKey {
            nname: nname,
            data: key
        })
    }
}

impl DataKey {
    /// Decrypt the data block
    pub fn decrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        decrypt_inplace(&self.data, &self.rname, data)
    }

    /// Encrypt the data block
    pub fn encrypt(&self, mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
        encrypt_inplace(&self.data, &self.rname, data)
    }

    /// Write the data key in secure format to a given target stream
    pub fn write<W: WriteBytesExt>(&self,
                                   ks: &Keystore,
                                   s: &mut W) -> Result<(), Error> {
        s.write_u16::<BigEndian>(KEY_FMT_VERSION)?;

        // encode the key to a vector before encrypting
        let mut vkey = Vec::new();
        vkey.write_u16::<BigEndian>(self.rname.as_bytes().len() as u16)?;
        vkey.write_all(self.rname.as_bytes())?;
        vkey.write_all(&self.data)?;

        // encrypt the key and write the nonce into the file
        let nonce = gen_nonce()?;
        s.write_all(&nonce);
        let enc = ks.encrypt_master(vkey, &nonce)?;
        s.write_all(&enc)?;

        Ok(())
    }

    /// Read a securely-encoded key from a target stream and verify it
    pub fn read<R: ReadBytesExt>(&self,
                                 ks: &Keystore,
                                 s: &mut R) -> Result<DataKey, Error> {
        let vsn = s.read_u16::<BigEndian>()?;
        if vsn > KEY_FMT_VERSION {
            return Err(Error::WrongFormat);
        }

        // read the nonce
        let mut nonce = [0u8; 12];
        s.read_exact(&mut nonce);

        // read the rest of the decrypted data
        let mut crypted = Vec::new();
        s.read_to_end(&mut crypted);

        // decrypt it
        let mut data = io::Cursor::new(ks.decrypt_master(crypted, &nonce)?);

        // read the rname and data
        let rname = {
            let l = data.read_u16::<BigEndian>()?;
            let mut buf = Vec::new();
            buf.resize(l as usize, 0);
            data.read_exact(&mut buf);
            String::from_utf8(buf).map_err(|_| {Error::InvalidKeystore})?
        };

        let mut key = [0u8; AEAD_KEY_LENGTH];
        data.read_exact(&mut key)?;

        Ok(DataKey {
            rname: rname,
            data: key
        })
    }
}

type MasterKey = [u8; ring::digest::SHA256_OUTPUT_LEN];

#[derive(Clone)]
pub struct Keystore {
    /// The location of the keystore's location on disk
    loc: PathBuf,

    /// In-memory master key cache to avoid multiple prompting
    mkey: cell::Cell<Option<MasterKey>>
}

impl Keystore {
    fn get_master_key(&self) -> Result<MasterKey, Error> {
        if let Some(r) = self.mkey.get() {
            return Ok(r);
        }

        // prompt password
        let passwd = prompt_password_stderr("Keystore password: ")?;

        // get the salt out of the filesystem
        let mut salt = [0u8; SALT_LENGTH];
        {
            let meta_path = self.loc.join("mkey_salt");
            let mut infile = fs::OpenOptions::new()
                .read(true)
                .open(meta_path)?;
            infile.read_exact(&mut salt)?;
        }

        // derive key
        let mut buf = [0u8; ring::digest::SHA256_OUTPUT_LEN];
        ring::pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERATIONS, &salt,
                             passwd.as_bytes(), &mut buf);

        // read and verify the key hash
        let hash = ring::digest::digest(&ring::digest::SHA256, &buf);
        {
            let meta_path = self.loc.join("mkey_hash");
            let mut data = Vec::new();
            let mut infile = fs::OpenOptions::new()
                .read(true)
                .open(meta_path)?;
            infile.read_to_end(&mut data)?;

            if !hash.as_ref().eq(data.as_slice()) {
                return Err(Error::PasswordError);
            }
        }

        // store the key
        self.mkey.replace(Some(buf.clone()));

        return Ok(buf)
    }

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

        // derive a key from the master password
        let mut buf = [0u8; ring::digest::SHA256_OUTPUT_LEN];
        let mut salt = [0u8; SALT_LENGTH];
        SystemRandom::new().fill(&mut salt);
        ring::pbkdf2::derive(DIGEST_ALG, PBKDF2_ITERATIONS, &salt,
                             passwd.as_bytes(), &mut buf);

        // write the password salt for rederivation
        {
            let meta_path = p.join("mkey_salt");
            let mut outf = fs::File::create(&meta_path)?;
            outf.write(&salt);
            outf.sync_all();
        }

        // write a hash of the password for verification
        let hash = ring::digest::digest(&ring::digest::SHA256, &buf);
        {
            let meta_path = p.join("mkey_hash");
            let mut outf = fs::File::create(&meta_path)?;
            outf.write(hash.as_ref());
            outf.sync_all();
        }

        Ok(Keystore {
            loc: p.to_path_buf(),
            mkey: cell::Cell::new(None)
        })
    }

    /// Open the keystore located at a given local path
    /// 
    /// Since local keystores are unencrypted, this doesn't ask for a password
    pub fn open(p: &Path) -> Result<Keystore, Error> {
        let cpath = fs::canonicalize(p)?;

        // verify keystore
        let root_meta = fs::metadata(&cpath)?;
        let mkhash_meta = fs::metadata(&cpath.join("mkey_hash"))?;
        let mksalt_meta = fs::metadata(&cpath.join("mkey_hash"))?;

        if !root_meta.is_dir() { return Err(Error::InvalidKeystore); }
        if !mkhash_meta.is_file() { return Err(Error::InvalidKeystore); }
        if !mksalt_meta.is_file() { return Err(Error::InvalidKeystore); }

        Ok(Keystore {
            loc: p.to_path_buf(),
            mkey: cell::Cell::new(None)
        })
    }

    /// Encrypt some data with the master key. This *will* prompt the user to
    /// enter the master password.
    fn encrypt_master(&self,
                      mut data: Vec<u8>,
                      nonce: &[u8; 12]) -> Result<Vec<u8>, Error> {
        let key = self.get_master_key()?;

        // encrypt the data
        let key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305,
                                              &key).unwrap();
        let empty = Vec::new();
        let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
        let out_len = data.len() + tag_len;
        data.resize(out_len, 0);
        let res = ring::aead::seal_in_place(&key, nonce.as_ref(),
                                            &empty, // no additional data
                                            &mut data, tag_len);
        match res {
            Ok(sz) => {
                Ok(data)
            },
            Err(_) => Err(Error::CryptoError)
        }
    }

    /// Decrypt some data with the master key. This *will* prompt the user to
    /// enter the master password.
    fn decrypt_master(&self,
                      mut data: Vec<u8>,
                      nonce: &[u8; 12]) -> Result<Vec<u8>, Error> {
        let key = self.get_master_key()?;

        // encrypt the data
        let key = ring::aead::SealingKey::new(&ring::aead::CHACHA20_POLY1305,
                                              &key).unwrap();
        let empty = Vec::new();
        let tag_len = ring::aead::CHACHA20_POLY1305.tag_len();
        let out_len = data.len() + tag_len;
        data.resize(out_len, 0);
        let res = ring::aead::seal_in_place(&key, nonce.as_ref(),
                                            &empty, // no additional data
                                            &mut data, tag_len);
        match res {
            Ok(sz) => {
                Ok(data)
            },
            Err(_) => Err(Error::CryptoError)
        }
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

        Ok(MetaKey {
            data: key,
            nname: nodename.to_owned()
        })
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
            Ok(MetaKey {
                data: arr,
                nname: nodename.to_owned()
            })
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
