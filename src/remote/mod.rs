mod ssh;

extern crate ring;
extern crate futures;
extern crate tokio_core;
extern crate url;

use std::io;
use std::path::{PathBuf};
use std::marker::Sized;

use std::fmt;
use std::error;
use std::net::{SocketAddr, ToSocketAddrs};

use self::url::Url;

use keys;
use config;
use metadata::{IdentityTag, MetaObject};

#[derive(Debug)]
#[allow(dead_code)]
pub enum BackendError {
    ConnectionFailed,
    InvalidOption,
    ResourceError,
    CommsError,
    NoSuchScheme,
    BackendError(String),
    InvalidURL(&'static str),
    IOError(io::Error),
    KeyError(keys::Error)
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &BackendError::ConnectionFailed =>
                write!(f, "connection failed"), 
            &BackendError::InvalidOption =>
                write!(f, "invalid option"),
            &BackendError::ResourceError =>
                write!(f, "insufficient resources"),
            &BackendError::CommsError    =>
                write!(f, "communications error"),
            &BackendError::NoSuchScheme  =>
                write!(f, "invalid backend URL scheme"),
            &BackendError::InvalidURL(ref s)=>
                write!(f, "invalid backend URL: {}", s),
            &BackendError::IOError(ref e)   =>
                write!(f, "I/O error: {}", e),
            &BackendError::BackendError(ref e)   =>
                write!(f, "backend error: {}", e),
            &BackendError::KeyError(ref e) =>
                write!(f, "keystore error: {}", e),
        }
    }
}

impl error::Error for BackendError {
    fn description(&self) -> &str {
        match self {
            &BackendError::ConnectionFailed   => "connection failed",
            &BackendError::InvalidOption      => "invalid option",
            &BackendError::ResourceError      => "insufficient resources",
            &BackendError::CommsError         => "communications error",
            &BackendError::NoSuchScheme       => "invalid backend URL scheme",
            &BackendError::InvalidURL(_)      => "invalid backend URL",
            &BackendError::IOError(_)         => "I/O error",
            &BackendError::BackendError(_)    => "backend error",
            &BackendError::KeyError(_)        => "keystore error",
        }
    }
}

impl From<io::Error> for BackendError {
    fn from(e: io::Error) -> BackendError { BackendError::IOError(e) }
}
impl From<keys::Error> for BackendError {
    fn from(e: keys::Error) -> BackendError { BackendError::KeyError(e) }
}

pub type BackendResult<T> = Result<T, BackendError>;

/// Trait for everything that stores metadata
pub trait MetadataStore {
    /// List available metadata object IDs
    fn list_meta(&mut self) -> BackendResult<Vec<IdentityTag>>;
    
    /// Try to read a metadata object by ID
    fn read_meta(&mut self, ident: &IdentityTag) -> BackendResult<MetaObject>;

    /// Try to read a metadata object by ID
    fn write_meta(&mut self, obj: &MetaObject) -> BackendResult<IdentityTag>;

    /// Read the current head, if one exists
    fn get_head(&mut self) -> BackendResult<Option<MetaObject>>;

    /// Set the current head to a given tag
    fn set_head(&mut self, tag: &IdentityTag) -> BackendResult<()>;
}

/// Trait for everything that stores data blocks
pub trait BlockStore {
    /// Read a block from the remote by its identity tag
    fn read_block(&mut self, ident: &IdentityTag) -> BackendResult<Vec<u8>>;

    /// Write a given block of data to the remote
    fn write_block(&mut self, data: &[u8]) -> BackendResult<IdentityTag>;
}

/// Marker type for storage backends
pub trait Backend : BlockStore + MetadataStore {}
impl<T: BlockStore + MetadataStore> Backend for T {}

/// Generic trait for remote I/O implementations.
/// 
/// Note that all implementations should lock the remote if possible upon
/// connecting, and unlock it when the object implementing RemoteBackend is
/// dropped.
pub trait RemoteBackend<O> : Backend where Self: Sized {
    /// Synchronously create a new backend with the given options
    /// 
    /// This should perform all necessary steps to either initialize a new
    /// target if none exists or verify that the current node can access the
    /// backend.
    fn create(opts: O) -> Result<Self, BackendError>;
}

/// Resolve a URL's host and port to find a socket address
fn url_addr(u: &Url) -> Result<SocketAddr, BackendError> {
    let host = u.host_str()
        .ok_or(BackendError::InvalidURL("port number is required"))?;
    let port = u.port().unwrap_or(22);

    (host, port).to_socket_addrs()
        .map_err(|x| BackendError::IOError(x))
        .and_then(|mut iter| iter.nth(0).ok_or(BackendError::ConnectionFailed))
}

/// Connect to a given backup target
pub fn connect_tgt(tgt: &config::BackupTarget,
                   nodename: &str,
                   ks: &keys::Keystore) -> BackendResult<Box<Backend>> {
    match tgt.url.scheme() {
        "ssh" => {
            let user = tgt.user.clone().unwrap_or(tgt.url.username().to_owned());
            let path = {
                let mut u = tgt.url.clone();
                u.set_host(None)
                    .map_err(|_| BackendError::ConnectionFailed)?;
                u.set_scheme("file")
                    .map_err(|_| BackendError::ConnectionFailed)?;
                let p = &u.path()[1..];
                PathBuf::from(p)
            };
            let opts = ssh::ConnectOptions {
                addr: url_addr(&tgt.url)?,
                user: user.to_owned(),
                key: tgt.key_file.clone(),
                key_pass: tgt.password.clone(),
                root: &path,
                nodename: nodename.to_owned(),
                keystore: ks.clone()
            };
            let backend = ssh::Backend::create(opts)?;
            Ok(Box::new(backend))
        },
        _     => Err(BackendError::NoSuchScheme)
    }
}

/// Connect to a given group of backup targets
#[allow(unused_variables, dead_code)]
pub fn connect_group(tgts: Vec<&config::BackupTarget>,
                     nodename: &str,
                     ks: &keys::Keystore) -> BackendResult<Box<Backend>> {
    unimplemented!()
}
