mod ssh;

extern crate ring;
extern crate futures;
extern crate tokio_core;
extern crate url;

use std::io;
use std::time;
use std::os::unix;
use std::path::{Path, PathBuf};
use std::marker::Sized;

use std::fmt;
use std::error;
use std::net::{SocketAddr, ToSocketAddrs};

use self::futures::Future;
use self::url::Url;

use config;
use metadata::{IdentityTag, MetaObject};

#[derive(Debug)]
pub enum BackendError {
    ConnectionFailed,
    InvalidOption,
    ResourceError,
    CommsError,
    NoSuchScheme,
    BackendError(String),
    InvalidURL(&'static str),
    IOError(io::Error)
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
        }
    }
}

impl error::Error for BackendError {
    fn description(&self) -> &str {
        match self {
            &BackendError::ConnectionFailed => "connection failed",
            &BackendError::InvalidOption    => "invalid option",
            &BackendError::ResourceError    => "insufficient resources",
            &BackendError::CommsError       => "communications error",
            &BackendError::NoSuchScheme     => "invalid backend URL scheme",
            &BackendError::InvalidURL(ref s)=> "invalid backend URL",
            &BackendError::IOError(ref e)   => "I/O error",
            &BackendError::BackendError(ref s)=> "backend error",
        }
    }
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

fn url_addr(u: &Url) -> Result<SocketAddr, BackendError> {
    let host = u.host_str()
        .ok_or(BackendError::InvalidURL("port number is required"))?;
    let port = u.port().unwrap_or(22);

    (host, port).to_socket_addrs()
        .map_err(|x| BackendError::IOError(x))
        .and_then(|mut iter| iter.nth(0).ok_or(BackendError::ConnectionFailed))
}

pub fn connect_tgt(tgt: &config::BackupTarget, nodename: &str)
        -> BackendResult<Box<Backend>> {
    match tgt.url.scheme() {
        "ssh" => {
            if tgt.url.username().is_empty() {
                return Err(BackendError::InvalidOption)
            }
            let path = Path::new(tgt.url.path());
            let opts = ssh::ConnectOptions {
                addr: url_addr(&tgt.url)?,
                user: tgt.url.username().to_owned(),
                root: &path,
                nodename: nodename.to_owned() };
            let backend = ssh::Backend::create(opts)?;
            Ok(Box::new(backend))
        },
        _     => Err(BackendError::NoSuchScheme)
    }
}

pub fn connect_group(tgts: Vec<&config::BackupTarget>)
        -> BackendResult<Box<Backend>> {
    unimplemented!()
}
