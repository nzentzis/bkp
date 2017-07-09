mod ssh;

extern crate ring;
extern crate futures;
extern crate tokio_core;

use std::io;
use std::time;
use std::os::unix;
use std::path::{Path, PathBuf};
use std::marker::Sized;

use self::futures::future::Future;

use metadata::{IdentityTag, MetaObject};

pub enum BackendError {
    ConnectionFailed,
    InvalidOption,
    ResourceError,
    CommsError,
    IOError(io::Error)
}

pub type BoxedFuture<T> = Box<Future<Item=T, Error=BackendError> + Send>;

/// Trait for everything that stores metadata
pub trait MetadataStore {
    /// List available metadata object IDs
    fn list_meta(&mut self) -> BoxedFuture<Vec<IdentityTag>>;
    
    /// Try to read a metadata object by ID
    fn read_meta(&mut self, ident: &IdentityTag) -> BoxedFuture<MetaObject>;

    /// Try to read a metadata object by ID
    fn write_meta(&mut self, obj: &MetaObject) -> BoxedFuture<IdentityTag>;
}

/// Trait for everything that stores data blocks
pub trait BlockStore {
    /// Read a block from the remote by its identity tag
    fn read_block(&mut self, ident: &IdentityTag) -> BoxedFuture<Vec<u8>>;

    /// Write a given block of data to the remote
    fn write_block(&mut self, data: &[u8]) -> BoxedFuture<IdentityTag>;
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
