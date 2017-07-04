//mod ssh;

extern crate ring;
extern crate futures;

use std::time;
use std::os::unix;
use metadata::{IdentityTag, MetaObject};

pub enum BackendError {
    ConnectionFailed,
    InvalidOption
}

/// Generic interface for all remote I/O implementations.
/// 
/// Note that all implementations should lock the remote if possible upon
/// connecting, and unlock it when the object implementing RemoteBackend is
/// dropped.
pub trait RemoteBackend {
    /// Initialize a new target on the given remote.
    fn init(&mut self) -> Result<(), BackendError>;

    /// Verify that the remote is valid and that the current node can access it
    fn validate(&mut self) -> Result<(), BackendError>;

    /// Synchronize local metadata caches with the remote
    fn sync_metadata(&mut self) -> Result<(), BackendError>;

    /// Try to read a metadata object by ID
    fn read_meta(&mut self, ident: &IdentityTag) -> Result<MetaObject, BackendError>;

    /// Try to read a metadata object by ID
    fn write_meta(&mut self, obj: &MetaObject) -> Result<IdentityTag, BackendError>;

    /// Read a block from the remote by its identity tag
    fn read_block(&mut self, ident: &IdentityTag) -> Result<Vec<u8>, BackendError>;

    /// Write a given block of data to the remote
    fn write_block(&mut self, data: &[u8]) -> Result<IdentityTag, BackendError>;
}
