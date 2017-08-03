use std::boxed::Box;
use std::result;
use std::error;
use std::fmt;
use std::io;
use std::fs;
use std::path::Path;
use std::io::prelude::*;

use chunking::Chunkable;
use remote::{BackendError, MetadataStore, BlockStore,  Backend};
use metadata::{ Snapshot,   TreeObject, FileObject, SymlinkObject, MetaObject,
                FSMetadata, IdentityTag};

#[derive(Debug)]
pub enum Error {
    InvalidArgument,
    IntegrityError,
    NoValidSnapshot,
    IOError(io::Error),
    Backend(BackendError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self {
            &Error::InvalidArgument=> write!(f, "invalid argument"),
            &Error::IntegrityError => write!(f, "integrity error"),
            &Error::NoValidSnapshot=> write!(f, "no valid snapshot"),
            &Error::IOError(ref e) => write!(f, "I/O error: {}", e),
            &Error::Backend(ref e) => write!(f, "backend error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::InvalidArgument=> "invalid argument",
            &Error::IntegrityError => "integrity error",
            &Error::NoValidSnapshot=> "no valid snapshot",
            &Error::IOError(ref e) => "I/O error",
            &Error::Backend(ref e) => "backend error",
        }
    }
}
pub type Result<T> = result::Result<T, Error>;

impl From<BackendError> for Error {
    fn from(e: BackendError) -> Error { Error::Backend(e) }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error { Error::IOError(e) }
}

/// The mode to use when running an integrity test
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum IntegrityTestMode {
    Quick,
    Normal,
    Slow,
    Exhaustive
}

impl IntegrityTestMode {
    fn check_hashes(&self) -> bool { *self == IntegrityTestMode::Exhaustive }
}

/// A wrapper struct to provide history access on top of a given backend
pub struct History<'a> {
    backend: &'a mut Box<Backend>
}

impl<'a> History<'a> {
    /// Wrap the given backend in the history layer
    pub fn new(backend: &'a mut Box<Backend>) -> Result<Self> {
        Ok(History { backend: backend })
    }

    // run integrity tests on a block
    fn check_block(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        //let mut data = self.backend.read_block(tag)?;
        self.backend.read_block(tag)?;
        Ok(true)
    }

    // run integrity tests on a file
    fn check_file(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        let mut obj = self.backend.read_meta(tag)?;
        match obj {
            MetaObject::File(file) => {
                for blk in file.body.iter() {
                    if !self.check_block(mode, &blk)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
            MetaObject::Symlink(_) => {Ok(true)},
            _ => Ok(false)
        }
    }

    // run integrity tests on a filesystem tree
    fn check_tree(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        let mut obj = self.backend.read_meta(tag)?;
        if let MetaObject::Tree(tree) = obj {
            for c in tree.children.iter() {
                if !self.check_file(mode, c)? {
                    return Ok(false);
                }
            }
        } else {
            // incorrect object type
            return Ok(false);
        }
        Ok(true)
    }

    /// Run integrity tests on the history
    pub fn check(&mut self, mode: IntegrityTestMode) -> Result<bool> {
        // get the chain head
        let mut head = self.backend.get_head()?;

        // traverse the snapshot chain
        while let Some(root) = head {
            if let MetaObject::Snapshot(snap) = root {
                // move to the parent if needed
                if let Some(p) = snap.parent {
                    head = Some(self.backend.read_meta(&p)?);
                } else {
                    head = None;
                }

                // check the file structure
                if !self.check_tree(mode, &snap.root)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Retrieve the most recent snapshot, if any
    pub fn get_snapshot(&mut self) -> Result<Option<Snapshot>> {
        let snapshot = self.backend.get_head()?;
        if snapshot.is_none() {
            return Ok(None);
        }
        let snapshot = snapshot.unwrap();

        if let MetaObject::Snapshot(s) = snapshot {
            Ok(Some(s))
        } else {
            Err(Error::NoValidSnapshot)
        }
    }

    /// Try to retrieve the given path from the latest snapshot
    /// 
    /// If no snapshots are stored or the object doesn't exist, this will return
    /// `Ok(None)`.
    pub fn get_path(&mut self, path: &Path) -> Result<Option<MetaObject>> {
        unimplemented!()
    }

    /// Create a file, tree, or symlink object from a path on disk.
    /// 
    /// The given path should be canonical.
    pub fn store_path(&mut self, path: &Path) -> Result<IdentityTag> {
        let meta = fs::symlink_metadata(path)?;
        let ftype = meta.file_type();
        let fname = path.file_name().ok_or(Error::InvalidArgument)?;

        // TODO: checks here to avoid redundant stores
        
        if ftype.is_file() {
            // break it into chunks and store them
            let mut f = fs::OpenOptions::new()
                            .read(true)
                            .open(path)?;
            let mut blocks = Vec::new();
            for c in f.bytes().chunks() {
                blocks.push(self.backend.write_block(&c?)?);
            }

            // construct a new meta-object and store it
            let obj = MetaObject::file(fname, meta, blocks);
            Ok(self.backend.write_meta(&obj)?)
        } else if ftype.is_dir() {
            // store each child
            let mut children = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?; // safely unwrap the result
                let pth = entry.path();

                // store the child node
                children.push(self.store_path(&pth)?);
            }

            // build and store the new object
            let obj = MetaObject::tree(fname, meta, children);
            Ok(self.backend.write_meta(&obj)?)
        } else if ftype.is_symlink() {
            // store the symlink object
            let tgt = fs::read_link(&path)?;
            let obj = MetaObject::symlink(fname, meta, &tgt);
            Ok(self.backend.write_meta(&obj)?)
        } else {
            unimplemented!()
        }
    }
}
