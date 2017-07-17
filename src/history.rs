use std::boxed::Box;
use std::result;
use std::error;
use std::fmt;

use remote::{BackendError, MetadataStore, BlockStore,  Backend};
use metadata::{MetaObjectContents, MetaObject, FSMetadata, IdentityTag};

#[derive(Debug)]
pub enum Error {
    Backend(BackendError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self {
            &Error::Backend(ref e) => write!(f, "backend error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::Backend(ref e) => "backend error",
        }
    }
}
pub type Result<T> = result::Result<T, Error>;

impl From<BackendError> for Error {
    fn from(e: BackendError) -> Error { Error::Backend(e) }
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

/// A wrapper struct 
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
        match obj.content {
            MetaObjectContents::FileObject {name:_, meta:_, body: blocks} => {
                for blk in blocks.iter() {
                    if !self.check_block(mode, &blk)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
            MetaObjectContents::SymlinkObject {name:_, meta:_, target:_} => {
                Ok(true)
            },
            _ => Ok(false)
        }
    }

    // run integrity tests on a filesystem tree
    fn check_tree(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        let mut obj = self.backend.read_meta(tag)?;
        if let MetaObjectContents::TreeObject
                { name: _, meta: _, children: children} = obj.content {
            for c in children.iter() {
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
            if let MetaObjectContents::VersionObject
                    { root: r, parent: par } = root.content {
                // move to the parent if needed
                if let Some(p) = par {
                    head = Some(self.backend.read_meta(&p)?);
                } else {
                    head = None;
                }

                // check the file structure
                if !self.check_tree(mode, &r)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
