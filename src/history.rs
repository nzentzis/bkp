use std::boxed::Box;
use std::result;
use std::error;
use std::fmt;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
use std::ffi::{OsStr, OsString};
use std::io::prelude::*;
use std::ops::Deref;
use std::os::unix::ffi::OsStringExt;

use util::Hasher;
use chunking::Chunkable;
use remote::{BackendResult, BackendError, Backend};
use metadata::{Snapshot, FileObject, SymlinkObject,
               MetaObject, IdentityTag, TreeObject,
               FSMetadata};

#[derive(Debug)]
#[allow(dead_code)]
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
            &Error::IOError(_)     => "I/O error",
            &Error::Backend(_)     => "backend error",
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
    fn check_blocks(&self) -> bool { *self >= IntegrityTestMode::Slow }
}

/// A struct which wraps metadata objects and associates them with a containing
/// backend object.
pub struct ContextWrapper<'a, T> {
    backend: &'a Box<Backend>,
    object: T
}

impl<'a, T> ContextWrapper<'a, T> {
    fn new(backend: &'a Box<Backend>, obj: T) -> Self {
        ContextWrapper { backend: backend, object: obj }
    }

    fn child<C>(&self, obj: C) -> ContextWrapper<'a, C> {
        ContextWrapper {
            backend: self.backend,
            object: obj
        }
    }
}

/// allow easy derefs of context wrapper objects
impl<'a, T> Deref for ContextWrapper<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target { &self.object }
}

/// Context implementation for snapshots
impl<'a> ContextWrapper<'a, Snapshot> {
    /// Get the root tree inside this snapshot
    pub fn get_tree(&self) -> Result<ContextWrapper<'a, TreeObject>> {
        let obj = self.backend.read_meta(&self.root)?;
        match obj {
            MetaObject::Tree(t) => Ok(self.child(t)),
            _                   => Err(Error::IntegrityError)
        }
    }
}

/// Context implementation for tree objects
impl<'a> ContextWrapper<'a, TreeObject> {
    /// Get the object's ID at a given path in this snapshot
    pub fn get_id<P>(&self, pth: P) -> Result<Option<IdentityTag>>
            where P: AsRef<Path> {
        let mut node: TreeObject = self.object.clone();

        // traverse path
        for part in pth.as_ref().iter() {
            let part_vec = part.to_owned().into_vec();

            // retrieve children
            let children: BackendResult<Vec<(IdentityTag,MetaObject)>> =
                node.children.iter()
                .map(|x| self.backend.read_meta(&x).map(|m| (x.clone(), m)))
                .collect();
            let children = children?;

            let mut found = false;
            for (ident,c) in children {
                match c {
                    MetaObject::Tree(t) => {
                        if t.name == part_vec {
                            node = t;
                            found = true;
                            break;
                        }
                    },
                    MetaObject::File(f) => {
                        if f.name == part_vec {
                            return Ok(Some(ident));
                        }
                    },
                    MetaObject::Symlink(ref f) if f.name == part_vec => {
                        if f.name == part_vec {
                            return Ok(Some(ident));
                        }
                    },
                    _ => {
                        // no other values are legal
                        return Err(Error::IntegrityError);
                    }
                }
            }

            if !found {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Get the object at a given path in this snapshot, if any
    pub fn get<P>(&self, pth: P) -> Result<Option<ContextWrapper<'a, MetaObject>>> 
            where P: AsRef<Path> {
        if let Some(ident) = self.get_id(pth)? {
            Ok(Some(self.child(self.backend.read_meta(&ident)?)))
        } else {
            Ok(None)
        }
    }
}

impl<'a> ContextWrapper<'a, FileObject> {
}

impl<'a> ContextWrapper<'a, SymlinkObject> {
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
        // skip block checks in faster modes
        if !mode.check_blocks() { return Ok(true); }

        let data = self.backend.read_block(tag)?;

        // check the hash if needed
        if mode.check_hashes() {
            let mut v = Vec::new();
            let mut writer = Hasher::sha256(&mut v);
            writer.write_all(&data)?;
            let r = writer.finish();
            if r.as_ref() != tag {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // run integrity tests on a file or tree
    fn check_file(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        let obj = self.backend.read_meta(tag)?;
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
            MetaObject::Tree(_) => self.check_tree(mode, tag),
            _ => Ok(false)
        }
    }

    // run integrity tests on a filesystem tree
    fn check_tree(&mut self, mode: IntegrityTestMode, tag: &IdentityTag)
            -> Result<bool> {
        let obj = self.backend.read_meta(tag)?;
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

    #[allow(dead_code)]
    /// Retrieve the most recent snapshot, if any
    pub fn get_snapshot(&self) -> Result<Option<Snapshot>> {
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

    #[allow(dead_code)]
    /// Creates a new snapshot with the given root tree
    /// 
    /// If a snapshot is already stored, then the resulting snapshot will use it
    /// as its parent. Otherwise, the new snapshot will be an origin snapshot.
    pub fn new_snapshot(&mut self, root: IdentityTag) -> Result<IdentityTag> {
        let snap = self.get_snapshot()?;
        let new_obj = MetaObject::snapshot(root,
                                           snap.map(|o| MetaObject::Snapshot(o)
                                                        .ident()));

        // store it
        let ident = self.backend.write_meta(&new_obj)?;

        // and commit it by modifying the head pointer
        self.backend.set_head(&ident)?;
        Ok(ident)
    }

    #[allow(dead_code)]
    /// Try to retrieve the given path from the latest snapshot
    /// 
    /// If no snapshots are stored or the object doesn't exist, this will return
    /// `Ok(None)`.
    pub fn get_path(&self, path: &Path) -> Result<Option<MetaObject>> {
        use std::path::Component;

        let snapshot = self.get_snapshot()?;

        if snapshot.is_none() { return Ok(None); }
        let snapshot = snapshot.unwrap();

        let mut current = snapshot.root;
        for comp in path.components() {
            let cur_elem = self.backend.read_meta(&current)?;

            // snapshots are never valid child targets
            let tree = if let MetaObject::Tree(t) = cur_elem {
                t
            } else {
                return Err(Error::IntegrityError);
            };

            // descend a level based on the component
            match comp {
                Component::Prefix(_) => unimplemented!(), // Windows only - don't care yet
                Component::RootDir => {}, // skip, since we already start at /
                Component::CurDir => panic!("retrieved path is not canonical"),
                Component::ParentDir => panic!("retrieved path is not canonical"),
                Component::Normal(cmp) => { // try to pull the item
                    // retrieve the tree's children
                    let children: Result<Vec<(IdentityTag, MetaObject)>> =
                        tree.children.iter()
                                     .map(|id| self.backend
                                              .read_meta(&id)
                                              .map_err(|e| Error::Backend(e))
                                              .map(|r| (id.to_owned(), r)))
                                     .collect();
                    let children: Vec<(IdentityTag, MetaObject)> = children?;

                    // try to find one matching the path component
                    if let Some(itm) = children.into_iter()
                                      .filter(|c| c.1.name() == Some(cmp.to_os_string()))
                                      .map(|c| c.0)
                                      .next() {
                        current = itm;
                    } else {
                        // no item matching what the path specified
                        return Ok(None);
                    }
                }
            }
        }

        Ok(Some(self.backend.read_meta(&current)?))
    }

    #[allow(dead_code)]
    /// Create a file, tree, or symlink object from a path on disk.
    /// 
    /// The given path should be canonical.
    fn store_path(&mut self, path: &Path) -> Result<IdentityTag> {
        let meta = fs::symlink_metadata(path)?;
        let ftype = meta.file_type();
        let fname = path.file_name().ok_or(Error::InvalidArgument)?;

        // TODO: handle stores of the root directory

        // TODO: checks here to avoid redundant stores
        // this should check the mtime or hash of the files on disk against
        // the mtime/hash of the most recent nodes in the tree
        
        if ftype.is_file() {
            // break it into chunks and store them
            let f = fs::OpenOptions::new()
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

    /// Construct a skeleton tree containing the given subtrees at the point of
    /// the given root, and return its identity.
    /// 
    /// For example, given the root `/usr` and the files `/usr/bin/ls` and
    /// `/usr/share/dict/words`, this function will construct the following set
    /// of tree objects:
    /// 
    ///     /usr
    ///         /bin
    ///             [ls]
    ///         /share
    ///             /dict
    ///                 [words]
    ///
    /// The generated objects will have 
    fn build_tree_skeleton<P: AsRef<Path>>(&mut self, root: &Path,
                                           objects: &Vec<(P, IdentityTag)>) ->
            Result<IdentityTag> {
        // iterate through relevant children and build their trees
        let mut children = Vec::new();
        for child in objects.iter().filter(|p| p.0.as_ref().starts_with(root)) {
            children.push(
                if child.0.as_ref().parent() == Some(root) {
                    // if we hit the child's parent, just add the child ID
                    child.1
                } else {
                    // figure out which path to create next
                    let relative = child.0.as_ref().strip_prefix(root).unwrap();
                    let part = relative.iter().next().unwrap();
                    
                    // create intermediary dirs
                    let path = root.join(part);
                    self.build_tree_skeleton(&path, objects)?
                });
        }

        let name = match root.file_name() {
            None => OsStr::new(""),
            Some(n) => n };
        let tree = MetaObject::tree(name, FSMetadata::default(), children);
        Ok(self.backend.write_meta(&tree)?)
    }

    /// Build a new tree based on the previous root - start at `/` and move
    /// down, inserting updated elements in the right positions along the way.
    /// 
    /// For each directory visited, this will choose whether to use the previous
    /// stored tree (if no updated path is rooted there), use a path from the
    /// input set, or use a new stored tree with recursively updated versions of
    /// the tree's children.
    fn update_tree<P: AsRef<Path>>(&mut self, root: &Path,
                       new_vals: &Vec<(P, IdentityTag)>) ->
            Result<IdentityTag> {
        match new_vals.iter().find(|x| x.0.as_ref() == root) {
            Some(r) => Ok(r.1), // return the updated object
            None => { // no override - look backwards
                let old_version = match self.get_path(root)? {
                    Some(r) => r,
                    None    => {
                        // the folder didn't exist before, so create a new tree
                        // object to hold it and insert the object there
                        return self.build_tree_skeleton(root, new_vals)
                    }
                };

                // check whether we actually need to store this - if nothing
                // under it was changed, we can just re-use the old object
                if new_vals.iter().any(|x| x.0.as_ref().starts_with(root)) {
                    // yep - build a new tree
                    //
                    // this involves iterating through the old tree's children
                    // and recursively updating each, then generating a new tree
                    // object with the updated children list
                    if let MetaObject::Tree(mut t) = old_version {
                        let mut new_children = Vec::new();
                        for child in t.children.drain(..) {
                            // grab a copy and pull out the path component
                            let obj = self.backend.read_meta(&child)?;
                            let name = OsString::from_vec(match obj {
                                MetaObject::Snapshot(_) => {
                                    // trees can't have snapshots as children
                                    return Err(Error::IntegrityError);
                                },
                                MetaObject::Tree(t) => t.name,
                                MetaObject::File(f) => f.name,
                                MetaObject::Symlink(l) => l.name,
                            });

                            // build the new root path and update it
                            let pth = root.join(&name);
                            let new_id = self.update_tree(&pth, new_vals)?;
                            new_children.push(new_id);
                        }

                        t.children = new_children;
                        Ok(self.backend.write_meta(&MetaObject::Tree(t))?)
                    } else {
                        // to get here, one of the new paths must be rooted at
                        // this node, but for a non-tree node that doesn't make
                        // sense
                        Err(Error::IntegrityError)
                    }
                } else {
                    // no, reuse the old one
                    Ok(old_version.ident())
                }
            }
        }
    }

    #[allow(dead_code)]
    /// Generate a new root tree where the nodes corresponding to the specified
    /// paths point to newly-stored copies.
    /// 
    /// Input paths will be canonicalized before further usage.
    pub fn update_paths<'b, P, I>(&mut self, paths: I) -> Result<IdentityTag>
            where P: 'b + AsRef<OsStr> + ?Sized,
                  I: IntoIterator<Item=&'b P> {
        // store a copy of the paths being updated, for later use when building
        // an updated root tree
        let paths: Vec<PathBuf> = {
            // first sort all the paths by depth, so the shallowest ones are
            // visited before their potential children
            let mut paths: Vec<PathBuf> = paths.into_iter()
                                            .map(Path::new)
                                            .map(|p| p.canonicalize().unwrap())
                                            .collect();
            paths.sort_by_key(|p| p.components().count());

            // prune directories that are subdirs of another dir in the list
            let mut result: Vec<PathBuf> = Vec::new();
            for p in paths.into_iter() {
                if !result.iter().any(|x| p.starts_with(x)) {
                    result.push(p);
                }
            }

            result
        };
        
        // store each copy of the dirs to update
        let path_copies: Result<Vec<(PathBuf, IdentityTag)>> = paths
            .into_iter()
            .map(|x| {self.store_path(&x).map(|r| (x, r))})
            .collect();
        let path_copies = path_copies?;

        // store the new root tree
        self.update_tree(&Path::new("/"), &path_copies)
    }
}
