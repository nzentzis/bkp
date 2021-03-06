extern crate ring;
extern crate byteorder;

use std::time;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::default::Default;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use metadata::byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use util::{Hasher, DevNull};

pub const IDENTITY_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
pub type IdentityTag = [u8; IDENTITY_LEN];

/// Convert the given digest into an identity tag.
/// 
/// Panics if the digest isn't the right size.
pub fn tag_from_digest(d: ring::digest::Digest) -> IdentityTag {
    if d.algorithm().output_len != IDENTITY_LEN {
        panic!("Cannot generate identity from incorrect-length digest");
    }
    let hash = d.as_ref();
    let mut r = [0u8; IDENTITY_LEN];
    for i in 0..IDENTITY_LEN { r[i] = hash[i]; }
    r
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FSMetadata {
    /// Modification time
    pub mtime: time::SystemTime,

    /// Access time
    pub atime: time::SystemTime,

    /// Owner's UID
    pub uid: u32,

    /// Owner's GID
    pub gid: u32,

    /// UNIX mode bits
    pub mode: u32,
}

impl FSMetadata {
    fn load<R: Read>(f: &mut R) -> io::Result<FSMetadata> {
        let mt = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let at = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let uid = f.read_u32::<LittleEndian>()? as u32;
        let gid = f.read_u32::<LittleEndian>()? as u32;
        let mode = f.read_u16::<LittleEndian>()? as u32;

        Ok(FSMetadata { mtime: mt, atime: at, uid, gid, mode })
    }

    fn save<W: Write>(&self, f: &mut W) -> io::Result<()> {
        match self.mtime.duration_since(time::UNIX_EPOCH) {
            Err(_) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }
        match self.atime.duration_since(time::UNIX_EPOCH) {
            Err(_) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }

        f.write_u32::<LittleEndian>(self.uid as u32)?;
        f.write_u32::<LittleEndian>(self.gid as u32)?;
        f.write_u16::<LittleEndian>(self.mode as u16)
    }
}

pub trait IntoFSMetadata {
    fn into_metadata(self) -> FSMetadata;
}

impl Default for FSMetadata {
    fn default() -> Self {
        FSMetadata {
            mtime: time::SystemTime::now(),
            atime: time::SystemTime::now(),
            uid: 0,
            gid: 0,
            mode: 0o755
        }
    }
}

impl IntoFSMetadata for fs::Metadata {
    fn into_metadata(self) -> FSMetadata {
        FSMetadata {
            mtime: self.modified().unwrap(),
            atime: self.accessed().unwrap(),
            uid: self.uid(),
            gid: self.gid(),
            mode: self.mode()
        }
    }
}

impl IntoFSMetadata for FSMetadata {
    fn into_metadata(self) -> FSMetadata { self }
}

/// A single logical snapshot of a coherent filesystem state
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    /// The object's creation time. Note that this applies to the *object*, not
    /// any files or trees that it contains.
    pub create_time: time::SystemTime,

    /// the root TreeObject's identity tag
    pub root: IdentityTag,

    /// the most recent snapshot upon which this one was based
    pub parent: Option<IdentityTag>
}

/// A logical snapshot of a filesystem tree
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeObject {
    /// filesystem name as a byte string
    pub name: Vec<u8>,

    /// filesystem metadata attached to this object
    pub meta: FSMetadata,

    /// child objects
    pub children: Vec<IdentityTag>
}

/// Data about the contents of a given file and the blocks that make it up
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileObject {
    /// filesystem name as a byte string
    pub name: Vec<u8>,

    /// filesystem metadata attached to this object
    pub meta: FSMetadata,

    /// the IDs of the file's content chunks
    pub body: Vec<IdentityTag>
}

/// Data about a symbolic link
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SymlinkObject {
    /// filesystem name as a byte string
    pub name: Vec<u8>,

    /// filesystem metadata attached to this object
    pub meta: FSMetadata,

    /// the symlink's target as a byte string
    pub target: Vec<u8>
}

#[derive(PartialEq, Eq, Debug)]
pub enum MetaObject {
    Snapshot(Snapshot),
    Tree(TreeObject),
    File(FileObject),
    Symlink(SymlinkObject)
}

impl MetaObject {
    fn load_id<R: Read>(f: &mut R) -> io::Result<IdentityTag> {
        let mut buf = [0u8; IDENTITY_LEN];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[allow(dead_code)]
    /// Compute the object's identity tag
    pub fn ident(&self) -> IdentityTag {
        let mut dev = DevNull::new();
        self.save(&mut dev).unwrap()
    }

    #[allow(dead_code)]
    /// Utility function to generate a new file object
    pub fn file<S, M, I>(name: &S, meta: M, data: I) -> Self
        where S: AsRef<OsStr> + ?Sized,
              M: IntoFSMetadata,
              I: IntoIterator<Item=IdentityTag> {
        MetaObject::File(FileObject {
            name: name.as_ref().to_owned().into_vec(),
            meta: meta.into_metadata(),
            body: data.into_iter().collect() })
    }

    #[allow(dead_code)]
    /// Utility function to generate a new tree object
    pub fn tree<S, M, I>(name: &S, meta: M, children: I) -> Self
        where S: AsRef<OsStr> + ?Sized,
              M: IntoFSMetadata,
              I: IntoIterator<Item=IdentityTag> {
        MetaObject::Tree(TreeObject {
            name: name.as_ref().to_owned().into_vec(),
            meta: meta.into_metadata(),
            children: children.into_iter().collect() })
    }

    #[allow(dead_code)]
    /// Utility function to generate a new symlink object
    pub fn symlink<S, M, T>(name: &S, meta: M, tgt: &T) -> Self
        where S: AsRef<OsStr> + ?Sized,
              T: AsRef<OsStr> + ?Sized,
              M: IntoFSMetadata {
        MetaObject::Symlink(SymlinkObject {
                name: name.as_ref().to_owned().into_vec(),
                meta: meta.into_metadata(),
                target: tgt.as_ref().to_owned().into_vec() })
    }

    #[allow(dead_code)]
    /// Utility function to generate a new snapshot object
    /// 
    /// Fills in the creation time field with the current time
    pub fn snapshot(root: IdentityTag, parent: Option<IdentityTag>) -> Self {
        // convert to seconds so we can round-trip safely
        let unix_time = time::SystemTime::now()
                             .duration_since(time::UNIX_EPOCH)
                             .unwrap()
                             .as_secs();
        let ctime = time::UNIX_EPOCH + time::Duration::from_secs(unix_time);
        MetaObject::Snapshot(Snapshot {
                create_time: ctime, root: root, parent: parent})
    }

    pub fn name(&self) -> Option<OsString> {
        match self {
            &MetaObject::Snapshot(_) => None,
            &MetaObject::Tree(ref t) => Some(OsString::from_vec(t.name.clone())),
            &MetaObject::File(ref f) => Some(OsString::from_vec(f.name.clone())),
            &MetaObject::Symlink(ref l) => Some(OsString::from_vec(l.name.clone())),
        }
    }

    /// Read a serialized meta object from the passed stream
    pub fn load<R: Read>(mut f: &mut R) -> io::Result<MetaObject> {
        // read required prefix bytes
        let node_type = f.read_u8()?;

        // read type-specific bytes
        let content = match node_type {
            0u8 => { // version
                let created_time = time::UNIX_EPOCH +
                    time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
                let root = MetaObject::load_id(f)?;
                let parent =
                    if f.read_u8()? != 0 { Some(MetaObject::load_id(f)?) }
                    else { None };
                MetaObject::Snapshot(Snapshot {
                    create_time: created_time,
                    root: root, parent: parent })
            },
            1u8 => { // tree
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;
                let num_children = f.read_u32::<LittleEndian>()?;
                let mut children = Vec::with_capacity(num_children as usize);
                for _ in 0..num_children {
                    children.push(MetaObject::load_id(&mut f)?);
                }

                MetaObject::Tree(TreeObject {
                    name: name, meta: meta, children: children })
            },
            2u8 => { // symlink
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;

                let tgtlen = f.read_u32::<LittleEndian>()?;
                let mut tgt = vec![0u8; tgtlen as usize];
                f.read_exact(&mut tgt)?;

                MetaObject::Symlink(SymlinkObject {
                    name: name, meta: meta, target: tgt })
            },
            3u8 => { // file
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;

                let num_chunks = f.read_u32::<LittleEndian>()?;
                let mut chunks = Vec::with_capacity(num_chunks as usize);
                for _ in 0..num_chunks {
                    chunks.push(MetaObject::load_id(&mut f)?);
                }

                MetaObject::File(FileObject {
                    name: name, meta: meta, body: chunks })
            },
            _   => return Err(io::Error::new(io::ErrorKind::InvalidData,
                                             "Incorrect content format")),
        };

        Ok(content)
    }

    fn write_time<W: Write>(f: &mut W, t: time::SystemTime) -> io::Result<()> {
        match t.duration_since(time::UNIX_EPOCH) {
            Err(_) => f.write_u64::<LittleEndian>(0), // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())
        }
    }

    /// Save the metaobject to the given writer, and return the resulting ID
    /// tag.
    pub fn save<W: Write>(&self, mut f: &mut W) -> io::Result<IdentityTag> {
        let mut f = Hasher::sha256(f);

        match self {
            &MetaObject::Snapshot(ref snap) => {
                f.write_u8(0u8)?;
                MetaObject::write_time(&mut f, snap.create_time)?;
                f.write(&snap.root)?;
                if let Some(p) = snap.parent {
                    f.write_u8(1);
                    f.write(&p)?;
                } else {
                    f.write_u8(0);
                }
            },
            &MetaObject::Tree(ref tree) => {
                f.write_u8(1u8)?;
                f.write_u16::<LittleEndian>(tree.name.len() as u16)?;
                f.write(&tree.name)?;
                tree.meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(tree.children.len() as u32)?;
                for c in tree.children.iter() {
                    f.write(c)?;
                }
            },
            &MetaObject::File(ref file) => {
                f.write_u8(3u8)?;
                f.write_u16::<LittleEndian>(file.name.len() as u16)?;
                f.write(&file.name)?;
                file.meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(file.body.len() as u32)?;
                for c in file.body.iter() {
                    f.write(c)?;
                }
            },
            &MetaObject::Symlink(ref link) => {
                f.write_u8(2u8)?;
                f.write_u16::<LittleEndian>(link.name.len() as u16)?;
                f.write(&link.name)?;
                link.meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(link.name.len() as u32)?;
                f.write(&link.name)?;
            },
        }

        let id = tag_from_digest(f.finish());
        Ok(id)
    }
}

mod tests {
    use metadata::*;
    use std::io::Cursor;

    fn check_roundtrip(m: MetaObject) {
        let mut v = Vec::new();
        m.save(&mut v).unwrap();
        let m2 = MetaObject::load(&mut Cursor::new(v)).unwrap();

        assert_eq!(m2, m);
    }

    #[test]
    fn roundtrip_test() {
        check_roundtrip(MetaObject::file(
                "test1",
                FSMetadata {
                    mtime: time::UNIX_EPOCH + time::Duration::from_secs(12345),
                    atime: time::UNIX_EPOCH + time::Duration::from_secs(23456),
                    uid: 12,
                    gid: 4,
                    mode: 12345
                },
                vec![]
        ));
        check_roundtrip(MetaObject::file(
                "test2",
                FSMetadata {
                    mtime: time::UNIX_EPOCH + time::Duration::from_secs(12345),
                    atime: time::UNIX_EPOCH + time::Duration::from_secs(23456),
                    uid: 0,
                    gid: 0xffffffff,
                    mode: 12345
                },
                vec![b"012345678901234567890123456789ab".to_owned(),
                     b"012345678901234567890123456789ab".to_owned(),
                     b"012345678901234567890123456789ab".to_owned()]
        ));
        check_roundtrip(MetaObject::file(
                "test3",
                FSMetadata {
                    mtime: time::UNIX_EPOCH + time::Duration::from_secs(12345),
                    atime: time::UNIX_EPOCH + time::Duration::from_secs(23456),
                    uid: 0xffffffff,
                    gid: 0,
                    mode: 12345
                },
                vec![b"012345678901234567890123456789ab".to_owned()]
        ));
        check_roundtrip(MetaObject::snapshot([1u8; 32], Some([2u8; 32])));
        check_roundtrip(MetaObject::snapshot([1u8; 32], None));
    }
}
