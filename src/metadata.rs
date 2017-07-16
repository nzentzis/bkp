extern crate ring;
extern crate byteorder;

use std::time;
use std::io;
use std::io::{Read, Write};
use metadata::byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use util::Hasher;

pub type IdentityTag = [u8; ring::digest::SHA256_OUTPUT_LEN];

/// Convert the given digest into an identity tag.
/// 
/// Panics if the digest isn't the right size.
pub fn tag_from_digest(d: ring::digest::Digest) -> IdentityTag {
    if d.algorithm().output_len != ring::digest::SHA256_OUTPUT_LEN {
        panic!("Cannot generate identity from incorrect-length digest");
    }
    let hash = d.as_ref();
    let mut r = [0u8; ring::digest::SHA256_OUTPUT_LEN];
    for i in 0..ring::digest::SHA256_OUTPUT_LEN { r[i] = hash[i]; }
    r
}

pub struct FSMetadata {
    /// Modification time
    pub mtime: time::SystemTime,

    /// Access time
    pub atime: time::SystemTime,

    /// Creation time
    pub ctime: time::SystemTime,

    /// UNIX mode bits
    pub mode: u32,
}

impl FSMetadata {
    fn load<R: Read>(f: &mut R) -> io::Result<FSMetadata> {
        let mt = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let at = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let ct = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let mode = f.read_u32::<LittleEndian>()?;

        Ok(FSMetadata { mtime: mt, atime: at, ctime: ct, mode: mode })
    }

    fn save<W: Write>(&self, f: &mut W) -> io::Result<()> {
        match self.mtime.duration_since(time::UNIX_EPOCH) {
            Err(e) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }
        match self.atime.duration_since(time::UNIX_EPOCH) {
            Err(e) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }
        match self.ctime.duration_since(time::UNIX_EPOCH) {
            Err(e) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }

        f.write_u16::<LittleEndian>(self.mode as u16)
    }
}

pub enum MetaObjectContents {
    /// A single logical snapshot of a coherent filesystem state
    VersionObject {
        /// the root TreeObject's identity tag
        root: IdentityTag,

        /// the most recent snapshot upon which this one was based
        parent: Option<IdentityTag>
    },

    /// A logical snapshot of a filesystem tree
    TreeObject {
        /// filesystem name as a byte string
        name: Vec<u8>,

        /// filesystem metadata attached to this object
        meta: FSMetadata,

        /// child objects
        children: Vec<IdentityTag>
    },

    /// Data about the contents of a given file and the blocks that make it up
    FileObject {
        /// filesystem name as a byte string
        name: Vec<u8>,

        /// filesystem metadata attached to this object
        meta: FSMetadata,

        /// the IDs of the file's content chunks
        body: Vec<IdentityTag>
    },

    /// Data about a symbolic link
    SymlinkObject {
        /// filesystem name as a byte string
        name: Vec<u8>,

        /// filesystem metadata attached to this object
        meta: FSMetadata,

        /// the symlink's target as a byte string
        target: Vec<u8>
    }
}

pub struct MetaObject {
    /// The object's creation time. Note that this applies to the *object*, not
    /// any files or trees that it contains.
    pub create_time: time::SystemTime,

    /// The object's contents
    pub content: MetaObjectContents
}

impl MetaObject {
    fn load_id<R: Read>(f: &mut R) -> io::Result<IdentityTag> {
        let mut buf = [0u8; ring::digest::SHA256_OUTPUT_LEN];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read a serialized meta object from the passed stream
    pub fn load<R: Read>(mut f: &mut R) -> io::Result<MetaObject> {
        // read required prefix bytes
        let created_time = time::UNIX_EPOCH +
            time::Duration::from_secs(f.read_u64::<LittleEndian>()?);
        let node_type = f.read_u8()?;

        // read type-specific bytes
        let content = match node_type {
            _   => return Err(io::Error::new(io::ErrorKind::InvalidData,
                                             "Incorrect content format")),
            0u8 => { // version
                let root = MetaObject::load_id(f)?;
                let parent =
                    if f.read_u8()? != 0 { Some(MetaObject::load_id(f)?) }
                    else { None };
                MetaObjectContents::VersionObject { root: root, parent: parent }
            },
            1u8 => { // tree
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;
                let num_children = f.read_u32::<LittleEndian>()?;
                let mut children = Vec::with_capacity(num_children as usize);
                for i in 0..num_children {
                    children.push(MetaObject::load_id(&mut f)?);
                }

                MetaObjectContents::TreeObject {
                    name: name, meta: meta, children: children }
            },
            2u8 => { // symlink
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;

                let tgtlen = f.read_u32::<LittleEndian>()?;
                let mut tgt = vec![0u8; namelen as usize];
                f.read_exact(&mut tgt)?;

                MetaObjectContents::SymlinkObject {
                    name: name, meta: meta, target: tgt }
            },
            3u8 => { // file
                let namelen = f.read_u16::<LittleEndian>()?;
                let mut name = vec![0u8; namelen as usize];
                f.read_exact(&mut name)?;

                let meta = FSMetadata::load(&mut f)?;

                let num_chunks = f.read_u32::<LittleEndian>()?;
                let mut chunks = Vec::with_capacity(num_chunks as usize);
                for i in 0..num_chunks {
                    chunks.push(MetaObject::load_id(&mut f)?);
                }

                MetaObjectContents::FileObject {
                    name: name, meta: meta, body: chunks }
            },
        };

        Ok(MetaObject {
            create_time: created_time,
            content: content
        })
    }

    /// Save the metaobject to the given writer, and return the resulting ID
    /// tag.
    pub fn save<W: Write>(&self, mut f: &mut W) -> io::Result<IdentityTag> {
        let mut f = Hasher::sha256(f);
        match self.create_time.duration_since(time::UNIX_EPOCH) {
            Err(e) => f.write_u64::<LittleEndian>(0)?, // clamp to the epoch
            Ok(x)  => f.write_u64::<LittleEndian>(x.as_secs())?
        }

        match self.content {
            MetaObjectContents::VersionObject {ref root, ref parent} => {
                f.write_u8(0u8)?;
                f.write(root)?;
                if let &Some(p) = parent {
                    f.write(&p)?;
                }
            },
            MetaObjectContents::TreeObject {ref name, ref meta, ref children} => {
                f.write_u8(1u8)?;
                f.write_u16::<LittleEndian>(name.len() as u16)?;
                f.write(&name)?;
                meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(children.len() as u32);
                for c in children.iter() {
                    f.write(c)?;
                }
            },
            MetaObjectContents::FileObject {ref name, ref meta, ref body} => {
                f.write_u8(3u8)?;
                f.write_u16::<LittleEndian>(name.len() as u16)?;
                f.write(&name)?;
                meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(body.len() as u32);
                for c in body.iter() {
                    f.write(c)?;
                }
            },
            MetaObjectContents::SymlinkObject {ref name, ref meta, ref target} => {
                f.write_u8(2u8)?;
                f.write_u16::<LittleEndian>(name.len() as u16)?;
                f.write(&name)?;
                meta.save(&mut f)?;

                f.write_u32::<LittleEndian>(name.len() as u32)?;
                f.write(&name)?;
            },
        }

        let id = tag_from_digest(f.finish());
        Ok(id)
    }
}
