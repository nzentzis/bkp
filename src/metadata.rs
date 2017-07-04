extern crate ring;

use std::time;

pub type IdentityTag = [u8; ring::digest::SHA256_OUTPUT_LEN];

pub struct FSMetadata {
    /// Modification time
    mtime: time::SystemTime,

    /// Access time
    atime: time::SystemTime,

    /// Creation time
    ctime: time::SystemTime,

    /// UNIX mode bits
    mode: u32,
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
    /// the object's unique identity, defined as the SHA256 hash of its content
    id: IdentityTag,

    /// The object's creation time. Note that this applies to the *object*, not
    /// any files or trees that it contains.
    create_time: time::SystemTime,

    /// The object's contents
    content: MetaObjectContents
}
