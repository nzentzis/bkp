bkp metadata format
-------------------
In order to support both cross-machine deduplication and logically isolate the
backup trees of each client system, bkp stores filesystem metadata separately
from the actual file content chunks. This metadata is organized into *objects*,
each of which is identified by the 256-bit SHA256 hash of its encoded contents.

The top-level FS metadata object is the *snapshot*. Snapshots represent a
coherent picture of the client's filesystem state. While different pieces of the
snapshot's inner tree may have been captured at different times (since bkp
allows partial snapshots) the snapshot as a whole contains the most recent
backed-up version of every filesystem node at the time where it was created. In
addition to a pointer to the inner tree's metadata object, snapshots also
contain pointers to the previous snapshot, if any exists.

Underneath the snapshot object, the tree object represents one directory on the
client's filesystem. Each tree contains the bytes of its own filename, a copy of
its FS metadata, and a list of IDs of the objects contained inside it. These IDs
can refer to any of the FS node object types: trees, files, or symlinks. Note
that the tree object's filename is empty if it's the root of the filesystem
hierarchy (though the filename may also be empty in other cases).

Symlink objects are the second type of FS object, and are referenced only from
tree objects. They represent a symbolic link on the disk, and contain their
name, metadata, and the path of their target as a bytestring.

File objects are the final type of FS object. As with the other FS objects, they
contain their name and metadata, but they also hold an ordered list of chunk IDs
whose contents form the file when concatenated in the given order.

on-disk formats
===============
The on-disk formats of the various metadata objects are as follows. Note that
all fields are little-endian unless otherwise specified.

    struct obj_tag {
        u8[32] id
    }

    struct fs_metadata {
        u64 mtime // unix time
        u64 atime

        // unix mode bits
        bitfield(u16) mode {
            o_read: 1  // others read
            o_write: 1 // others write
            o_exec: 1  // others exec
            g_read: 1  // group read
            g_write: 1 // group write
            g_exec: 1  // group exec
            u_read: 1  // owner read
            u_write: 1 // owner write
            u_exec: 1  // owner exec
            setuid: 1
            setgid: 1
            sticky: 1
        }
    }

    struct version_object {
        u8  obj_type_id = 0
        u64 create_time

        obj_tag root;

        bool8 has_parent
        if(has_parent) {
            obj_tag parent
        }
    }

    struct tree_object {
        u8  obj_type_id = 1

        u16 name_len
        u8[name_len] name

        fs_metadata meta

        u32 num_children
        obj_tag[num_children] children
    }

    struct symlink_object {
        u8  obj_type_id = 2

        u16 name_len
        u8[name_len] name

        fs_metadata meta

        u32 target_len
        u8[target_len] target
    }

    struct file_object {
        u8  obj_type_id = 3

        u16 name_len
        u8[name_len] name

        fs_metadata meta

        u32 num_chunks
        obj_tag[num_chunks] chunks
    }

packfiles
---------
Since objects are often relatively small, it can be beneficial in some cases to 
store multiple objects within the same file. Within a packfile, all objects
share a common prefix in their identifying SHA256 hashes. These files are
formatted as follows:

    struct packfile_entry<N> {
        u8[N] id
        u32 length
        u8[length] body
    }

    struct packfile {
        u8[4] magic = "PACK"
        u32 num_elements

        // common prefix to SHA hash
        u8 prefix_length
        u8[prefix_length] prefix

        packfile_entry<32-prefix_length>[num_elements] entries
    }

Note that the entries within a packfile are sorted lexicographically based on
their hashes. Packfiles are also gzip-compressed before encryption and/or
storage.
