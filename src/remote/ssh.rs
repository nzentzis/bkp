extern crate ssh2;
extern crate tokio_core;
extern crate futures;
extern crate owning_ref;
extern crate ring;
extern crate rpassword;

use std::env;
use std::ops::Drop;
use std::path::{Path, PathBuf};
use std::net::{SocketAddr, TcpStream};
use std::boxed::Box;
use std::sync::Mutex;
use std::iter::FromIterator;
use std::cell::Cell;

use std::io::{Cursor,Read,Write};

use self::ssh2::{Session, Sftp};
use self::futures::sync::oneshot;
use self::owning_ref::OwningHandle;

use metadata;
use metadata::{IdentityTag, MetaObject, tag_from_digest};
use remote::*;
use keys::{MetaKey, DataKey};
use util::ToHex;

const PERM_0755: i32 = 0x1ed;
const TAG_LENGTH: usize = 32;

pub struct ConnectOptions<'a> {
    /// The socket address of the remote server
    pub addr: SocketAddr,

    /// Which user to log in as
    pub user: String,

    /// An optional path to an SSH key to use. If agent auth fails, key auth
    /// will be tried anyway using ~/.ssh/id_rsa
    pub key: Option<PathBuf>,

    /// The SSH key's password, if any
    pub key_pass: Option<String>,

    /// The remote directory to use as a storage root
    pub root: &'a Path,

    /// The local nodename. Used for creating remote head pointers
    pub nodename: String,

    /// The keystore to use for data encryption/decryption
    pub keystore: keys::Keystore
}

pub struct Backend {
    sess: Mutex<OwningHandle<Box<Session>, Box<Sftp<'static>>>>,
    #[allow(dead_code)]
    sock: TcpStream,

    /// The root path on the remote host
    root: PathBuf,

    /// The remote hostname
    host: String,

    /// The node name to use on the remote host
    node: String,

    /// The keystore to use for data encryption/decryption
    keystore: keys::Keystore,

    // cached data and metadata keys
    datakey: Cell<Option<DataKey>>,
    metakey: Cell<Option<MetaKey>>,
}

impl From<self::ssh2::Error> for BackendError {
    fn from(e: self::ssh2::Error) -> BackendError {
        BackendError::BackendError(
            format!("libssh2 error ({}): {}", e.code(), e.message()))
    }
}

impl From<oneshot::Canceled> for BackendError {
    fn from(_: oneshot::Canceled) -> BackendError {
        BackendError::ConnectionFailed
    }
}

struct BackendLock<'a> {
    backend: &'a Backend
}

impl<'a> Drop for BackendLock<'a> {
    fn drop(&mut self) {
        let _ = self.backend.unlock();
    }
}

impl Backend {
    /// Initialize a store on the target if one doesn't exist already. Return
    /// the remote's data key.
    fn initialize(&mut self) -> Result<(), BackendError> {
        let sess = self.sess.lock().unwrap();
        let meta_root = self.root.join("metadata");
        let mkeys_root = self.root.join("metakeys");
        if sess.stat(&meta_root).is_err() ||
                sess.stat(&self.root.join("blocks")).is_err() {
            println!("initializing SFTP target at {} under {:?}",
                     self.host, self.root);
            sess.mkdir(&meta_root, PERM_0755)?;
            sess.mkdir(&mkeys_root, PERM_0755)?;
            sess.mkdir(&self.root.join("blocks"), PERM_0755)?;
            sess.mkdir(&self.root.join("heads"), PERM_0755)?;

            // generate data key for the remote and store it there
            let data_key = self.keystore.new_data_key(&self.host)?;
            {
                let mut dkey = sess.create(&self.root.join("datakey"))?;
                data_key.write(&self.keystore, &mut dkey)?;
            }
        }

        // make sure we have the remote's data key locally
        if let Err(_) = self.keystore.get_data_key(&self.host) {
            println!("retriving remote data key");
            // sync it
            let mut f = sess.open(&self.root.join("datakey"))?;
            self.keystore.store_data_key(&self.host, &mut f)?;
        }

        // make sure we have the appropriate meta key there
        let our_meta = mkeys_root.join(&self.node);
        if sess.stat(&our_meta).is_err() {
            let meta_key = self.keystore.get_meta_key()?;
            {
                let mut mkey = sess.create(&our_meta)?;
                meta_key.write(&self.keystore, &mut mkey)?;
            }
        }

        Ok(())
    }

    /// Get the local meta key
    fn meta_key(&self) -> MetaKey {
        match self.metakey.get() {
            Some(r) => r,
            None => {
                self.metakey.replace(self.keystore.get_meta_key().ok());
                self.metakey.get().unwrap()
            }
        }
    }

    /// Get the local data key
    fn data_key(&self) -> DataKey {
        match self.datakey.get() {
            Some(r) => r,
            None => {
                self.datakey.replace(self.keystore.get_data_key(&self.host).ok());
                self.datakey.get().unwrap()
            }
        }
    }

    /// Lock the target atomically. If we fail, return an error.
    fn lock(&self) -> Result<BackendLock, BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let sess = self.sess.lock().unwrap();
        let r = if let Err(e) = sess.open_mode(&lock_path,
                                       self::ssh2::CREATE | self::ssh2::EXCLUSIVE,
                                       PERM_0755,
                                       self::ssh2::OpenType::File) {
            let e_code = e.code();
            let e_msg = e.message();
            Err(BackendError::BackendError(
                format!("unable to lock ({}) - {}", e_code, e_msg)))
        } else {
            Ok(BackendLock { backend: self })
        };
        r
    }

    /// Release an atomic lock on the target
    fn unlock(&self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let sess = self.sess.lock().unwrap();
        sess.unlink(&lock_path)?;
        Ok(())
    }
}

impl MetadataStore for Backend {
    fn list_meta(&self) -> BackendResult<Vec<IdentityTag>> {
        let sess = self.sess.lock().unwrap();
        let meta_path = self.root.join("metadata");
        let prefix_files = sess.readdir(&meta_path)?;

        let mut result = Vec::new();

        for (root,stat) in prefix_files.into_iter() {
            if stat.is_dir() {
                // prefix dir
                for (file,_) in sess.readdir(&root)?.into_iter() {
                    if let Some(nm) = file.file_name() {
                        let nm = nm.to_str();
                        if nm.is_none() {
                            continue;
                        }
                        let nm = nm.unwrap();

                        // parse the identity tag out of the filename
                        if !nm.chars().all(|ref x| x.is_digit(16)) ||
                                nm.len() != TAG_LENGTH {
                            // not a valid object name
                            continue;
                        }
                        let mut tag = [0u8; TAG_LENGTH];
                        let chars: Vec<char> = nm.chars().collect();

                        for (i,b) in chars.chunks(2).enumerate() {
                            tag[i] = u8::from_str_radix(
                                &String::from_iter(b.iter()), 16).unwrap();
                        }
                        result.push(tag);
                    }
                }
            } else {
                // packfile
                // TODO: Implement this
                unimplemented!()
            }
        }

        Ok(result)
    }

    fn read_meta(&self, ident: &IdentityTag) -> BackendResult<MetaObject> {
        // generate the prefix and filename
        let prefix = format!("{:02x}", ident[0]);
        let name = ident.as_ref().to_hex();
        
        // read the metadata file
        let sess = self.sess.lock().unwrap();
        let mut path = self.root.join("metadata");
        path.push(prefix);
        path.push(name);
        let data = {
            let mut f = sess.open(&path)?;
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            self.meta_key().decrypt(data)?
        };

        // read the meta object
        Ok(MetaObject::load(&mut Cursor::new(data))?)
    }

    fn write_meta(&mut self, obj: &MetaObject) -> BackendResult<IdentityTag> {
        // encode the object and encrypt it
        let (tag, encoded) = {
            let mut v = Vec::new();
            let tag = obj.save(&mut v)?;
            (tag, self.meta_key().encrypt(v)?)
        };

        // generate the prefix and filename
        let prefix = format!("{:02x}", tag[0]);
        let name = tag.as_ref().to_hex();

        // open the file and write the object
        // no need to lock here, since the files are keyed by contents
        let sess = self.sess.lock().unwrap();
        let mut path = self.root.join("metadata");
        path.push(prefix);

        // make sure the dir exists
        if sess.stat(&path).is_err() { sess.mkdir(&path, PERM_0755)?; }

        // short-circuit if it's already stored
        path.push(name);
        if sess.stat(&path).is_ok() { return Ok(tag); }

        // actually write it
        let mut f = sess.create(&path)?;
        f.write_all(&encoded)?;
        Ok(tag)
    }

    fn get_head(&self) -> BackendResult<Option<MetaObject>> {
        // generate a head path
        let mut path = self.root.join("heads");
        path.push(self.node.to_owned());

        // open and read it
        let mut ident = [0u8; metadata::IDENTITY_LEN];
        {
            let dir_lock = self.lock()?;
            let sess = self.sess.lock().unwrap();
            let f = sess.open(&path);
            match f {
                Ok(mut f) => f.read_exact(&mut ident)?,
                Err(_)    => return Ok(None)
            }
        }

        // get the object
        self.read_meta(&ident).map(Some)
    }

    fn set_head(&mut self, tag: &IdentityTag) -> BackendResult<()> {
        // generate a head path
        let mut path = self.root.join("heads");
        path.push(self.node.to_owned());

        // write it out
        {
            let dir_lock = self.lock()?;
            let sess = self.sess.lock().unwrap();
            let mut f = sess.create(&path)?;
            f.write_all(tag)?;
        }

        Ok(())
    }
}

impl BlockStore for Backend {
    fn read_block(&self, ident: &IdentityTag) -> BackendResult<Vec<u8>> {
        // generate the prefix and filename
        let prefix = format!("{:02x}", ident[0]);
        let name = ident.as_ref().to_hex();
        
        // read the metadata file
        let sess = self.sess.lock().unwrap();
        let mut path = self.root.join("blocks");
        path.push(prefix);
        path.push(name);
        let mut f = sess.open(&path)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        Ok(self.data_key().decrypt(data)?)
    }

    fn write_block(&mut self, data: &[u8]) -> BackendResult<IdentityTag> {
        // hash the data
        let tag = tag_from_digest(ring::digest::digest(&ring::digest::SHA256,
                                                       data));

        // generate the prefix and filename
        let prefix = format!("{:02x}", tag[0]);
        let name = tag.as_ref().to_hex();

        // encrypt the data and write it to a file
        let encrypted = self.data_key().encrypt(data.iter().cloned().collect())?;

        // no need to lock here, since the files are keyed by contents
        let sess = self.sess.lock().unwrap();
        let mut path = self.root.join("blocks");
        path.push(prefix);

        // make sure the dir exists
        if sess.stat(&path).is_err() { sess.mkdir(&path, PERM_0755)?; }

        // short-circuit if it's already stored
        path.push(name);
        if sess.stat(&path).is_ok() { return Ok(tag); }

        // actually write it
        let mut f = sess.create(&path)?;
        f.write_all(&encrypted)?;
        Ok(tag)
    }
}

fn authenticate(sess: &mut Session, user: &str, pass: Option<&String>,
                keyfile: &Option<PathBuf>) -> Result<(), BackendError> {
    if let Ok(_) = sess.userauth_agent(&user) {
        return Ok(());
    }

    // resort to looking through ~/.ssh
    let dot_ssh = env::home_dir().unwrap().join(".ssh");

    let keyfile = keyfile.to_owned().unwrap_or(dot_ssh.join("id_rsa"));
    let pubkey_name = keyfile.file_name()
        .ok_or(BackendError::BackendError(String::from("no public key found")))
        .map(|x| {
            let mut v = x.to_os_string();
            v.push(".pub");
            v })?;
    let pubkey = keyfile.with_file_name(pubkey_name);
    if keyfile.exists() {
        Ok(sess.userauth_pubkey_file(&user,
                                     Some(&pubkey),
                                     &keyfile,
                                     pass.map(|x| x.as_str()))?)
    } else {
        Err(BackendError::ConnectionFailed)
    }
}

impl<'a> RemoteBackend<ConnectOptions<'a>> for Backend {
    fn create(opts: ConnectOptions) -> Result<Backend, BackendError> {
        let mut sess = Session::new().ok_or(BackendError::ResourceError)?;
        let conn = TcpStream::connect(opts.addr)?;

        // configure and start the SSH session
        sess.set_compress(true);
        sess.handshake(&conn)?;

        authenticate(&mut sess, &opts.user,
                     opts.key_pass.as_ref(),
                     &opts.key)?;
        if !sess.authenticated() {
            return Err(BackendError::ConnectionFailed);
        }

        // set up sftp and create the backend
        let sess = Box::new(sess);
        let sess_box = OwningHandle::try_new(sess,
                         |p| {
                             unsafe {
                                 (*p).sftp().map(Box::new)
                             }
                         })?;
        let mut backend = Backend {
            sess: Mutex::new(sess_box),
            sock: conn,
            root: opts.root.to_owned(),
            node: opts.nodename,
            host: format!("{}", opts.addr),
            keystore: opts.keystore,
            datakey: Cell::new(None),
            metakey: Cell::new(None)
        };

        // make sure the target directory exists
        {
            let sess = backend.sess.lock().unwrap();
            let s = sess.stat(&backend.root);
            if s.is_err() {
                return Err(BackendError::BackendError(
                        String::from("cannot access directory")));
            }
        }

        // acquire exclusive access *before* initializing so two processes don't
        // clobber each other
        backend.lock()?;
        backend.initialize()?;

        Ok(backend)
    }
}
