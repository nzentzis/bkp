extern crate ssh2;
extern crate tokio_core;
extern crate futures;
extern crate owning_ref;
extern crate ring;
extern crate rpassword;

use std::ffi;
use std::env;
use std::io;
use std::ops::Drop;
use std::path::{Path, PathBuf};
use std::net::{SocketAddr, TcpStream};
use std::boxed::Box;
use std::thread;
use std::sync::Mutex;
use std::iter::FromIterator;

use self::ssh2::{Session, Sftp};
use self::futures::future;
use self::futures::future::Future;
use self::futures::sync::oneshot;
use self::owning_ref::OwningHandle;
use self::rpassword::prompt_password_stderr;
use self::ring::rand::{SecureRandom,SystemRandom};

use metadata::{IdentityTag, MetaObject};
use remote::*;
use keys::{MetaKey, DataKey, Keystore};

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
    sock: TcpStream,

    /// The root path on the remote host
    root: PathBuf,

    /// The remote hostname
    host: String,

    /// The node name to use on the remote host
    node: String,

    /// The keystore to use for data encryption/decryption
    keystore: keys::Keystore
}

impl From<self::ssh2::Error> for BackendError {
    fn from(e: self::ssh2::Error) -> BackendError {
        BackendError::BackendError(format!("libssh2 failure {}", e))
    }
}

impl From<oneshot::Canceled> for BackendError {
    fn from(_: oneshot::Canceled) -> BackendError {
        BackendError::ConnectionFailed
    }
}

impl Backend {
    /// Initialize a store on the target if one doesn't exist already
    fn initialize(&mut self) -> Result<(), BackendError> {
        let sess = self.sess.lock().unwrap();
        let meta_root = self.root.join("metadata");
        let mkeys_root = self.root.join("metakeys");
        if sess.stat(&meta_root).is_err() ||
                sess.stat(&self.root.join("blocks")).is_err() {
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

        // make sure we have a meta key there
        let our_meta = mkeys_root.join(&self.node);
        if sess.stat(&our_meta).is_err() {
            let meta_key = self.keystore.new_meta_key(&self.node)?;
            {
                let mut mkey = sess.create(&our_meta)?;
                meta_key.write(&self.keystore, &mut mkey);
            }
        }
        Ok(())
    }

    /// Lock the target atomically. If we fail, return an error.
    fn lock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let sess = self.sess.lock().unwrap();
        let mut f = sess.open_mode(&lock_path, self::ssh2::CREATE,
                                   PERM_0755, self::ssh2::OpenType::File)?;
        Ok(())
    }

    /// Release an atomic lock on the target
    fn unlock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let sess = self.sess.lock().unwrap();
        sess.unlink(&lock_path)?;
        Ok(())
    }
}

impl MetadataStore for Backend {
    fn list_meta(&mut self) -> BackendResult<Vec<IdentityTag>> {
        let sess = self.sess.lock().unwrap();
        let meta_path = self.root.join("metadata");
        let prefix_files = sess.readdir(&meta_path)?;

        let mut result = Vec::new();

        for (root,stat) in prefix_files.into_iter() {
            if stat.is_dir() {
                // prefix dir
                for (file,fstat) in sess.readdir(&root)?.into_iter() {
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

    fn read_meta(&mut self, ident: &IdentityTag) -> BackendResult<MetaObject> {
        unimplemented!()
    }

    fn write_meta(&mut self, obj: &MetaObject) -> BackendResult<IdentityTag> {
        unimplemented!()
    }
}

impl BlockStore for Backend {
    fn read_block(&mut self, ident: &IdentityTag) -> BackendResult<Vec<u8>> {
        unimplemented!()
    }

    fn write_block(&mut self, data: &[u8]) -> BackendResult<IdentityTag> {
        unimplemented!()
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
        let mut conn = TcpStream::connect(opts.addr)?;

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
            keystore: opts.keystore
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

impl Drop for Backend {
    fn drop(&mut self) {
        self.unlock();
    }
}
