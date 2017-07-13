extern crate ssh2;
extern crate tokio_core;
extern crate futures;
extern crate owning_ref;

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

use metadata::{IdentityTag, MetaObject};
use remote::*;

const PERM_0755: i32 = 0xe4;
const TAG_LENGTH: usize = 32;

pub struct ConnectOptions<'a> {
    pub addr: SocketAddr,
    pub user: String,
    pub root: &'a Path,
    pub nodename: String
}

pub struct Backend {
    sess: Mutex<OwningHandle<Box<Session>, Box<Sftp<'static>>>>,
    sock: TcpStream,

    /// The root path on the remote host
    root: PathBuf,

    /// The node name to use on the remote host
    node: String
}

impl From<io::Error> for BackendError {
    fn from(e: io::Error) -> BackendError { BackendError::IOError(e) }
}

impl From<self::ssh2::Error> for BackendError {
    fn from(e: self::ssh2::Error) -> BackendError {
        BackendError::BackendError(String::from(e.message()))
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
        if sess.stat(&self.root.join("metadata")).is_err() ||
            sess.stat(&self.root.join("blocks")).is_err() {
            sess.mkdir(&self.root.join("metadata"), PERM_0755)?;
            sess.mkdir(&self.root.join("blocks"), PERM_0755)?;
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

impl<'a> RemoteBackend<ConnectOptions<'a>> for Backend {
    fn create(opts: ConnectOptions) -> Result<Backend, BackendError> {
        let mut sess = Session::new().ok_or(BackendError::ResourceError)?;
        let mut conn = TcpStream::connect(opts.addr)?;

        // configure and start the SSH session
        sess.set_compress(true);
        sess.handshake(&conn)?;

        // try authenticating via an SSH agent, if one's available. Failing that
        // look through ~/.ssh for identities and try them.
        {
            sess.userauth_agent(&opts.user)?;
            let dot_ssh = env::home_dir().unwrap().join(".ssh");

            let id_rsa = dot_ssh.join("id_rsa");
            if id_rsa.exists() {
                Ok(sess.userauth_pubkey_file(&opts.user, None, &id_rsa, None)?)
            } else {
                Err(BackendError::ConnectionFailed)
            }
        }?;
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
            node: opts.nodename
        };

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
