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

use self::ssh2::{Session, Sftp};
use self::futures::future;
use self::futures::future::Future;
use self::futures::sync::oneshot;
use self::owning_ref::OwningHandle;

use metadata::{IdentityTag, MetaObject};
use remote::*;

const PERM_0755: i32 = 0xe4;

pub struct ConnectOptions<'a> {
    addr: SocketAddr,
    user: String,
    root: &'a Path
}

pub struct Backend {
    sess: OwningHandle<Box<Session>, Box<Sftp<'static>>>,
    sock: TcpStream,

    /// The root path on the remote host
    root: PathBuf,
}

impl From<io::Error> for BackendError {
    fn from(e: io::Error) -> BackendError { BackendError::IOError(e) }
}

impl From<self::ssh2::Error> for BackendError {
    fn from(e: self::ssh2::Error) -> BackendError { BackendError::CommsError }
}

impl From<oneshot::Canceled> for BackendError {
    fn from(_: oneshot::Canceled) -> BackendError {
        BackendError::ConnectionFailed
    }
}

impl Backend {
    /// Initialize a store on the target if one doesn't exist already
    fn initialize(&mut self) -> Result<(), BackendError> {
        if self.sess.stat(&self.root.join("metadata")).is_err() ||
            self.sess.stat(&self.root.join("blocks")).is_err() {
            self.sess.mkdir(&self.root.join("metadata"), PERM_0755)?;
            self.sess.mkdir(&self.root.join("blocks"), PERM_0755)?;
        }
        Ok(())
    }

    /// Lock the target atomically. If we fail, return an error.
    fn lock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let mut f = self.sess.open_mode(&lock_path,
                                        self::ssh2::CREATE,
                                        PERM_0755,
                                        self::ssh2::OpenType::File)?;
        Ok(())
    }

    /// Release an atomic lock on the target
    fn unlock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        self.sess.unlink(&lock_path)?;
        Ok(())
    }
}

impl MetadataStore for Backend {
    fn list_meta(&mut self) -> BoxedFuture<Vec<IdentityTag>> {
        unimplemented!()
    }

    fn read_meta(&mut self, ident: &IdentityTag) -> BoxedFuture<MetaObject> {
        unimplemented!()
    }

    fn write_meta(&mut self, obj: &MetaObject) -> BoxedFuture<IdentityTag> {
        unimplemented!()
    }
}

impl BlockStore for Backend {
    fn read_block(&mut self, ident: &IdentityTag) -> BoxedFuture<Vec<u8>> {
        unimplemented!()
    }

    fn write_block(&mut self, data: &[u8]) -> BoxedFuture<IdentityTag> {
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
            sess: sess_box,
            sock: conn,
            root: opts.root.to_owned(),
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
