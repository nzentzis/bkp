extern crate ssh2;
extern crate tokio_core;
extern crate futures;

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

use metadata::{IdentityTag, MetaObject};
use remote::{RemoteBackend, BackendError, BoxedFuture};

pub struct ConnectOptions<'a> {
    addr: SocketAddr,
    user: String,
    root: &'a Path
}

pub struct Backend {
    sess: Session,
    sock: TcpStream,
    sftp: Sftp<'static>,
    root: PathBuf
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
        Ok(())
    }

    /// Lock the target atomically. If we fail, return an error.
    fn lock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        let mut f = self.sftp.open_mode(&lock_path,
                                        self::ssh2::CREATE,
                                        0xe4, // 0755
                                        self::ssh2::OpenType::File)?;
        Ok(())
    }

    /// Release an atomic lock on the target
    fn unlock(&mut self) -> Result<(), BackendError> {
        let lock_path = self.root.join("bkp.lock");
        self.sftp.unlink(&lock_path)?;
        Ok(())
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
        let mut sftp = sess.sftp()?;
        let mut backend = Backend {
            sess: sess,
            sock: conn,
            sftp: sftp,
            root: opts.root.to_owned()
        };

        // acquire exclusive access
        backend.initialize()?;
        backend.lock()?;

        Ok(backend)
    }

    fn sync_metadata(&mut self, cacheroot: &Path) -> BoxedFuture<()> {
    }

    fn read_meta(&mut self, ident: &IdentityTag) -> BoxedFuture<MetaObject> {
    }

    fn write_meta(&mut self, obj: &MetaObject) -> BoxedFuture<IdentityTag> {
    }

    fn read_block(&mut self, ident: &IdentityTag) -> BoxedFuture<Vec<u8>> {
    }

    fn write_block(&mut self, data: &[u8]) -> BoxedFuture<IdentityTag> {
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.unlock();
    }
}
