use url::Url;
use std::path::{PathBuf,Path};
use std::fs::File;

/// Configuration and options for asymmetric signature algorithms
pub struct SignatureConfig {
    /// Name of the asymmetric key to use
    key: String
}

/// Configuration and options for symmetric data-protection algorithms
pub struct EncryptionConfig {
    /// Name of the symmetric key to use
    key: String
}

pub enum CryptoMode {
    /// Disable encryption for this destination. Data will still be encrypted
    /// during transmission.
    NoEncryption,

    /// Data will be signed to protect it from remote modification, but will
    /// still be readable by the target.
    Immutable(SignatureConfig),

    /// Data will be encrypted and signed, but metadata will only be signed, not
    /// encrypted.
    DataSecure(SignatureConfig, EncryptionConfig),

    /// Both data and metadata will be encrypted with the remote's key to
    /// protect it from reads and signed to prevent modification.
    FullySecure(SignatureConfig, EncryptionConfig)
}

pub struct TargetOptions {
    /// whether data on this destination should be replicated elsewhere
    pub reliable: bool,

    /// encryption settings for data stored on this target
    pub crypto: CryptoMode,

    /// the relative costs of data upload and download for this target
    pub upload_cost: f32,
    pub download_cost: f32,

    /// whether keystore should be mirrored on this destination
    pub mirror_global_keys: bool
}

pub struct BackupTarget {
    pub name: String,
    pub url: Url,
    pub user: Option<String>,
    pub password: Option<String>,
    pub key: Option<PathBuf>,
    pub options: TargetOptions
}

pub struct TargetGroup {
    pub name: String,
    pub members: Vec<String>
}

pub struct Config {
    /// Where the config is stored
    pub location: PathBuf,

    /// The set of available backup targets
    pub targets: Vec<BackupTarget>,
    /// Backup target groups
    pub target_groups: Vec<TargetGroup>
}

pub enum ConfigErr {
    ParseError()
    IOError(std::io::Error)
}

impl Config {
    pub fn load(pth: &Path) -> Result<Config, ConfigErr> {
        File 
    }

    pub fn save()

    pub fn find_target(&self, name: &str) -> Option<BackupTarget> {
    }

    pub fn find_group(&self, name: &str) -> Option<TargetGroup> {
    }
}
