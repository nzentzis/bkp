use url::Url;
use std::path::{PathBuf,Path};
use std::fs::File;
use std::io::{Read,Write};
use std::io;
use pest::*;
use pest;

/// Configuration and options for asymmetric signature algorithms
#[derive(Debug)]
pub struct SignatureConfig {
    /// Name of the asymmetric key to use
    key: String
}

/// Configuration and options for symmetric data-protection algorithms
#[derive(Debug)]
pub struct EncryptionConfig {
    /// Name of the symmetric key to use
    key: String
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct TargetOptions {
    /// whether data on this destination needs replicated elsewhere
    pub reliable: bool,

    /// encryption settings for data stored on this target
    pub crypto: CryptoMode,

    /// the relative costs of data upload and download for this target
    pub upload_cost: i32,
    pub download_cost: i32,

    /// whether keystore should be mirrored on this destination
    pub mirror_global_keys: bool
}

#[derive(Debug)]
pub struct BackupTarget {
    pub name: String,
    pub url: Url,
    pub user: Option<String>,
    pub password: Option<String>,
    pub key: Option<PathBuf>,
    pub options: TargetOptions
}

#[derive(Debug)]
pub struct TargetGroup {
    pub name: String,
    pub members: Vec<String>
}

#[derive(Debug)]
pub struct Config {
    /// Where the config is stored
    pub location: PathBuf,

    /// The set of available backup targets
    pub targets: Vec<BackupTarget>,
    /// Backup target groups
    pub target_groups: Vec<TargetGroup>
}

#[derive(Debug)]
pub enum ConfigErr {
    ParseError(String),
    IOError(io::Error)
}

impl From<io::Error> for ConfigErr {
    fn from(e: io::Error) -> Self { ConfigErr::IOError(e) }
}

#[derive(Debug)]
pub enum TargetEntry {
    ObjUrl(Url),
    User(String),
    Password(String),
    Key(PathBuf),
    Reliable(bool),
    Crypto(CryptoMode),
    UploadCost(i32),
    DownloadCost(i32),
    MirrorKeys(bool)
}

// set up the parser and run it
impl_rdp! {
    grammar! {
        whitespace = _{[" "] | ["\t"]}
        nl = _{(["#"] ~ (!["\n"] ~ any)*)? ~ ["\n"]}
        open = {["{"] ~ nl}
        close = {["}"] ~ nl?}
        eq = _{["="]}
        string_escape = {["\\"] ~ (["\""] | ["\\"])}
        string = @{["\""] ~ ((!(["\\"] | ["\""]) ~ any) | string_escape)* ~ ["\""]}
        boolean = @{ ["true"] | ["false"] }
        integer = @{ ['0'..'9']+ }

        target_name = @{(['a'..'z'] | ['A' .. 'z'] | ["-"])+}
        key_name = @{(['a'..'z'] | ['A' .. 'z'] | ["-"])+}

        par_tgt_name = _{["("] ~ target_name ~ [")"]}
        url = { ["url"] ~ eq ~ string ~ nl}
        user = { ["user"] ~ eq ~ string ~ nl}
        password = { ["password"] ~ eq ~ string ~ nl}
        key = { ["key-file"] ~ eq ~ string ~ nl}
        reliable = { ["reliable"] ~ eq ~ boolean ~ nl}
        upload_cost = { ["upload-cost"] ~ eq ~ integer ~ nl}
        download_cost = { ["download-cost"] ~ eq ~ integer ~ nl}
        mirror_keys = { ["mirror-global-keys"] ~ eq ~ boolean ~ nl}
        signature_cfg = { ["signature"] ~ ["{"] ~ ["key"] ~ eq ~ key_name ~ ["}"]}
        symmetric_cfg = { ["symmetric"] ~ ["{"] ~ ["key"] ~ eq ~ key_name ~ ["}"]}
        both_cfg = _{(signature_cfg ~ nl? ~ symmetric_cfg) | (symmetric_cfg ~ nl? ~ signature_cfg)}
        crypto_none = {["none"]}
        crypto_immut = {["immutable"] ~ ["{"] ~ nl? ~ signature_cfg ~ nl? ~ ["}"]}
        crypto_datasec = {["data-secure"] ~ ["{"] ~ nl? ~ both_cfg ~ nl? ~ ["}"]}
        crypto_secure = {["secure"] ~ ["{"] ~ nl? ~ both_cfg ~ nl? ~ ["}"]}
        crypto_val = _{crypto_none | crypto_immut | crypto_datasec | crypto_secure}
        crypto = {["security"] ~ eq ~ crypto_val ~ nl}
        option = _{ reliable | upload_cost | download_cost | mirror_keys}
        target = { ["target"] ~ par_tgt_name ~ open ~
                (url | user | password | key | option | crypto)+ ~
            close}
        target_group = {
            ["target-group"] ~ ["("] ~ target_name ~ [")"] ~ open ~
                target_name+ ~
            close}
        conf_eoi = {eoi}
        config = { soi ~ ( target | target_group )* ~ conf_eoi }
    }

    process! {
        _string(&self) -> String {
            (&s: string) => { String::from(&s[1..s.len()-1]) }
        }
        _bool(&self) -> bool { (&b: boolean) => (b == "true") }
        _integer(&self) -> i32 {
            (&x: integer) => x.parse::<i32>().unwrap() }
        _crypto_both(&self) -> (SignatureConfig, EncryptionConfig) {
            (_: signature_cfg, &sk: key_name, _: symmetric_cfg, &mk: key_name) =>
                (SignatureConfig{key: String::from(sk)},
                 EncryptionConfig{key: String::from(mk)}),
            (_: symmetric_cfg, &mk: key_name, _: signature_cfg, &sk: key_name) =>
                (SignatureConfig{key: String::from(sk)},
                 EncryptionConfig{key: String::from(mk)}),
        }
        _crypto_info(&self) -> Result<CryptoMode, String> {
            (_: crypto_none) => Ok(CryptoMode::NoEncryption),
            (_: crypto_immut, _: signature_cfg, &k: key_name) =>
                Ok(CryptoMode::Immutable(SignatureConfig { key: String::from(k) })),
            (_: crypto_datasec, b: _crypto_both()) => Ok(CryptoMode::DataSecure(b.0, b.1)),
            (_: crypto_secure, b: _crypto_both()) => Ok(CryptoMode::FullySecure(b.0, b.1))
        }
        _tgt_entry(&self) -> Result<TargetEntry, String> {
            (_: url, s: _string()) =>
                Ok(TargetEntry::ObjUrl(Url::parse(&s).unwrap())),
            (_: user, s: _string()) => Ok(TargetEntry::User(s)),
            (_: password, s: _string()) => Ok(TargetEntry::Password(s)),
            (_: key, s: _string()) => Ok(TargetEntry::Key(PathBuf::from(s))),
            (_: reliable, b: _bool()) => Ok(TargetEntry::Reliable(b)),
            (_: crypto, c: _crypto_info()) => { c.map(TargetEntry::Crypto) },
            (_: upload_cost, n: _integer()) => {
                Ok(TargetEntry::UploadCost(n)) },
            (_: download_cost, n: _integer()) => {
                Ok(TargetEntry::DownloadCost(n)) },
            (_: mirror_keys, x: _bool()) => {
                Ok(TargetEntry::MirrorKeys(x)) }
        }
        _target_entries(&self) -> Result<Vec<TargetEntry>, String> {
            (e: _tgt_entry(), _: close) => {
                let mut xs = Vec::new();
                match e {
                    Ok(x) => { xs.push(x); Ok(xs) }
                    Err(e) => Err(e)
                }
            },
            (e: _tgt_entry(), rest: _target_entries()) =>
                match e {
                    Ok(e) => { rest.map(|mut r| { r.push(e); r }) }
                    Err(e) => Err(e)
                }
        }
        _target(&self) -> Result<BackupTarget, String> {
            (_: target, &n: target_name, _: open, body: _target_entries()) => {
                // check entries
                let mut url = None;
                let mut user = None;
                let mut password = None;
                let mut key = None;
                let mut reliable = None;
                let mut crypto = None;
                let mut upload = None;
                let mut download = None;
                let mut mirror = None;

                if body.is_err() { return Err(body.unwrap_err()); }

                for i in body.unwrap() {
                    match i {
                        TargetEntry::ObjUrl(u) => {
                            if url.is_some() {
                                return Err(String::from("Duplicate URL found")); }
                            else { url = Some(u) } }
                        TargetEntry::User(u) => {
                            if user.is_some() {
                                return Err(String::from("Duplicate user found")); }
                            else { user = Some(u) } }
                        TargetEntry::Password(p) => {
                            if password.is_some() {
                                return Err(String::from("Duplicate password found")); }
                            else { password = Some(p) } }
                        TargetEntry::Key(p) => {
                            if key.is_some() {
                                return Err(String::from("Duplicate key found")); }
                            else { key = Some(p) } }
                        TargetEntry::Reliable(x) => {
                            if reliable.is_some() {
                                return Err(String::from("Duplicate reliable found")); }
                            else { reliable = Some(x) } }
                        TargetEntry::Crypto(c) => {
                            if crypto.is_some() {
                                return Err(String::from("Duplicate crypto found")); }
                            else { crypto = Some(c) } }
                        TargetEntry::UploadCost(x) => {
                            if upload.is_some() {
                                return Err(String::from("Duplicate upload-cost found")); }
                            else { upload = Some(x) } }
                        TargetEntry::DownloadCost(x) => {
                            if download.is_some() {
                                return Err(String::from("Duplicate download-cost found")); }
                            else { download = Some(x) } }
                        TargetEntry::MirrorKeys(x) => {
                            if mirror.is_some() {
                                return Err(String::from("Duplicate mirror-keys found")); }
                            else { mirror = Some(x) } }
                    }
                }

                if url.is_none() {
                    return Err(String::from("Target group must contain URL")); }
                if crypto.is_none() {
                    return Err(String::from("Target group must set crypto mode")); }

                Ok(BackupTarget {
                    name: String::from(n),
                    url: url.unwrap(),
                    user: user, password: password, key: key,
                    options: TargetOptions {
                        reliable: reliable.unwrap_or(false),
                        crypto: crypto.unwrap(),
                        upload_cost: upload.unwrap_or(1) as i32,
                        download_cost: download.unwrap_or(1) as i32,
                        mirror_global_keys: mirror.unwrap_or(true)}})
            }
        }
        _targets(&self) -> Vec<String> {
            (&n: target_name, _: close) => {
                let mut v = Vec::new();
                v.push(String::from(n));
                v
            },
            (&n: target_name, mut rest: _targets()) => {
                rest.push(String::from(n));
                rest
            }
        }
        _target_group(&self) -> TargetGroup {
            (_: target_group, &nm: target_name, _: open, body: _targets()) => {
                TargetGroup { name: String::from(nm), members: body }}}
        _config_body(&self) -> Result<(Vec<BackupTarget>, Vec<TargetGroup>), String> {
            (_: conf_eoi) => Ok((Vec::new(), Vec::new())),
            (tgt: _target(), rest: _config_body()) =>
                match tgt {
                    Err(s) => Err(s),
                    Ok(t) => rest.map(|mut r| {r.0.push(t); r})
                },
            (grp: _target_group(), rest: _config_body()) =>
                rest.and_then(|mut r| {r.1.push(grp); Ok(r)})
        }
        _config(&self) -> Result<Config, String> {
            (_: config, body: _config_body()) => {
                body.map(|(tgts, grps)| Config {
                    location: PathBuf::new(),
                    targets: tgts,
                    target_groups: grps })
            }
        }
    }
}

impl BackupTarget {
    fn save(&self, f: &mut File) -> io::Result<()> {
        writeln!(f, "target({}) {{", self.name)?;
        writeln!(f, "\turl = \"{}\"", self.url)?;
        if let Some(ref u) = self.user { writeln!(f, "\tuser = \"{}\"", u)?; }
        if let Some(ref p) = self.password {writeln!(f, "\tpassword = \"{}\"", p)?;}
        if let Some(ref k) = self.key {writeln!(f, "\tkey = \"{}\"", k.display())?;}
        if self.options.reliable { writeln!(f, "\treliable = true")?; }
        if !self.options.mirror_global_keys { writeln!(f, "\tmirror-global-keys = false")?; }
        writeln!(f, "\tupload-cost = {}", self.options.upload_cost)?;
        writeln!(f, "\tdownload-cost = {}", self.options.download_cost)?;
        write!(f, "\tsecurity = ")?;

        match self.options.crypto {
            CryptoMode::NoEncryption => {
                writeln!(f, "none")?;
            }
            CryptoMode::Immutable(ref sig) => {
                writeln!(f, "immutable {{")?;
                writeln!(f, "\t\tsignature {{ key = {} }}", sig.key)?;
                writeln!(f, "\t}}")?;
            }
            CryptoMode::DataSecure(ref sig,ref symm) => {
                writeln!(f, "data-secure {{")?;
                writeln!(f, "\t\tsignature {{ key = {} }}", sig.key)?;
                writeln!(f, "\t\tsymmetric {{ key = {} }}", symm.key)?;
                writeln!(f, "\t}}")?;
            }
            CryptoMode::FullySecure(ref sig,ref symm) => {
                writeln!(f, "secure {{")?;
                writeln!(f, "\t\tsignature {{ key = {} }}", sig.key)?;
                writeln!(f, "\t\tsymmetric {{ key = {} }}", symm.key)?;
                writeln!(f, "\t}}")?;
            }
        }
        Ok(())
    }
}

impl TargetGroup {
    fn save(&self, f: &mut File) -> io::Result<()> {
        writeln!(f, "target-group({}) {{", self.name)?;
        for m in self.members.iter() { writeln!(f, "\t{}", m)?; }
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl Config {
    pub fn load(pth: &Path) -> Result<Config, ConfigErr> {
        let mut file = File::open(pth)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;

        let mut parse = Rdp::new(pest::StringInput::new(&data));

        if !parse.config() {
            return Err(ConfigErr::ParseError(
                    String::from("Cannot parse input file")));
        }
        let mut cfg = parse._config().map_err(|e| ConfigErr::ParseError(e))?;
        cfg.location = PathBuf::from(pth);

        Ok(cfg)
    }

    pub fn save(&self) -> io::Result<()> {
        let mut file = File::create(&self.location)?;
        for t in self.targets.iter() { t.save(&mut file)?; }
        for t in self.target_groups.iter() { t.save(&mut file)?; }
        Ok(())
    }

    pub fn find_target(&self, name: &str) -> Option<&BackupTarget> {
        self.targets.iter().find(|ref t| t.name == name)
    }

    pub fn find_group(&self, name: &str) -> Option<&TargetGroup> {
        self.target_groups.iter().find(|ref t| t.name == name)
    }
}
