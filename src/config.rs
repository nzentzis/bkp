extern crate hostname;

use url::Url;
use std::path::{PathBuf,Path};
use std::fs::File;
use std::io::{Read,Write};
use std::io;
use std::env;
use pest::*;
use pest;

#[derive(Debug)]
pub struct TargetOptions {
    /// whether data on this destination needs replicated elsewhere
    pub reliable: bool,

    /// the relative costs of data upload and download for this target
    pub upload_cost: i32,
    pub download_cost: i32,
}

#[derive(Debug)]
pub struct BackupTarget {
    pub name: String,
    pub url: Url,
    pub user: Option<String>,
    pub password: Option<String>,
    pub key_file: Option<PathBuf>,
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
    pub target_groups: Vec<TargetGroup>,

    /// The current node's name
    pub node_name: String
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
    KeyFile(PathBuf),
    Reliable(bool),
    UploadCost(i32),
    DownloadCost(i32),
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

        par_tgt_name = _{["("] ~ target_name ~ [")"]}
        url = { ["url"] ~ eq ~ string ~ nl}
        user = { ["user"] ~ eq ~ string ~ nl}
        password = { ["password"] ~ eq ~ string ~ nl}
        key_file = { ["key-file"] ~ eq ~ string ~ nl}
        reliable = { ["reliable"] ~ eq ~ boolean ~ nl}
        upload_cost = { ["upload-cost"] ~ eq ~ integer ~ nl}
        download_cost = { ["download-cost"] ~ eq ~ integer ~ nl}
        option = _{ reliable | upload_cost | download_cost}
        target = { ["target"] ~ par_tgt_name ~ open ~
                (url | user | password | key_file | option)+ ~
            close}
        target_group = {
            ["target-group"] ~ ["("] ~ target_name ~ [")"] ~ open ~
                target_name+ ~
            close}
        node_name = { ["node-name"] ~ eq ~ target_name ~ nl? }
        conf_eoi = {eoi}
        config = { soi ~ ( node_name | target | target_group )* ~ conf_eoi }
    }

    process! {
        _string(&self) -> String {
            (&s: string) => { String::from(&s[1..s.len()-1]) }
        }
        _bool(&self) -> bool { (&b: boolean) => (b == "true") }
        _integer(&self) -> i32 {
            (&x: integer) => x.parse::<i32>().unwrap() }
        _tgt_entry(&self) -> Result<TargetEntry, String> {
            (_: url, s: _string()) =>
                Ok(TargetEntry::ObjUrl(Url::parse(&s).unwrap())),
            (_: user, s: _string()) => Ok(TargetEntry::User(s)),
            (_: password, s: _string()) => Ok(TargetEntry::Password(s)),
            (_: key_file, s: _string()) =>
                Ok(TargetEntry::KeyFile(PathBuf::from(s))),
            (_: reliable, b: _bool()) => Ok(TargetEntry::Reliable(b)),
            (_: upload_cost, n: _integer()) => {
                Ok(TargetEntry::UploadCost(n)) },
            (_: download_cost, n: _integer()) => {
                Ok(TargetEntry::DownloadCost(n)) },
        }
        _node_name(&self) -> String {
            (&n: target_name) => { String::from(n) } }
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
            (&n: target_name, _: open, body: _target_entries()) => {
                // check entries
                let mut url = None;
                let mut user = None;
                let mut password = None;
                let mut key_file = None;
                let mut reliable = None;
                let mut upload = None;
                let mut download = None;

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
                                return Err(String::from("Duplicate password found"));
                            } else { password = Some(p) } }
                        TargetEntry::KeyFile(p) => {
                            if key_file.is_some() {
                                return Err(String::from("Duplicate keyfile found"));
                            } else { key_file = Some(p) } }
                        TargetEntry::Reliable(x) => {
                            if reliable.is_some() {
                                return Err(String::from("Duplicate reliable found"));
                            } else { reliable = Some(x) } }
                        TargetEntry::UploadCost(x) => {
                            if upload.is_some() {
                                return Err(String::from("Duplicate upload-cost found")); }
                            else { upload = Some(x) } }
                        TargetEntry::DownloadCost(x) => {
                            if download.is_some() {
                                return Err(String::from("Duplicate download-cost found")); }
                            else { download = Some(x) } }
                    }
                }

                if url.is_none() {
                    return Err(String::from("Target group must contain URL")); }

                Ok(BackupTarget {
                    name: String::from(n),
                    url: url.unwrap(),
                    user: user, password: password,
                    key_file: key_file,
                    options: TargetOptions {
                        reliable: reliable.unwrap_or(false),
                        upload_cost: upload.unwrap_or(1) as i32,
                        download_cost: download.unwrap_or(1) as i32}})
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
        _config_body(&self) -> Result<(Option<String>, Vec<BackupTarget>, Vec<TargetGroup>), String> {
            (_: conf_eoi) => Ok((None, Vec::new(), Vec::new())),
            (_: node_name, n: _node_name(), rest: _config_body()) =>
                rest.and_then(|mut r| {
                    if r.0.is_some() {
                        Err(String::from("Found duplicate node name"))
                    } else {
                        r.0 = Some(n);
                        Ok(r)
                    }
                }),
            (_: target, tgt: _target(), rest: _config_body()) =>
                match tgt {
                    Err(s) => Err(s),
                    Ok(t) => rest.map(|mut r| {r.1.push(t); r})
                },
            (grp: _target_group(), rest: _config_body()) =>
                rest.and_then(|mut r| {r.2.push(grp); Ok(r)})
        }
        _config(&self) -> Result<Config, String> {
            (_: config, body: _config_body()) => {
                body.and_then(|(nm, tgts, grps)|
                    if let Some(nm) = nm {
                        Ok(Config {
                            node_name: nm,
                            location: PathBuf::new(),
                            targets: tgts,
                            target_groups: grps
                        })
                    } else {
                        Err(String::from("No node name specified"))
                    })
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
        if self.options.reliable { writeln!(f, "\treliable = true")?; }
        writeln!(f, "\tupload-cost = {}", self.options.upload_cost)?;
        writeln!(f, "\tdownload-cost = {}", self.options.download_cost)?;
        write!(f, "}}")?;
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
        writeln!(file, "node-name = {}", self.node_name)?;
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

impl Default for Config {
    fn default() -> Self {
        Config {
            location: env::home_dir().unwrap().join(".bkprc"),
            targets: Vec::new(),
            target_groups: Vec::new(),
            node_name: self::hostname::get_hostname().unwrap()
        }
    }
}
