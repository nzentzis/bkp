// required for pest
#![recursion_limit="128"]

mod config;
mod keys;
mod metadata;
mod remote;

extern crate ring;
extern crate untrusted;

#[macro_use]
extern crate pest;
#[macro_use]
extern crate clap;
extern crate url;

use url::Url;
use std::io::Write;
use std::error::Error;
use std::fs;
use std::path::{Path,PathBuf};

macro_rules! err_write {
    ($s: tt) => {
        writeln!(std::io::stderr(), $s).ok().unwrap_or(())};
    ($s: tt, $($e: expr),*) => {
        writeln!(std::io::stderr(), $s, $($e,)*).ok().unwrap_or(())}
}

struct GlobalOptions {
    data_dir: PathBuf,
    keystore: keys::Keystore,
    cfg: config::Config,
    verbose: bool,
    quiet: bool
}

fn fail_error<E: Error>(msg: &str, err: E) {
    writeln!(std::io::stderr(), "bkp: {}: {}", msg, err).unwrap();
    std::process::exit(1);
}

trait UnwrapOrFail<T> {
    /// Unwrap the result or fail with the given error message
    fn unwrap_or_fail(self, msg: &str) -> T;
}

impl<T, E: Error> UnwrapOrFail<T> for Result<T, E> {
    fn unwrap_or_fail(self, msg: &str) -> T {
        match self {
            Err(e) => {
                fail_error(msg, e);
                unreachable!()
            },
            Ok(x) => x
        }
    }
}

fn connect_backend(name: String, opts: &GlobalOptions)
        -> Result<Box<remote::Backend>, remote::BackendError> {
    use remote::BackendError;
    if let Some(t) = opts.cfg.find_target(&name) {
        remote::connect_tgt(t, &opts.cfg.node_name, &opts.keystore)
    } else if let Some(g) = opts.cfg.find_group(&name) {
        // bind names to actual targets
        let tgts = g.members.iter()
            .map(|ref n| opts.cfg.find_target(&n)
                                 .ok_or(BackendError::InvalidOption))

            .collect::<Result<Vec<&config::BackupTarget>, BackendError>>()?;

        // connect all of them
        remote::connect_group(tgts, &opts.cfg.node_name, &opts.keystore)
    } else {
        Err(BackendError::InvalidOption)
    }
}

fn do_dest(args: &clap::ArgMatches, opts: &mut GlobalOptions) {
    match args.subcommand() {
        ("add", Some(m)) => { // add a destination
            let name = m.value_of("name").unwrap();
            let url = m.value_of("url").unwrap();
            let user = m.value_of("user");
            let password = m.value_of("password");

            // make sure the specified destination doesn't already exist
            if opts.cfg.targets.iter().any(|t| {t.name == name}) {
                err_write!("bkp: Destination '{}' already exists", name);
                std::process::exit(1);
            }

            // parse the target URL
            let url = Url::parse(&url)
                .unwrap_or_fail("Cannot parse given URL");

            // build the new target
            let tgt = config::BackupTarget {
                name: name.to_owned(),
                url: url,
                user: user.map(String::from),
                password: password.map(String::from),
                key_file: None,
                options: config::TargetOptions {
                    reliable: true,
                    upload_cost: 1,
                    download_cost: 1
                }
            };
            opts.cfg.targets.push(tgt);
            opts.cfg.save().unwrap_or_fail("Failed to save config file");
        },
        ("list", Some(m)) => { // list destinations
            let max_left_col = opts.cfg.targets.iter()
                    .map(|ref x| x.name.len())
                    .max().unwrap_or(0);
            for t in opts.cfg.targets.iter() {
                println!("{1:0$}  {2}", max_left_col, t.name, t.url.as_str());
            }
        },
        ("remove", Some(m)) => { // remove destinations
            unimplemented!()
        },
        ("test", Some(m)) => { // test destination connectivity
            let mut has_errs = false;
            let max_col = m.values_of("name").unwrap()
                    .map(|ref x| x.len()).max().unwrap_or(0);
            for name in m.values_of("name").unwrap() {
                let tgt = connect_backend(name.to_owned(), &opts);
                match tgt {
                    Ok(_)  => println!("{1:0$}:   successful", max_col, name),
                    Err(e) => {
                        println!("{1:0$}:   {2}", max_col, name, e);
                        has_errs = true;
                    }
                }
            }

            if has_errs {
                std::process::exit(1);
            }
        },
        (_, _) => panic!("No subcommand handler found")
    }
}

fn do_test(args: &clap::ArgMatches, opts: &GlobalOptions) {
    //let profile = args.value_of("profile").unwrap();
    //let all = args.is_present("all");
    unimplemented!()
}

fn do_stat(args: &clap::ArgMatches, opts: &GlobalOptions) {
    unimplemented!()
}

fn do_clean(args: &clap::ArgMatches, opts: &GlobalOptions) {
    unimplemented!()
}

fn do_snap(args: &clap::ArgMatches, opts: &GlobalOptions) {
    unimplemented!()
}

fn do_restore(args: &clap::ArgMatches, opts: &GlobalOptions) {
    unimplemented!()
}

fn load_config(pth: &Path) -> config::Config {
    let cfg = config::Config::load(&pth);
    if let Err(e) = cfg {
        if let config::ConfigErr::IOError(ref err) = e {
            if err.kind() == std::io::ErrorKind::NotFound {
                err_write!("Creating new configuration file");

                // try to create a new config
                let cfg = config::Config::default();
                cfg.save().ok().unwrap_or(());
                return cfg
            }
        }
        let errstr = match e {
            config::ConfigErr::ParseError(x) => x,
            config::ConfigErr::IOError(x) => String::from(x.description())
        };
        writeln!(std::io::stderr(),
            "bkp: Cannot load config file: {}", errstr).unwrap();
        std::process::exit(1);
    }
    return cfg.unwrap();
} 

fn main() {
    let opt_matches = clap_app!(bkp =>
        (version: "0.1")
        (author: "Noah Zentzis <nzentzis@gmail.com>")
        (about: "Automated system backup utility")
        (@arg CONFIG: -c --config +takes_value "Specifies a config file to use")
        (@arg DATADIR: -D --data-dir +takes_value "Specify the local data path")
        (@arg BACKEND: -t --target +takes_value
         "Override the default destination")
        (@arg VERBOSE: -v --verbose "Enable verbose terminal output")
        (@arg QUIET: -q --quiet "Silence non-error terminal output")
        (@subcommand dest =>
         (about: "Query and modify available backup destinations")
         (@subcommand add =>
          (about: "Create a new destination")
          (@arg name: +required "The name of the new destination")
          (@arg url: +required {|s| {Url::parse(&s).map(|_| ())
              .map_err(|_| String::from("Not a valid URL"))}}
              "The new destination's URL" )
          (@arg user: -u --user +takes_value "Set the associated username")
          (@arg password: -p --password +takes_value
           "Set the associated password"))
         (@subcommand list =>
          (about: "List the available destinations")
          (@arg no_groups: -n --("no-groups")
           "Don't show grouped destinations"))
         (@subcommand remove =>
          (about: "Remove an existing destination")
          (@arg name: +required "The destination name to remove")
          (@arg scrub: -S --scrub "Remove existing backups from the target"))
         (@subcommand test =>
          (about: "Test connectivity to a destination")
          (@arg name: +required * "The destination to test")))
        (@subcommand test =>
         (about: "Test integrity of existing backups")
         (@arg profile: +takes_value
          possible_values(&["quick", "normal", "slow", "exhaustive"])
          default_value("normal")
          "The test profile to run")
         (@arg all: -a --all
          "Test backups from all machines rather than just this one"))
        (@subcommand stat =>
         (about: "Show backup statistics")
         (@arg dest: +takes_value ...
          "Only show data about the given destinations")
         (@arg remote: -r --remote
          "Query remote servers, bypassing local caches"))
        (@subcommand clean =>
         (about: "Remove backup data matching specific criteria. \
          All given predicates must match in order for data to be removed.")
         (@arg dest: +takes_value ...
          "Only remove data from the given destinations")
         (@arg dry_run: -n --("dry-run")
          "Don't remove anything, just show what would be done")
         (@group predicates =>
          (@attributes +multiple +required)
          (@arg snap_type: -t --type +takes_value
           possible_values(&["diff", "full"])
           "Match data in snapshots with type")
          (@arg older_than: -o --("older-than") +takes_value
           "Match data older than a certain age")
          (@arg newer_than: -N --("newer-than") +takes_value
           "Match data newer than a certain age")
          (@arg exists: -e --exists +takes_value
           possible_values(&["yes", "no"])
           "Match data based on whether it exists on the host")))
        (@subcommand snap =>
         (about: "Take a snapshot of local files")
         (@arg local: +takes_value ... "Files or directories to snapshot")
         (@arg no_trust_mtime: -T --("no-trust-mtime")
          "Use content hashes to check for file changes rather than FS's mtime"))
        (@subcommand restore =>
         (about: "Restore local files from backup")
         (@arg as_of: -t --time +takes_value
          "Restore to most recent snapshot before given date/time")
         (@arg overwrite: -o --overwrite +takes_value
          "Overwrite existing local files")
         (@arg from: -f --from +takes_value "Restore data from another machine")
         (@arg no_perms: -p --("no-perms")
          "Don't restore filesystem permissions")
         (@arg no_attrs: -a --("no-attrs") "Don't restore file metadata")
         (@arg into: -i --into conflicts_with[overwrite] +takes_value
          "Restore to a given path")
         (@arg local: +takes_value * ... "Files or directories to restore")
         )
        ).get_matches();

    // load a config file
    let config_path = opt_matches
        .value_of("CONFIG")
        .map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or(std::env::home_dir().unwrap().join(".bkprc"));
    let cfg = load_config(&config_path);

    // create the data dir if needed
    let data_dir = opt_matches.value_of("DATADIR").map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or(std::env::home_dir().unwrap().join(".bkp"));
    if let Err(e) = fs::metadata(&data_dir) {
        if e.kind() == std::io::ErrorKind::NotFound {
            if fs::create_dir(&data_dir).is_err() {
                writeln!(std::io::stderr(), "bkp: Cannot create directory: {}",
                    data_dir.display()).unwrap();
                std::process::exit(1);
            }
        } else {
            writeln!(std::io::stderr(), "bkp: Cannot access directory: {}",
                data_dir.display()).unwrap();
            std::process::exit(1);
        }
    }

    // open the key store
    let kspath = data_dir.join("keystore");
    let ks = match fs::metadata(&kspath) {
        Ok(_) => match keys::Keystore::open(&kspath) {
            Ok(k) => k,
            Err(e) => {
                err_write!("bkp: Cannot open keystore: {}", e.description());
                std::process::exit(1);
            }
        },
        Err(e) => if e.kind() == std::io::ErrorKind::NotFound {
            match keys::Keystore::create(&kspath) {
                Ok(k) => k,
                Err(e) => {
                    err_write!("bkp: Cannot create keystore: {}", e.description());
                    std::process::exit(1);
                }
            }
        } else {
            writeln!(std::io::stderr(), "bkp: Cannot access keystore: {}",
                kspath.display()).unwrap();
            std::process::exit(1);
        }
    };

    // parse global flags
    let mut global_flags = GlobalOptions {
        cfg: cfg,
        verbose: opt_matches.is_present("VERBOSE"),
        quiet: opt_matches.is_present("QUIET"),
        data_dir: data_dir,
        keystore: ks
    };

    // figure out what to do
    match opt_matches.subcommand() {
        ("", _) => { println!("bkp: No subcommand specified"); },
        ("dest", Some(m)) => do_dest(m, &mut global_flags),
        ("test", Some(m)) => do_test(m, &global_flags),
        ("stat", Some(m)) => do_stat(m, &global_flags),
        ("clean", Some(m)) => do_clean(m, &global_flags),
        ("snap", Some(m)) => do_snap(m, &global_flags),
        ("restore", Some(m)) => do_restore(m, &global_flags),
        (_, _) => panic!("No subcommand handler found!")
    }
}
