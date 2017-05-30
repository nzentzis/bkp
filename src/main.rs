// required for pest
#![recursion_limit="128"]

mod config;
mod keys;

#[macro_use]
extern crate pest;
#[macro_use]
extern crate clap;
extern crate url;

use url::Url;
use std::io::Write;
use std::error::Error;

struct GlobalOptions {
    cfg: config::Config,
    verbose: bool,
    quiet: bool
}

fn do_keys(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_dest(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_test(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_stat(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_clean(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_snap(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn do_restore(args: &clap::ArgMatches, opts: &GlobalOptions) {
}

fn main() {
    let opt_matches = clap_app!(bkp =>
        (version: "0.1")
        (author: "Noah Zentzis <nzentzis@gmail.com>")
        (about: "Automated system backup utility")
        (@arg CONFIG: -c --config +takes_value "Specifies a config file to use")
        (@arg BACKEND: -d --dest +takes_value
         "Override the default destination")
        (@arg VERBOSE: -v --verbose "Enable verbose terminal output")
        (@arg QUIET: -q --quiet "Silence non-error terminal output")
        (@subcommand keys =>
         (about: "Manipulate local or remote keystores")
         (@subcommand import =>
          (about: "Import keystore from an encrypted backup file")
          (@arg file: +required "Keystore file to import")
          (@arg overwrite: -o --overwrite "Allow overwriting local keystore"))
         (@subcommand export =>
          (about: "Export keystore to an encrypted backup file")
          (@arg file: +required "Filename of new backup file"))
         (@subcommand show =>
          (about: "Show local, remote, and backup keystores")
          (@arg from: "Filename of backup file or name of remote"))
         (@subcommand sync =>
          (about: "Sync local and remote copies of keystore")
          (@arg down_only: -d --down "Only sync from remote to local")
          (@arg up_only: -u --up "Only sync from local to remote")))
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
           "Set the associated password")
          (@arg key: -k --key +takes_value "Set the associated key file"))
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
          (@arg name: +required "The destination to test")))
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
         (@arg local: +takes_value ... "Files or directories to snapshot"))
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
    let config_path = std::path::PathBuf::from(
        opt_matches.value_of("CONFIG").unwrap_or("foo.cfg"));
    let cfg = config::Config::load(&config_path);
    if let Err(e) = cfg {
        let errstr = match e {
            config::ConfigErr::ParseError(x) => x,
            config::ConfigErr::IOError(x) => String::from(x.description()) };
        writeln!(std::io::stderr(), "bkp: Cannot load config file: {}", errstr);
        std::process::exit(1);
    }

    // parse global flags
    let mut global_flags = GlobalOptions {
        cfg: cfg.unwrap(),
        verbose: opt_matches.is_present("VERBOSE"),
        quiet: opt_matches.is_present("QUIET") };

    // figure out what to do
    match opt_matches.subcommand() {
        ("", _) => { println!("bkp: No subcommand specified"); },
        ("dest", Some(m)) => do_dest(m, &global_flags),
        ("keys", Some(m)) => do_keys(m, &global_flags),
        ("test", Some(m)) => do_test(m, &global_flags),
        ("stat", Some(m)) => do_stat(m, &global_flags),
        ("clean", Some(m)) => do_clean(m, &global_flags),
        ("snap", Some(m)) => do_snap(m, &global_flags),
        ("restore", Some(m)) => do_restore(m, &global_flags),
        (x, _) => panic!("No subcommand handler found!")
    }
}
