extern crate chrono;
#[macro_use]
extern crate clap;
extern crate crossterm;
extern crate regex;
#[macro_use]
extern crate serde_derive;
extern crate serde_xml_rs;
extern crate serde_yaml;

extern crate base64;
extern crate cookie;
extern crate ini;
extern crate keyring;
extern crate reqwest;
extern crate scraper;

mod aws;
mod config;
mod groups;
mod keycloak;
mod refresh;
mod saml;

use clap::App;
use std::io;

fn main() {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml);
    let matches = app.get_matches();

    if let Some(_) = matches.subcommand_matches("version") {
        App::from_yaml(yaml)
            .write_long_version(&mut io::stdout())
            .unwrap();
        return;
    }

    let verbosity = matches.occurrences_of("verbose");

    config::check_or_interactive_create();

    if let Some(matches) = matches.subcommand_matches("groups") {
        groups::command(matches)
    } else if let Some(_) = matches.subcommand_matches("configure") {
        config::interactive_create()
    } else if let Some(matches) = matches.subcommand_matches("refresh") {
        refresh::command(matches, verbosity)
    }
}
