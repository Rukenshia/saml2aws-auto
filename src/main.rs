extern crate chrono;
#[macro_use]
extern crate clap;
extern crate crossterm;
extern crate regex;
#[macro_use]
extern crate serde_derive;
extern crate serde_xml_rs;
extern crate serde_yaml;

#[macro_use]
extern crate log;
extern crate fern;

extern crate base64;
extern crate cookie;
extern crate dirs;
extern crate ini;
extern crate keyring;
extern crate openssl_probe;
extern crate reqwest;
extern crate rpassword;
extern crate scraper;
extern crate url;

mod aws;
mod client;
mod config;
mod groups;
mod keycloak;
mod refresh;
mod saml;
mod update;

use std::io;

use clap::App;
use crossterm::{style, Color};
use log::LevelFilter;

fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml);
    let matches = app.get_matches();

    let level = match matches.occurrences_of("verbose") {
        1 => Some(LevelFilter::Error),
        2 => Some(LevelFilter::Warn),
        3 => Some(LevelFilter::Info),
        4 => Some(LevelFilter::Debug),
        5...999 => Some(LevelFilter::Trace),
        _ => None,
    };

    if let Some(level) = level {
        fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{}][{}] {}",
                    record.level(),
                    record.target(),
                    message
                ))
            })
            .level(LevelFilter::Off)
            .level_for("saml2aws_auto", level)
            .chain(std::io::stdout())
            .apply()
            .unwrap();
    }

    // Check for a new version
    if let Ok(update::VersionComparison::IsDifferent) =
        update::compare_version(yaml["version"].as_str().unwrap())
    {

        println!(
            "\n\t{}",
            style("A new version of saml2aws-auto is available")
                .with(Color::Green)
        );
        println!("\tIf you want to enjoy the greatest and latest features, make sure to update\n\tyour installation of saml2aws-auto.");
        println!("");
    };

    if let Some(_) = matches.subcommand_matches("version") {
        App::from_yaml(yaml)
            .write_long_version(&mut io::stdout())
            .unwrap();
        return;
    }

    if !config::check_or_interactive_create() {
        return;
    }

    if let Some(matches) = matches.subcommand_matches("groups") {
        groups::command(matches)
    } else if let Some(_) = matches.subcommand_matches("configure") {
        let cfg = config::load_or_default()
            .expect("Internal error when trying to read config. Please open an issue on GitHub.");
        config::interactive_create(cfg)
    } else if let Some(matches) = matches.subcommand_matches("refresh") {
        refresh::command(matches)
    }
}
