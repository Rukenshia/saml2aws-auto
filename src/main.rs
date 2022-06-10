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
extern crate tabled;
extern crate url;

mod aws;
pub mod client;
mod config;
mod groups;
mod keycloak;
mod refresh;
mod saml;
mod update;

use std::io;

use clap::App;
use crossterm::style::Stylize;
use log::LevelFilter;

fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml);
    let matches = app.get_matches();

    let level = match matches.occurrences_of("verbose") {
        0 => None,
        1 => Some(LevelFilter::Error),
        2 => Some(LevelFilter::Warn),
        3 => Some(LevelFilter::Info),
        4 => Some(LevelFilter::Debug),
        _ => Some(LevelFilter::Trace),
    };

    let config_path: String = match matches.value_of("config") {
        Some(s) => s.to_owned(),
        None => config::default_filename(),
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
    if let Ok(update::VersionComparison::HasNewer) =
        update::compare_version(yaml["version"].as_str().unwrap())
    {
        println!(
            "\n\t{}",
            "A new version of saml2aws-auto is available".green()
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

    if !config::check_or_interactive_create(
        &config_path,
        matches.is_present("skip-password-manager"),
    ) {
        return;
    }

    let mut config = config::load_or_default(&config_path)
        .expect("Could not read config, please open an issue on GitHub");

    if let Some(_) = matches.subcommand_matches("configure") {
        config::interactive_create(config);
        return;
    }

    if let Some(matches) = matches.subcommand_matches("groups") {
        groups::command(&mut config, matches)
    } else if let Some(matches) = matches.subcommand_matches("refresh") {
        refresh::command(&mut config, matches)
    }
}
