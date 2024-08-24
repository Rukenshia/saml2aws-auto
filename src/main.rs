extern crate chrono;
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
extern crate itertools;
extern crate keyring;
extern crate openssl_probe;
extern crate reqwest;
extern crate rpassword;
extern crate scraper;
extern crate tabled;
extern crate url;

mod aws;
mod cli;
pub mod client;
mod config;
mod groups;
mod keycloak;
mod refresh;
mod saml;
mod update;

use clap::Parser;
use cli::Cli;
use crossterm::style::Stylize;
use log::LevelFilter;

fn main() {
    openssl_probe::init_ssl_cert_env_vars();

    let cli = Cli::parse();

    let level = match cli.verbose {
        false => None,
        true => Some(LevelFilter::Trace),
    };

    let config_path: String = match cli.config {
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
        update::compare_version(env!("CARGO_PKG_VERSION"))
    {
        println!(
            "\n\t{}",
            "A new version of saml2aws-auto is available".green()
        );
        println!("\tIf you want to enjoy the greatest and latest features, make sure to update\n\tyour installation of saml2aws-auto.");
        println!("");
    }

    if !config::check_or_interactive_create(&config_path, cli.skip_password_manager) {
        return;
    }

    match cli.command {
        cli::Commands::Configure => {
            config::interactive_create(config::Config::default(&config_path));
        }
        cli::Commands::Groups { command } => groups::command(
            &mut config::load_or_default(&config_path).unwrap(),
            &command,
        ),
        cli::Commands::Refresh(args) => {
            refresh::command(&mut config::load_or_default(&config_path).unwrap(), &args)
        }
        cli::Commands::Version => {
            println!("saml2aws-auto {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
