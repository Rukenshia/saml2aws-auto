#[macro_use]
extern crate clap;
extern crate crossterm;
extern crate regex;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;

mod saml2aws;
mod groups;
mod config;

use clap::App;

fn main() {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml);
    let matches = app.get_matches();

    if let Some(matches) = matches.subcommand_matches("groups") {
        groups::command(matches)
    }
}
