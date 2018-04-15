use std::error::Error;

use clap::ArgMatches;
use crossterm::crossterm_style::{paint, Color};

use config;
use saml2aws::Saml2Aws;

pub fn command(matches: &ArgMatches) {
    let group = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa").unwrap();
    let cfg = config::load_or_default().unwrap();

    let group = match cfg.groups.get(group) {
        Some(g) => g,
        None => {
            println!(
                "\nCould not refresh credentials for {}:\n\n\t{}\n",
                paint(group).with(Color::Yellow),
                paint("The specified group does not exist.").with(Color::Red)
            );
            return;
        }
    };

    let s = Saml2Aws::new();
    let mut errors = vec![];

    for account in &group.accounts {
        print!("Refreshing {}\t", paint(&account.name).with(Color::Yellow));

        match s.login(&account.arn, &account.name, &mfa) {
            Ok(_) => {
                print!("{}", paint("SUCCESS").with(Color::Green));
            }
            Err(e) => {
                errors.push(e);
                print!("{}", paint("FAIL").with(Color::Red));
            }
        }
        print!("\n");
    }

    if errors.len() > 0 {
        println!("\nErrors:");

        for error in &errors {
            println!("\t{}", paint(error.description()).with(Color::Red));
        }
    }
}
