use std::error::Error;

use clap::ArgMatches;
use crossterm::crossterm_style::{paint, Color};

use config;
use saml2aws::Saml2Aws;

pub fn command(matches: &ArgMatches) {
    let group_name = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa").unwrap();
    let cfg = config::load_or_default().unwrap();

    let group = match cfg.groups.get(group_name) {
        Some(g) => g,
        None => {
            println!(
                "\nCould not refresh credentials for {}:\n\n\t{}\n",
                paint(group_name).with(Color::Yellow),
                paint("The specified group does not exist.").with(Color::Red)
            );
            return;
        }
    };

    if group.accounts.len() == 0 {
        println!(
            "Nothing to refresh. Group {} is empty.",
            paint(group_name).with(Color::Yellow)
        );
        return;
    }

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

        return;
    }

    println!("\nRefreshed group {}. To use them in the AWS cli, apply the --profile flag with the name of the account.", paint(group_name).with(Color::Yellow));
    println!(
        "\nExample:\n\n\taws --profile {} s3 ls\n",
        paint(&group.accounts[0].name).with(Color::Yellow).bold()
    );
}
