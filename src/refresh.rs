use std::error::Error;
use std::io;

use clap::ArgMatches;
use crossterm::crossterm_style::{paint, Color};

use chrono::prelude::*;

use config;
use saml2aws::Saml2Aws;

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(matches: &ArgMatches) {
    let group_name = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa");
    let password = matches.value_of("password");
    let mut cfg = config::load_or_default().unwrap();

    {
        let group = match cfg.groups.get_mut(group_name) {
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

        let mfa = match group.accounts.iter().all(|a| a.session_valid()) {
            true => "000000".into(),
            false => match mfa {
                Some(m) => m.into(),
                None => {
                    let mut buf = String::new();

                    print!("{} {}", paint("?").with(Color::Green), paint("MFA Token: "));

                    if let Err(_) = io::stdin().read_line(&mut buf) {
                        println!(
                            "\nCould not refresh credentaisl for {}:\n\n\t{}\n",
                            paint(group_name).with(Color::Yellow),
                            paint("No MFA Token provided").with(Color::Red)
                        );
                        return;
                    }

                    buf
                }
            },
        };

        let s = Saml2Aws::new(&mfa, password);
        let mut errors = vec![];

        for mut account in &mut group.accounts {
            if account.session_valid() {
                let now = Local::now();

                let expiration = account.valid_until.unwrap().signed_duration_since(now);
                println!(
                    "Refreshing {}\t{}",
                    paint(&account.name).with(Color::Yellow),
                    paint(&format!("valid for {} minutes", expiration.num_minutes()))
                        .with(Color::Green)
                );
                continue;
            }

            print!("Refreshing {}\t", paint(&account.name).with(Color::Yellow));

            match s.login(&account.arn, &account.name, group.session_duration) {
                Ok(expiration) => {
                    account.valid_until = Some(expiration);
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
            paint(&group.accounts[0].name).with(Color::Yellow)
        );
    }

    cfg.save().unwrap();
}
