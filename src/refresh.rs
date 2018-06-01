use std::error::Error;
use std::io;

use clap::ArgMatches;
use crossterm::crossterm_style::{paint, Color};

use chrono::prelude::*;

use aws::assume_role::assume_role;
use cookie::CookieJar;
use keycloak::login::get_assertion_response;
use saml::parse_assertion;

use config;

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(matches: &ArgMatches, verbosity: u64) {
    let group_name = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa");
    let username = matches.value_of("username");
    let password = matches.value_of("password");

    let mut cfg = config::load_or_default().unwrap();

    let debug_prefix = paint("DEBU").with(Color::Cyan);

    {
        let group = match cfg.groups.get_mut(group_name) {
            Some(g) => g,
            None => {
                if verbosity > 0 {
                    println!(
                        "{} match cfg.groups.get_mut(group_name) => None",
                        debug_prefix
                    );
                }

                println!(
                    "\nCould not refresh credentials for {}:\n\n\t{}\n",
                    paint(group_name).with(Color::Yellow),
                    paint("The specified group does not exist.").with(Color::Red)
                );
                return;
            }
        };

        if group.accounts.len() == 0 {
            if verbosity > 0 {
                println!("{} group.accounts len is 0", debug_prefix);
            }
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
                    if verbosity > 0 {
                        println!("{} mfa flag not set, no valid session", debug_prefix);
                    }
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

        let mut errors = vec![];

        let mut cookie_jar = CookieJar::new();

        for mut account in &mut group.accounts {
            if account.session_valid() {
                if verbosity > 0 {
                    println!("{} session still valid", debug_prefix);
                }

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

            let (saml_response, aws_web_response) = match get_assertion_response(
                &mut cookie_jar,
                &cfg.idp_url,
                username.unwrap(),
                password.unwrap(),
                &mfa.trim(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    println!("{}", paint("FAIL").with(Color::Red));

                    errors.push(e);
                    continue;
                }
            };

            if verbosity > 0 {
                println!("{} got saml response, finding principal next", debug_prefix);
            }

            let assertion = parse_assertion(&saml_response).unwrap();

            let principal = assertion
                .roles
                .into_iter()
                .find(|r| r.arn == account.arn)
                .map(|r| r.principal_arn)
                .unwrap();

            match assume_role(
                &account.arn,
                &principal,
                &saml_response,
                group.session_duration,
            ) {
                Ok(res) => {
                    println!("{}", paint("SUCCESS").with(Color::Green));

                    if verbosity > 0 {
                        println!(
                            "{} assumed role. AccessKeyID: {}",
                            debug_prefix,
                            res.credentials.unwrap().access_key_id
                        );
                    }
                }
                Err(e) => {
                    println!("{}", paint("FAIL").with(Color::Red));

                    errors.push(io::Error::new(io::ErrorKind::Other, e.description()));
                    continue;
                }
            };
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
