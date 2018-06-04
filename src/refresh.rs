use std::error::Error;
use std::io;

use clap::ArgMatches;
use crossterm::style::{paint, Color};

use chrono::prelude::*;
use std::str::FromStr;

use aws::assume_role::assume_role;
use aws::credentials::load_credentials_file;
use config::prompt;
use cookie::CookieJar;
use keycloak::login::get_assertion_response;
use keycloak::KeycloakErrorKind;
use saml::parse_assertion;

use config;

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(matches: &ArgMatches, verbosity: u64) {
    let mut cfg = config::load_or_default().unwrap();

    let group_name = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa");

    let cfg_username = cfg.username.as_ref().unwrap();
    let cfg_password = cfg.password.as_ref().unwrap();
    let username = matches.value_of("username").unwrap_or(&cfg_username);
    let password = matches.value_of("password").unwrap_or(&cfg_password);

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

                    prompt("MFA Token", Some("000000")).unwrap()
                }
            },
        };

        let mut errors: Vec<Box<Error>> = vec![];

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

            let (saml_response, _) = match get_assertion_response(
                &mut cookie_jar,
                &cfg.idp_url,
                username,
                password,
                &mfa.trim(),
                false,
            ) {
                Ok(r) => r,
                Err(e) => {
                    println!("{}", paint("FAIL").with(Color::Red));

                    if e.kind == KeycloakErrorKind::InvalidCredentials
                        || e.kind == KeycloakErrorKind::InvalidToken
                    {
                        println!(
                            "\n{} Cannot recover from error:\n\n\t{}\n",
                            paint("!").with(Color::Red),
                            paint(e.description()).with(Color::Red)
                        );
                        return;
                    }

                    errors.push(Box::new(e));
                    continue;
                }
            };

            if verbosity > 0 {
                println!(
                    "\n{} got saml response, finding principal next",
                    debug_prefix
                );
            }

            let assertion = match parse_assertion(&saml_response) {
                Ok(a) => a,
                Err(e) => {
                    errors.push(Box::new(e));
                    continue;
                }
            };

            let principal = match assertion
                .roles
                .into_iter()
                .find(|r| r.arn == account.arn)
                .map(|r| r.principal_arn)
            {
                Some(r) => r,
                None => {
                    errors.push(Box::new(io::Error::new(
                        io::ErrorKind::NotFound,
                        "Principal not found. Are you sure you have access to this account?",
                    )));
                    continue;
                }
            };

            match assume_role(
                &account.arn,
                &principal,
                &saml_response,
                group.session_duration.or(Some(assertion.session_duration)),
            ) {
                Ok(res) => {
                    println!("{}", paint("SUCCESS").with(Color::Green));

                    if verbosity > 0 {
                        println!(
                            "{} assumed role. AccessKeyID: {}",
                            debug_prefix,
                            res.credentials.as_ref().unwrap().access_key_id
                        );
                    }

                    let (mut credentials, filepath) = load_credentials_file().unwrap();
                    let aws_credentials = &res.credentials.as_ref().unwrap();

                    credentials
                        .with_section(Some(account.name.as_str()))
                        .set("aws_access_key_id", aws_credentials.access_key_id.as_str())
                        .set(
                            "aws_secret_access_key",
                            aws_credentials.secret_access_key.as_str(),
                        )
                        .set("aws_session_token", aws_credentials.session_token.as_str())
                        .set("expiration", aws_credentials.expiration.as_str());

                    credentials.write_to_file(filepath).unwrap();

                    account.valid_until =
                        Some(DateTime::from_str(aws_credentials.expiration.as_str()).unwrap());
                }
                Err(e) => {
                    println!("{}", paint("FAIL").with(Color::Red));

                    errors.push(Box::new(e));
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
