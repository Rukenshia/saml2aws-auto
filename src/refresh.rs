use std::error::Error;
use std::io;

use clap::ArgMatches;
use crossterm::style::Color;
use crossterm::Crossterm;

use chrono::prelude::*;
use std::str::FromStr;
use std::thread;
use std::collections::HashMap;

use aws::assume_role::assume_role;
use aws::credentials::load_credentials_file;
use aws::xml::Credentials;
use config::prompt;
use cookie::CookieJar;
use keycloak::login::get_assertion_response;
use keycloak::KeycloakErrorKind;
use saml::parse_assertion;

use config;

fn debug_log(msg: &str) {
    let crossterm = Crossterm::new();
    println!("{} {}", crossterm.paint("DEBU").with(Color::Cyan), msg);
}

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(matches: &ArgMatches, verbosity: u64) {
    let crossterm = Crossterm::new();
    let mut cfg = config::load_or_default().unwrap();

    let group_name = matches.value_of("GROUP").unwrap();
    let mfa = matches.value_of("mfa");
    let force = matches.is_present("force");

    let cfg_username = cfg.username.as_ref().unwrap();
    let cfg_password = cfg.password.as_ref().unwrap();
    let username = matches.value_of("username").unwrap_or(&cfg_username);
    let password = matches.value_of("password").unwrap_or(&cfg_password);

    {
        let group = match cfg.groups.get_mut(group_name) {
            Some(g) => g,
            None => {
                if verbosity > 0 {
                    debug_log("match cfg.groups.get_mut(group_name) => None");
                }

                println!(
                    "\nCould not refresh credentials for {}:\n\n\t{}\n",
                    crossterm.paint(group_name).with(Color::Yellow),
                    crossterm
                        .paint("The specified group does not exist.")
                        .with(Color::Red)
                );
                return;
            }
        };

        if group.accounts.len() == 0 {
            if verbosity > 0 {
                debug_log("group.accounts len is 0");
            }
            println!(
                "Nothing to refresh. Group {} is empty.",
                crossterm.paint(group_name).with(Color::Yellow)
            );
            return;
        }

        if group.accounts.iter().all(|a| a.session_valid()) && !force {
            println!(
                "Nothing to refresh. All accounts have valid sessions. Use --force to overwrite."
            );
            return;
        }

        let mfa = match mfa {
            Some(m) => m.into(),
            None => {
                if verbosity > 0 {
                    debug_log("mfa flag not set, no valid session");
                }

                prompt("MFA Token", Some("000000")).unwrap()
            }
        };

        let mut cookie_jar = CookieJar::new();

        {
            // Do an initial login to fill our cookie jar

            match get_assertion_response(
                &mut cookie_jar,
                &cfg.idp_url,
                username,
                password,
                &mfa.trim(),
                false,
            ) {
                Ok(r) => r,
                Err(e) => {
                    println!("Initial login {}", crossterm.paint("FAIL").with(Color::Red));

                    if e.kind == KeycloakErrorKind::InvalidCredentials
                        || e.kind == KeycloakErrorKind::InvalidToken
                        || e.kind == KeycloakErrorKind::PasswordUpdateRequired
                    {
                        println!(
                            "\n{} Cannot recover from error:\n\n\t{}\n",
                            crossterm.paint("!").with(Color::Red),
                            crossterm.paint(e.description()).with(Color::Red)
                        );
                    }

                    return;
                }
            };
            println!(
                "Initial login {}",
                crossterm.paint("SUCCESS").with(Color::Green)
            );
        }

        if verbosity > 0 {
            debug_log("looping through accounts");
        }

        let mut threads: Vec<
            thread::JoinHandle<Result<(RefreshAccountOutput, CookieJar), Box<Error + Send>>>,
        > = vec![];

        for account in &group.accounts {
            let mfa = mfa.clone();
            let password = format!("{}", password);
            let username = format!("{}", username);
            let idp_url = cfg.idp_url.clone();
            let session_duration = group.session_duration.clone();
            let cookie_jar = cookie_jar.clone();
            let account = account.clone();

            threads.push(thread::spawn(move || {
                return refresh_account(
                    session_duration,
                    &account,
                    cookie_jar,
                    &idp_url,
                    &username,
                    &password,
                    &mfa,
                    force,
                    verbosity,
                );
            }));
        }

        let mut accounts: HashMap<String, Option<DateTime<FixedOffset>>> = HashMap::new();

        let (mut credentials_file, filepath) = load_credentials_file().unwrap();

        for t in threads {
            match t.join() {
                Ok(res) => match res {
                    Ok((output, _)) => {
                        if let Some(credentials) = output.credentials {
                            credentials_file
                                .with_section(Some(output.account.name.as_str()))
                                .set("aws_access_key_id", credentials.access_key_id.as_str())
                                .set(
                                    "aws_secret_access_key",
                                    credentials.secret_access_key.as_str(),
                                )
                                .set("aws_session_token", credentials.session_token.as_str())
                                .set("expiration", credentials.expiration.as_str());
                        }
                        accounts.insert(output.account.arn, output.account.valid_until);
                    }
                    Err(e) => {
                        println!("\t{}", crossterm.paint(e.description()).with(Color::Red));
                    }
                },
                Err(e) => {
                    println!(
                        "\t{}",
                        crossterm
                            .paint(e.downcast_ref::<Box<Error>>().unwrap().description())
                            .with(Color::Red)
                    );
                }
            };
        }
        credentials_file.write_to_file(filepath).unwrap();

        // update valid_until fields
        for account in &mut group.accounts {
            if !accounts.contains_key(&account.arn) {
                continue
            }

            account.valid_until = *accounts.get(&account.arn).unwrap();
        }

        println!("\nRefreshed group {}. To use them in the AWS cli, apply the --profile flag with the name of the account.", crossterm.paint(group_name).with(Color::Yellow));
        println!(
            "\nExample:\n\n\taws --profile {} s3 ls\n",
            crossterm.paint(&group.accounts[0].name).with(Color::Yellow)
        );
    }

    cfg.save().unwrap();
}

#[derive(Debug)]
struct RefreshAccountOutput {
    pub account: config::Account,
    pub credentials: Option<Credentials>,
}

fn refresh_account(
    session_duration: Option<i64>,
    account: &config::Account,
    mut cookie_jar: CookieJar,
    idp_url: &str,
    username: &str,
    password: &str,
    mfa: &str,
    force: bool,
    verbosity: u64,
) -> Result<(RefreshAccountOutput, CookieJar), Box<Error + Send>> {
    let crossterm = Crossterm::new();

    if account.session_valid() && !force {
        if verbosity > 0 {
            debug_log("session still valid");
        }

        let now = Local::now();

        let expiration = account.valid_until.unwrap().signed_duration_since(now);
        println!(
            "Refreshing {}\t{}",
            crossterm.paint(&account.name).with(Color::Yellow),
            crossterm
                .paint(&format!("valid for {} minutes", expiration.num_minutes()))
                .with(Color::Green)
        );
        return Ok((
            RefreshAccountOutput {
                account: account.clone(),
                credentials: None,
            },
            cookie_jar,
        ));
    }

    if verbosity > 0 {
        println!("");
        debug_log(&format!("logging in at '{}'", idp_url));
    }

    let (saml_response, _) = match get_assertion_response(
        &mut cookie_jar,
        idp_url,
        username,
        password,
        &mfa.trim(),
        false,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "{} {}",
                account.name,
                crossterm.paint("FAIL").with(Color::Red)
            );

            if e.kind == KeycloakErrorKind::InvalidCredentials
                || e.kind == KeycloakErrorKind::InvalidToken
                || e.kind == KeycloakErrorKind::PasswordUpdateRequired
            {
                println!(
                    "\n{} Cannot recover from error:\n\n\t{}\n",
                    crossterm.paint("!").with(Color::Red),
                    crossterm.paint(e.description()).with(Color::Red)
                );
            }

            return Err(Box::new(e));
        }
    };

    if verbosity > 0 {
        debug_log("got saml response, finding principal next");
    }

    let assertion = match parse_assertion(&saml_response) {
        Ok(a) => a,
        Err(e) => {
            return Err(Box::new(e));
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
            return Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "Principal not found. Are you sure you have access to this account?",
            )));
        }
    };

    if verbosity > 0 {
        debug_log("making assume_role call");
    }

    match assume_role(
        &account.arn,
        &principal,
        &saml_response,
        session_duration.or(Some(assertion.session_duration)),
    ) {
        Ok(res) => {
            println!(
                "{} {}",
                account.name,
                crossterm.paint("SUCCESS").with(Color::Green)
            );

            if verbosity > 0 {
                debug_log(&format!("assumed role. AccessKeyID: {}", res.access_key_id));
            }

            let mut account = account.clone();
            account.valid_until = Some(DateTime::from_str(res.expiration.as_str()).unwrap());

            return Ok((
                RefreshAccountOutput {
                    account,
                    credentials: Some(res),
                },
                cookie_jar,
            ));
        }
        Err(e) => {
            println!(
                "{} {}",
                account.name,
                crossterm.paint("FAIL").with(Color::Red)
            );
            return Err(Box::new(e));
        }
    };
}
