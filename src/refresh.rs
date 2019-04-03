use std::error::Error;

use clap::ArgMatches;
use crossterm::{style, Color};

use chrono::prelude::*;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::thread;

use aws::assume_role::assume_role;
use aws::credentials::load_credentials_file;
use aws::xml::Credentials;
use config::prompt;
use cookie::CookieJar;
use keycloak::login::get_assertion_response;
use keycloak::KeycloakErrorKind;
use saml::parse_assertion;

use config;

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(matches: &ArgMatches) {
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
                debug!("match cfg.groups.get_mut(group_name) => None");

                println!(
                    "\nCould not refresh credentials for {}:\n\n\t{}\n",
                    style(group_name).with(Color::Yellow),
                    style("The specified group does not exist.").with(Color::Red)
                );
                return;
            }
        };

        if group.accounts.len() == 0 {
            debug!("group.accounts len is 0");

            println!(
                "Nothing to refresh. Group {} is empty.",
                style(group_name).with(Color::Yellow)
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
                debug!("mfa flag not set, no valid session");

                prompt("MFA Token", Some("000000")).unwrap()
            }
        };

        let mut cookie_jar = CookieJar::new();

        {
            // Do an initial login to fill our cookie jar
            trace!("command.initial_login.before");
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
                    println!("Initial login {}", style("FAIL").with(Color::Red));

                    if e.kind == KeycloakErrorKind::InvalidCredentials
                        || e.kind == KeycloakErrorKind::InvalidToken
                        || e.kind == KeycloakErrorKind::PasswordUpdateRequired
                    {
                        println!(
                            "\n{} Cannot recover from error:\n\n\t{}\n",
                            style("!").with(Color::Red),
                            style(e.description()).with(Color::Red)
                        );
                    }

                    return;
                }
            };
            trace!("command.initial_login.success");
            println!("Initial login {}", style("SUCCESS").with(Color::Green));
        }

        trace!("command.cookie_jar={:?}", cookie_jar);

        trace!("command.looping_through_accounts");

        let mut threads: Vec<
            thread::JoinHandle<Result<(RefreshAccountOutput, CookieJar), RefreshError>>,
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

                        if output.renewed {
                            println!(
                                "{}\t{}",
                                output.account.name,
                                style("SUCCESS").with(Color::Green)
                            );
                        } else {
                            let now = Local::now();

                            let expiration = output
                                .account
                                .valid_until
                                .unwrap()
                                .signed_duration_since(now);
                            println!(
                                "{}\t{}",
                                output.account.name,
                                style(&format!("valid for {} minutes", expiration.num_minutes()))
                                    .with(Color::Green)
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "{}\t{}",
                            e.account_name,
                            style(e.description()).with(Color::Red)
                        );
                    }
                },
                Err(e) => {
                    println!(
                        "{} Multithreading error\t{}",
                        style("!").with(Color::Red),
                        style(e.downcast_ref::<Box<Error>>().unwrap().description())
                            .with(Color::Red)
                    );
                }
            };
        }
        credentials_file.write_to_file(filepath).unwrap();

        // update valid_until fields
        for account in &mut group.accounts {
            if !accounts.contains_key(&account.arn) {
                continue;
            }

            account.valid_until = *accounts.get(&account.arn).unwrap();
        }

        println!("\nRefreshed group {}. To use them in the AWS cli, apply the --profile flag with the name of the account.", style(group_name).with(Color::Yellow));
        println!(
            "\nExample:\n\n\taws --profile {} s3 ls\n",
            style(&group.accounts[0].name).with(Color::Yellow)
        );
    }

    cfg.save().unwrap();
}

#[derive(Debug)]
struct RefreshAccountOutput {
    pub account: config::Account,
    pub credentials: Option<Credentials>,
    pub renewed: bool,
}

#[derive(Debug)]
struct RefreshError {
    pub account_name: String,
    msg: String,
}

impl RefreshError {
    pub fn new(account_name: &str, message: &str) -> Self {
        RefreshError {
            account_name: account_name.into(),
            msg: message.into(),
        }
    }
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "could not refresh account")
    }
}

impl Error for RefreshError {
    fn description(&self) -> &str {
        &self.msg
    }

    fn cause(&self) -> Option<&Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
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
) -> Result<(RefreshAccountOutput, CookieJar), RefreshError> {
    if account.session_valid() && !force {
        debug!("refresh_account.session_still_valid");

        return Ok((
            RefreshAccountOutput {
                account: account.clone(),
                credentials: None,
                renewed: false,
            },
            cookie_jar,
        ));
    }

    trace!("\nrefresh_account.before_get_assertion_response",);
    debug!("using idp at {}", idp_url);

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
            println!("{} {}", account.name, style("FAIL").with(Color::Red));

            if e.kind == KeycloakErrorKind::InvalidCredentials
                || e.kind == KeycloakErrorKind::InvalidToken
                || e.kind == KeycloakErrorKind::PasswordUpdateRequired
            {
                println!(
                    "\n{} Cannot recover from error:\n\n\t{}\n",
                    style("!").with(Color::Red),
                    style(e.description()).with(Color::Red)
                );
            }

            return Err(RefreshError::new(&account.name, e.description()));
        }
    };

    trace!("refresh_account.after_get_assertion_response");

    let assertion = match parse_assertion(&saml_response) {
        Ok(a) => a,
        Err(e) => {
            trace!("refresh_account.parse_assertion.err");
            return Err(RefreshError::new(&account.name, e.description()));
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
            trace!("refresh_account.match_assertion.none");

            return Err(RefreshError::new(
                &account.name,
                "Principal not found. Are you sure you have access to this account?",
            ));
        }
    };

    trace!("refresh_account.before_assume_role");

    match assume_role(
        &account.arn,
        &principal,
        &saml_response,
        session_duration.or(Some(assertion.session_duration)),
    ) {
        Ok(res) => {
            trace!("refresh_account.after_assume_role.ok");
            debug!("Access Key ID: {}", res.access_key_id);

            let mut account = account.clone();
            account.valid_until = Some(DateTime::from_str(res.expiration.as_str()).unwrap());

            return Ok((
                RefreshAccountOutput {
                    account,
                    credentials: Some(res),
                    renewed: true,
                },
                cookie_jar,
            ));
        }
        Err(e) => {
            trace!("refresh_account.after_assume_role.err");
            return Err(RefreshError::new(&account.name, e.description()));
        }
    };
}
