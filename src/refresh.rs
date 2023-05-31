use std::{borrow::BorrowMut, error::Error};

use clap::ArgMatches;

use itertools::Itertools;

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
use crossterm::style::Stylize;
use keycloak::login::get_assertion_response;
use keycloak::KeycloakErrorKind;
use saml::parse_assertion;
use tabled::{
    object::{Columns, Object},
    Alignment, Modify, Style, Table, Tabled,
};

use config;

/// Returns the MFA token. If it is provided via the input, it will be unwrapped and
pub fn command(cfg: &mut config::Config, matches: &ArgMatches) {
    let mut group_names: Vec<&str> = matches.values_of("GROUP").unwrap().collect();
    let mfa = matches.value_of("mfa");
    let force = matches.is_present("force");

    let cfg_username = cfg.username.as_ref().unwrap();
    let username = matches.value_of("username").unwrap_or(&cfg_username);

    let password = match matches.value_of("password") {
        Some(s) => s.to_string(),
        None => cfg.password.as_ref().expect("Password could not be found, please run saml2aws-auto configure or provide a password by supplying the --password flag").clone(),
    };

    {
        let mfa = match mfa {
            Some(m) => m.into(),
            None => {
                debug!("mfa flag not set, no valid session");

                prompt("MFA Token", Some("000000"), false).unwrap()
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
                &password,
                cfg.mfa_device.as_deref(),
                &mfa.trim(),
                false,
            ) {
                Ok(r) => r,
                Err(e) => {
                    if e.kind == KeycloakErrorKind::InvalidCredentials
                        || e.kind == KeycloakErrorKind::InvalidToken
                        || e.kind == KeycloakErrorKind::PasswordUpdateRequired
                    {
                        println!(
                            "\n{} Cannot recover from error:\n\n\t{}\n",
                            "!".red(),
                            e.to_string().red(),
                        );
                    }

                    return;
                }
            };
            trace!("command.initial_login.success");
        }

        trace!("command.cookie_jar={:?}", cookie_jar);

        for (group_name, group) in cfg
            .groups
            .iter_mut()
            .filter(|(name, _)| group_names.iter().any(|n| n == &name.as_str()))
        {
            if group.accounts.len() == 0 {
                debug!("group.accounts len is 0");

                println!(
                    "Nothing to refresh. Group {} is empty.",
                    group_name.as_str().yellow(),
                );
                continue;
            }

            if group.accounts.iter().all(|a| a.session_valid()) && !force {
                println!(
                "Nothing to refresh. All accounts have valid sessions. Use --force to overwrite.");
                continue;
            }

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
                let sts_endpoint = group.sts_endpoint.clone();
                let cookie_jar = cookie_jar.clone();
                let account = account.clone();
                let mfa_device = cfg.mfa_device.clone();

                threads.push(thread::spawn(move || {
                    return refresh_account(
                        session_duration,
                        &account,
                        cookie_jar,
                        &idp_url,
                        &username,
                        &password,
                        mfa_device.as_deref(),
                        &mfa,
                        force,
                        sts_endpoint,
                    );
                }));
            }

            let mut accounts: HashMap<String, Option<DateTime<FixedOffset>>> = HashMap::new();

            let (mut credentials_file, filepath) = load_credentials_file().unwrap();

            #[derive(Debug, Tabled)]
            struct TableRefreshedAccount {
                #[tabled(rename = "Account Name")]
                account_name: String,
                #[tabled(rename = "Refreshed")]
                refreshed: String,
                #[tabled(rename = "Result")]
                expiration: String,
            }

            let outputs: Vec<TableRefreshedAccount> = threads
                .into_iter()
                .map(|t| match t.join() {
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

                            let now = Local::now();

                            let expiration = format!(
                                "valid for {} minutes",
                                format!(
                                    "{}",
                                    output
                                        .account
                                        .valid_until
                                        .unwrap()
                                        .signed_duration_since(now)
                                        .num_minutes()
                                )
                                .green()
                            );

                            TableRefreshedAccount {
                                account_name: output.account.name,
                                refreshed: match output.renewed {
                                    true => "✓".green().to_string(),
                                    false => "⨯".bold().red().to_string(),
                                },
                                expiration,
                            }
                        }
                        Err(ref e) => TableRefreshedAccount {
                            account_name: e.account_name.clone(),
                            refreshed: "⨯".bold().red().to_string(),
                            expiration: e.to_string().red().to_string(),
                        },
                    },
                    Err(e) => TableRefreshedAccount {
                        account_name: "unknown".to_string(),
                        refreshed: "⨯".bold().red().to_string(),
                        expiration: format!("{:?}", e),
                    },
                })
                .collect();

            print!(
                "\n\n{}",
                Table::new(outputs)
                    .with(Style::modern())
                    .with(
                        Modify::new(Columns::single(0).and(Columns::single(2)))
                            .with(Alignment::left())
                    )
                    .to_string()
            );
            credentials_file.write_to_file(filepath).unwrap();

            let example_account = group.accounts[0].name.clone();

            // update valid_until fields
            for mut account in &mut group.accounts {
                if !accounts.contains_key(&account.arn) {
                    continue;
                }

                account.valid_until = *accounts.get(&account.arn).unwrap();
            }

            println!("\nRefreshed group {}. To use them in the AWS cli, apply the --profile flag with the name of the account.", group_name.clone().yellow());
            println!(
                "\nExample:\n\n\taws --profile {} s3 ls\n",
                example_account.as_str().yellow(),
            );
        }
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
        write!(f, "{}", self.msg)
    }
}

impl Error for RefreshError {
    fn description(&self) -> &str {
        &self.msg
    }

    fn cause(&self) -> Option<&dyn Error> {
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
    mfa_device: Option<&str>,
    mfa: &str,
    force: bool,
    sts_endpoint: Option<String>,
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
        mfa_device.as_deref(),
        &mfa.trim(),
        false,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("{} {}", account.name, "FAIL".red());

            if e.kind == KeycloakErrorKind::InvalidCredentials
                || e.kind == KeycloakErrorKind::InvalidToken
                || e.kind == KeycloakErrorKind::PasswordUpdateRequired
            {
                println!(
                    "\n{} Cannot recover from error:\n\n\t{}\n",
                    "!".red(),
                    e.to_string().red(),
                );
            }

            return Err(RefreshError::new(&account.name, &e.to_string()));
        }
    };

    trace!("refresh_account.after_get_assertion_response");

    let assertion = match parse_assertion(&saml_response) {
        Ok(a) => a,
        Err(e) => {
            trace!("refresh_account.parse_assertion.err");
            return Err(RefreshError::new(&account.name, &e.to_string()));
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
        sts_endpoint.as_deref(),
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
            return Err(RefreshError::new(&account.name, &e.to_string()));
        }
    };
}
