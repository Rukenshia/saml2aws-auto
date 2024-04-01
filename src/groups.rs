use crate::aws::{extract_saml_accounts, AWSAccountInfo};
use crate::config;
use crate::keycloak::login::get_assertion_response;
use crate::refresh;
use config::{prompt, Account, Group};

use chrono::prelude::*;
use clap::ArgMatches;
use cookie::CookieJar;
use crossterm::style::Stylize;
use std::io;
use std::io::prelude::*;

pub fn command(cfg: &mut config::Config, matches: &ArgMatches) {
    if let Some(_) = matches.subcommand_matches("list") {
        list(&cfg)
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        let name = matches.value_of("GROUP").unwrap();

        delete(cfg, name)
    } else if let Some(matches) = matches.subcommand_matches("refresh") {
        refresh::command(cfg, matches);
    } else if let Some(matches) = matches.subcommand_matches("add") {
        let name = matches.value_of("NAME").unwrap();
        let role = matches.value_of("role").unwrap();
        let append = matches.is_present("append");

        let cfg_username = &cfg.username.as_ref().unwrap();
        let username = matches.value_of("username").unwrap_or(cfg_username);

        let password = match matches.value_of("password") {
            Some(s) => s.to_owned(),
            None => cfg.password.as_ref().expect("Password could not be found, please run saml2aws-auto configure or provide a password by supplying the --password flag").clone(),
        };

        let mfa = matches
            .value_of("mfa")
            .map(|m| m.into())
            .or_else(|| prompt("MFA Token", Some("000000"), false))
            .expect("No MFA Token provided");

        let session_duration = matches
            .value_of("session_duration")
            .map(|s| s.parse().ok().unwrap());

        let sts_endpoint = matches.value_of("sts_endpoint").map(|s| s.into());

        let prefix = matches.value_of("prefix");
        let account_names = matches.values_of("accounts");

        if prefix.is_some() && account_names.is_some() {
            println!("Cannot specify both --accounts and --prefix");
            return;
        }

        if prefix.is_none() && account_names.is_none() {
            println!(
                "\nCould not add group {}:\n\n\t{}\n",
                name.yellow(),
                "Must specify either --prefix or --accounts flag".red(),
            );
            return;
        }

        let mut accounts: Vec<Account> = vec![];

        print!("Listing allowed roles for your account\t");
        io::stdout().flush().unwrap();
        trace!("command.get_assertion_response");

        let mut cookie_jar = CookieJar::new();
        let (saml_response, web_response) = match get_assertion_response(
            &mut cookie_jar,
            &cfg.idp_url,
            username,
            &password,
            cfg.mfa_device.as_deref(),
            &mfa,
            true,
        ) {
            Ok(r) => r,
            Err(e) => {
                trace!("command.get_assertion_response.err");
                error!("{:?}", e);
                println!("{}", "FAIL".red());
                println!("\nCould not add group:\n\n\t{}\n", e.to_string().red());
                return;
            }
        };

        trace!("command.extract_saml_accounts");
        let aws_list = match extract_saml_accounts(&web_response.unwrap(), &saml_response) {
            Ok(l) => l,
            Err(e) => {
                trace!("command.extract_saml_accounts.err");
                error!("{:?}", e);
                println!("{}", "FAIL".red());
                println!("\nCould not add group:\n\n\t{}\n", e.to_string().red());
                return;
            }
        };

        if aws_list.len() == 1 {
            // This is a special case because the user will never see a role list form
            // on the web console. We will now add a single account with the account id
            // and ask the user for a name.

            println!("\t{}", "WARNING".yellow());
            println!("\nYou seem to only have access to a single AWS Account. The name could not be found automatically, so please enter an account name manually.");

            let account_name = prompt("Account name", None, false).unwrap();

            accounts = vec![Account {
                name: account_name,
                arn: aws_list[0].arn.clone(),
                valid_until: None,
            }];
        } else {
            if let Some(prefix) = prefix {
                accounts = get_acocunts_prefixed_by(&aws_list, prefix, role);
            }
            if let Some(account_names) = account_names {
                accounts = get_accounts_by_names(
                    &aws_list,
                    account_names.map(|a| a.into()).collect(),
                    role,
                );
            }
        }

        if accounts.len() == 0 {
            println!("\t{}", "WARNING".yellow());
            println!("\nNo accounts were found with the given parameters. Possible errors:");
            println!("\t- Wrong prefix/accounts used");
            println!("\t- Wrong role used");

            trace!("aws_list");
            for account in &aws_list {
                trace!("aws_list name={} arn={}", account.name, account.arn);
            }
        } else {
            println!("\t{}", "SUCCESS".green());
            add(cfg, name, session_duration, accounts, append, sts_endpoint)
        }
    }
}

fn list(cfg: &config::Config) {
    for (name, group) in &cfg.groups {
        println!("\n{}:", name.as_str().yellow());

        if let Some(duration) = group.session_duration {
            println!(
                "\t{}: {}",
                "Session Duration",
                format!("{} seconds", duration).blue()
            );
        } else {
            println!("\t{}: {}", "Session Duration", "implicit".blue(),);
        }

        if let Some(endpoint) = &group.sts_endpoint {
            println!("\t{}: {}", "STS Endpoint", endpoint.as_str().blue(),);
        } else {
            println!("\t{}: {}", "STS Endpoint", "default".blue());
        }

        println!("\n\t{}", "Sessions");
        for account in &group.accounts {
            match account.valid_until {
                Some(expiration) => {
                    let now = Local::now();

                    let expiration = expiration.signed_duration_since(now);
                    if expiration.num_minutes() < 0 {
                        println!("\t{}: {}", &account.name, "no valid session".red(),);
                    } else {
                        println!(
                            "\t{}: {}",
                            &account.name,
                            format!("{} minutes left", expiration.num_minutes()).green()
                        );
                    }
                }
                None => {
                    println!("\t{}: {}", &account.name, "no valid session".red(),);
                }
            };
        }

        println!("\n\tARNs");
        for account in &group.accounts {
            println!("\t{}: {}", &account.name, account.arn,);
        }
        println!("");
    }
}

fn delete(cfg: &mut config::Config, name: &str) {
    if !cfg.groups.contains_key(name) {
        println!(
            "\nCould not delete the group {}:\n\n\t{}\n",
            name.yellow(),
            "The specified group does not exist".red()
        );
        return;
    }
    cfg.groups.remove(name).unwrap();

    cfg.save().unwrap();
    println!("\nSuccessfully deleted group {}.\n", name.yellow(),);
}

fn add(
    cfg: &mut config::Config,
    name: &str,
    session_duration: Option<i64>,
    accounts: Vec<Account>,
    append_only: bool,
    sts_endpoint: Option<String>,
) {
    let mut exists = false;

    if let Some((name, group)) = cfg.groups.iter_mut().find(|&(a, _)| a == name) {
        if append_only {
            println!("Group {} exists, appending new accounts", name);

            let existing_names: Vec<String> = (&group.accounts)
                .into_iter()
                .map(|ref a| a.name.clone())
                .collect();

            group.accounts.extend(
                (&accounts)
                    .into_iter()
                    .filter(|a| !existing_names.contains(&a.name))
                    .map(|a| a.clone())
                    .collect::<Vec<Account>>(),
            );
        } else {
            group.accounts = accounts.clone();
            println!("Group {} exists, replacing accounts", name);
        }
        group.session_duration = session_duration;

        // Extra logic: if the sts endpoint was set explicitly, assign it to the group
        // if the parameter is not present, but there was a previous configuration,
        // reset the sts endpoint to None
        if sts_endpoint.is_some() {
            group.sts_endpoint = sts_endpoint.clone();
        } else if group.sts_endpoint.is_some() && sts_endpoint.is_none() {
            group.sts_endpoint = None;
        }
        exists = true;
    };

    if !exists {
        println!("Adding group {}", name);

        cfg.groups.insert(
            name.into(),
            Group {
                session_duration,
                sts_endpoint,
                accounts,
            },
        );
    }

    println!("\n{}:", name.yellow());

    for account in &cfg.groups.get(name).unwrap().accounts {
        println!("\t{}: {}", account.name, account.arn,);
    }

    cfg.save().unwrap();
    println!("\nGroup configuration updated");
}

fn get_acocunts_prefixed_by(
    accounts: &Vec<AWSAccountInfo>,
    prefix: &str,
    role_name: &str,
) -> Vec<Account> {
    accounts
        .into_iter()
        .filter(|a| a.name.starts_with(prefix))
        .filter(|a| a.arn.ends_with(&format!("role/{}", role_name)))
        .map(|a| Account {
            name: a.name.clone(),
            arn: a.arn.clone(),
            valid_until: None,
        })
        .collect()
}

fn get_accounts_by_names(
    accounts: &Vec<AWSAccountInfo>,
    names: Vec<String>,
    role_name: &str,
) -> Vec<Account> {
    accounts
        .into_iter()
        .filter(|a| names.iter().find(|name| *name == &a.name).is_some())
        .filter(|a| a.arn.ends_with(&format!("role/{}", role_name)))
        .map(|a| Account {
            name: a.name.clone(),
            arn: a.arn.clone(),
            valid_until: None,
        })
        .collect()
}
