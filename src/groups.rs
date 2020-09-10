use aws::{extract_saml_accounts, AWSAccountInfo};
use config;
use config::{prompt, Account, Group};
use keycloak::login::get_assertion_response;
use refresh;

use chrono::prelude::*;
use clap::ArgMatches;
use cookie::CookieJar;
use crossterm::{style, Color};

pub fn command(matches: &ArgMatches) {
    if let Some(_) = matches.subcommand_matches("list") {
        list()
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        let name = matches.value_of("GROUP").unwrap();

        delete(name)
    } else if let Some(matches) = matches.subcommand_matches("refresh") {
        refresh::command(matches);
    } else if let Some(matches) = matches.subcommand_matches("add") {
        let cfg = config::load_or_default().unwrap();

        let name = matches.value_of("NAME").unwrap();
        let role = matches.value_of("role").unwrap();
        let append = matches.is_present("append");

        let cfg_username = cfg.username.unwrap();
        let username = matches.value_of("username").unwrap_or(&cfg_username);

        let password = match matches.value_of("password") {
            Some(s) => s.to_owned(),
            None => cfg.password.expect("Password could not be found, please run saml2aws-auto configure or provide a password by supplying the --password flag").clone(),
        };

        let mfa = matches
            .value_of("mfa")
            .map(|m| m.into())
            .or_else(|| prompt("MFA Token", Some("000000")))
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
                style(name).with(Color::Yellow),
                style("Must specify either --prefix or --accounts flag").with(Color::Red)
            );
            return;
        }

        let mut accounts: Vec<Account> = vec![];

        print!("Listing allowed roles for your account\t");
        trace!("command.get_assertion_response");

        let mut cookie_jar = CookieJar::new();
        let (saml_response, web_response) = match get_assertion_response(
            &mut cookie_jar,
            &cfg.idp_url,
            username,
            &password,
            &mfa,
            true,
        ) {
            Ok(r) => r,
            Err(e) => {
                trace!("command.get_assertion_response.err");
                error!("{:?}", e);
                println!("{}", style("FAIL").with(Color::Red));
                println!(
                    "\nCould not add group:\n\n\t{}\n",
                    style(e).with(Color::Red)
                );
                return;
            }
        };

        trace!("command.extract_saml_accounts");
        let aws_list = match extract_saml_accounts(&web_response.unwrap(), &saml_response) {
            Ok(l) => l,
            Err(e) => {
                trace!("command.extract_saml_accounts.err");
                error!("{:?}", e);
                println!("{}", style("FAIL").with(Color::Red));
                println!(
                    "\nCould not add group:\n\n\t{}\n",
                    style(e).with(Color::Red)
                );
                return;
            }
        };

        if aws_list.len() == 1 {
            // This is a special case because the user will never see a role list form
            // on the web console. We will now add a single account with the account id
            // and ask the user for a name.

            println!("\t{}", style("WARNING").with(Color::Yellow));
            println!("\nYou seem to only have access to a single AWS Account. The name could not be found automatically, so please enter an account name manually.");

            let account_name = prompt("Account name", None).unwrap();

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
            println!("\t{}", style("WARNING").with(Color::Yellow));
            println!("\nNo accounts were found with the given parameters. Possible errors:");
            println!("\t- Wrong prefix/accounts used");
            println!("\t- Wrong role used");

            trace!("aws_list");
            for account in &aws_list {
                trace!("aws_list name={} arn={}", account.name, account.arn);
            }
        } else {
            println!("\t{}", style("SUCCESS").with(Color::Green));
            add(name, session_duration, accounts, append, sts_endpoint)
        }
    }
}

fn list() {
    let cfg = config::load_or_default().unwrap();

    for (name, group) in &cfg.groups {
        println!("\n{}:", style(name).with(Color::Yellow));

        if let Some(duration) = group.session_duration {
            println!(
                "\t{}: {}",
                "Session Duration",
                style(&format!("{} seconds", duration)).with(Color::Blue)
            );
        } else {
            println!(
                "\t{}: {}",
                "Session Duration",
                style("implicit").with(Color::Blue)
            );
        }

        if let Some(endpoint) = &group.sts_endpoint {
            println!(
                "\t{}: {}",
                "STS Endpoint",
                style(&format!("{}", endpoint)).with(Color::Blue)
            );
        } else {
            println!(
                "\t{}: {}",
                "STS Endpoint",
                style("default").with(Color::Blue)
            );
        }

        println!("\n\t{}", "Sessions");
        for account in &group.accounts {
            match account.valid_until {
                Some(expiration) => {
                    let now = Local::now();

                    let expiration = expiration.signed_duration_since(now);
                    if expiration.num_minutes() < 0 {
                        println!(
                            "\t{}: {}",
                            &account.name,
                            style("no valid session").with(Color::Red)
                        );
                    } else {
                        println!(
                            "\t{}: {}",
                            &account.name,
                            style(&format!("{} minutes left", expiration.num_minutes()))
                                .with(Color::Green)
                        );
                    }
                }
                None => {
                    println!(
                        "\t{}: {}",
                        &account.name,
                        style("no valid session").with(Color::Red)
                    );
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

fn delete(name: &str) {
    let mut cfg = config::load_or_default().unwrap();

    if !cfg.groups.contains_key(name) {
        println!(
            "\nCould not delete the group {}:\n\n\t{}\n",
            style(name).with(Color::Yellow),
            style("The specified group does not exist").with(Color::Red)
        );
        return;
    }
    cfg.groups.remove(name).unwrap();

    cfg.save().unwrap();
    println!(
        "\nSuccessfully deleted group {}.\n",
        style(name).with(Color::Yellow)
    );
}

fn add(
    name: &str,
    session_duration: Option<i64>,
    accounts: Vec<Account>,
    append_only: bool,
    sts_endpoint: Option<String>,
) {
    let mut cfg = config::load_or_default().unwrap();

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
                accounts: accounts,
                session_duration: session_duration,
                sts_endpoint: sts_endpoint,
            },
        );
    }

    println!("\n{}:", style(name).with(Color::Yellow));

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
