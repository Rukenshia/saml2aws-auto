use aws::{extract_saml_accounts, AWSAccountInfo};
use config;
use config::{prompt, Account, Group};
use keycloak::login::get_assertion_response;

use chrono::prelude::*;
use clap::ArgMatches;
use cookie::CookieJar;
use crossterm::crossterm_style::{paint, Color};

pub fn command(matches: &ArgMatches) {
    if let Some(_) = matches.subcommand_matches("list") {
        list()
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        let name = matches.value_of("GROUP").unwrap();

        delete(name)
    } else if let Some(matches) = matches.subcommand_matches("add") {
        let cfg = config::load_or_default().unwrap();

        let name = matches.value_of("NAME").unwrap();
        let role = matches.value_of("role").unwrap();
        let append = matches.is_present("append");

        let cfg_username = cfg.username.unwrap();
        let cfg_password = cfg.password.unwrap();
        let username = matches.value_of("username").unwrap_or(&cfg_username);
        let password = matches.value_of("password").unwrap_or(&cfg_password);

        let mfa = matches
            .value_of("mfa")
            .map(|m| m.into())
            .or_else(|| prompt("MFA Token", Some("000000")))
            .expect("No MFA Token provided");

        let session_duration = matches
            .value_of("session_duration")
            .map(|s| s.parse().ok().unwrap());

        let prefix = matches.value_of("prefix");
        let account_names = matches.values_of("accounts");

        if prefix.is_some() && account_names.is_some() {
            println!("Cannot specify both --accounts and --prefix");
            return;
        }

        if prefix.is_none() && account_names.is_none() {
            println!(
                "\nCould not add group {}:\n\n\t{}\n",
                paint(name).with(Color::Yellow),
                paint("Must specify either --prefix or --accounts flag").with(Color::Red)
            );
            return;
        }

        let mut accounts: Vec<Account> = vec![];

        print!("Listing allowed roles for your account...");

        let mut cookie_jar = CookieJar::new();
        let (_, web_response) = get_assertion_response(
            &mut cookie_jar,
            &cfg.idp_url,
            username,
            password,
            &mfa,
            true,
        ).unwrap();

        let aws_list = extract_saml_accounts(&web_response.unwrap()).unwrap();

        if let Some(prefix) = prefix {
            accounts = get_acocunts_prefixed_by(&aws_list, prefix, role);
        }
        if let Some(account_names) = account_names {
            accounts =
                get_accounts_by_names(&aws_list, account_names.map(|a| a.into()).collect(), role);
        }

        println!("\t{}", paint("SUCCESS").with(Color::Green));

        add(name, session_duration, accounts, append)
    }
}

fn list() {
    let cfg = config::load_or_default().unwrap();

    for (name, group) in &cfg.groups {
        println!("\n{}:", paint(name).with(Color::Yellow));

        if let Some(duration) = group.session_duration {
            println!(
                "\t{}: {}",
                paint("Session Duration"),
                paint(&format!("{} seconds", duration)).with(Color::Blue)
            );
        } else {
            println!(
                "\t{}: {}",
                paint("Session Duration"),
                paint("implicit").with(Color::Blue)
            );
        }

        println!("\n\t{}", paint("Sessions"));
        for account in &group.accounts {
            match account.valid_until {
                Some(expiration) => {
                    let now = Local::now();

                    let expiration = expiration.signed_duration_since(now);
                    if expiration.num_minutes() < 0 {
                        println!(
                            "\t{}: {}",
                            paint(&account.name),
                            paint("no valid session").with(Color::Red)
                        );
                    } else {
                        println!(
                            "\t{}: {}",
                            paint(&account.name),
                            paint(&format!("{} minutes left", expiration.num_minutes()))
                                .with(Color::Green)
                        );
                    }
                }
                None => {
                    println!(
                        "\t{}: {}",
                        paint(&account.name),
                        paint("no valid session").with(Color::Red)
                    );
                }
            };
        }

        println!("\n\t{}", paint("ARNs"));
        for account in &group.accounts {
            println!("\t{}: {}", paint(&account.name), account.arn,);
        }
        println!("");
    }
}

fn delete(name: &str) {
    let mut cfg = config::load_or_default().unwrap();

    if !cfg.groups.contains_key(name) {
        println!(
            "\nCould not delete the group {}:\n\n\t{}\n",
            paint(name).with(Color::Yellow),
            paint("The specified group does not exist").with(Color::Red)
        );
        return;
    }
    cfg.groups.remove(name).unwrap();

    cfg.save().unwrap();
    println!(
        "\nSuccessfully deleted group {}.\n",
        paint(name).with(Color::Yellow)
    );
}

fn add(name: &str, session_duration: Option<i64>, accounts: Vec<Account>, append_only: bool) {
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
        exists = true;
    };

    if !exists {
        println!("Adding group {}", name);

        cfg.groups.insert(
            name.into(),
            Group {
                accounts: accounts,
                session_duration: session_duration,
            },
        );
    }
    println!("\n{}:", paint(name).with(Color::Yellow));

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
