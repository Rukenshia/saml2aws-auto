use std::error::Error;

use config;
use config::{Account, Group};
use saml2aws::{Saml2Aws, Saml2AwsError};

use clap::ArgMatches;

use crossterm::crossterm_style::{paint, Color};

pub fn command(matches: &ArgMatches) {
    if let Some(_) = matches.subcommand_matches("list") {
        list()
    } else if let Some(matches) = matches.subcommand_matches("delete") {
        let name = matches.value_of("GROUP").unwrap();

        delete(name)
    } else if let Some(matches) = matches.subcommand_matches("add") {
        let name = matches.value_of("NAME").unwrap();
        let mfa = matches.value_of("mfa").unwrap();
        let role = matches.value_of("role").unwrap();

        let bu = matches.value_of("business_unit");
        let account_names = matches.values_of("accounts");

        if bu.is_some() && account_names.is_some() {
            println!("Cannot specify both --accounts and --business-unit");
            return;
        }

        let mut accounts: Vec<Account> = vec![];

        if let Some(business_unit) = bu {
            accounts = match get_accounts_by_business_unit(business_unit, role, mfa) {
                Ok(a) => a,
                Err(e) => {
                    println!(
                        "\n{}\n\n\t{}\n",
                        paint("Could not list roles for business unit:").bold(),
                        paint(e.description()).with(Color::Red)
                    );

                    return;
                }
            }
        }
        if let Some(account_names) = account_names {
            accounts =
                match get_accounts_by_names(account_names.map(|a| a.into()).collect(), role, mfa) {
                    Ok(a) => a,
                    Err(e) => {
                        println!(
                            "\n{}\n\n\t{}\n",
                            paint("Could not list roles for accounts by names:").bold(),
                            paint(e.description()).with(Color::Red)
                        );

                        return;
                    }
                }
        }

        println!("Found {} accounts", accounts.len());

        add(name, accounts)
    }
}

fn list() {
    let cfg = config::load_or_default().unwrap();

    for (name, group) in &cfg.groups {
        println!("\n{}:", paint(name).with(Color::Yellow));

        for account in &group.accounts {
            println!(
                "\t{}: {}{}{}",
                account.name,
                account.arn.split(&account.id).next().unwrap(),
                paint(&account.id).with(Color::Red),
                account.arn.split(&account.id).skip(1).next().unwrap()
            );
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

fn add(name: &str, accounts: Vec<Account>) {
    let mut cfg = config::load_or_default().unwrap();

    let mut exists = false;

    if let Some((name, group)) = cfg.groups.iter_mut().find(|&(a, _)| a == name) {
        println!("Group {} exists, replacing accounts", name);

        group.accounts = accounts.clone();
        exists = true;
    };

    if !exists {
        println!("Adding group {}", name);

        cfg.groups.insert(name.into(), Group { accounts: accounts });
    }

    cfg.save().unwrap();
}

fn get_accounts_by_business_unit(
    name: &str,
    role_name: &str,
    mfa: &str,
) -> Result<Vec<Account>, Saml2AwsError> {
    let client = Saml2Aws::new();

    match client.list_roles(mfa) {
        Ok(a) => Ok(a.into_iter()
            .filter(|a| a.name.starts_with(name))
            .filter(|a| a.arn.ends_with(&format!("role/{}", role_name)))
            .collect()),
        Err(e) => Err(e),
    }
}

fn get_accounts_by_names(
    names: Vec<String>,
    role_name: &str,
    mfa: &str,
) -> Result<Vec<Account>, Saml2AwsError> {
    let client = Saml2Aws::new();

    match client.list_roles(mfa) {
        Ok(a) => Ok(a.into_iter()
            .filter(|a| names.iter().find(|name| *name == &a.name).is_some())
            .filter(|a| a.arn.ends_with(&format!("role/{}", role_name)))
            .collect()),
        Err(e) => Err(e),
    }
}
