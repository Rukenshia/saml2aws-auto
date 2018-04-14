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

        let bu = matches.value_of("business_unit");
        let accounts = matches.value_of("accounts");

        if bu.is_some() && accounts.is_some() {
            println!("Cannot specify both --accounts and --business-unit");
            return;
        }

        let mut accounts: Vec<Account> = vec![];

        if let Some(business_unit) = bu {
            accounts = match get_accounts_by_business_unit(business_unit, mfa) {
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

        println!("Found {} accounts", accounts.len());

        add(name, accounts)
    }
}

fn list() {
    let cfg = config::load_or_default().unwrap();

    for group in &cfg.groups {
        println!("[{}] with {} accounts", group.name, group.accounts.len());
    }
}

fn delete(name: &str) {
    let cfg = config::load_or_default().unwrap();

    let new_groups: Vec<&Group> = cfg.groups.iter().filter(|g| g.name != name).collect();

    if new_groups.len() == cfg.groups.len() {
        println!("the specified group does not seem to exist");
        return;
    }

    println!("group {} deleted.", name);
    cfg.save().unwrap();
}

fn add(name: &str, accounts: Vec<Account>) {
    let mut cfg = config::load_or_default().unwrap();

    let mut exists = false;

    if let Some(group) = cfg.groups.iter_mut().find(|a| a.name == name) {
        println!("Group {} exists, replacing accounts", name);

        group.accounts = accounts.clone();
        exists = true;
    };

    if !exists {
        println!("Adding group {}", name);

        cfg.groups.push(Group {
            name: name.into(),
            accounts: accounts,
        });
    }

    cfg.save().unwrap();
}

fn get_accounts_by_business_unit(name: &str, mfa: &str) -> Result<Vec<Account>, Saml2AwsError> {
    let client = Saml2Aws::new();

    match client.list_roles(mfa) {
        Ok(a) => Ok(a.into_iter().filter(|a| a.name.starts_with(name)).collect()),
        Err(e) => Err(e),
    }
}
