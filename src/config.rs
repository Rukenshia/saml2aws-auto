use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;

use chrono::prelude::*;
use crossterm::style::Color;
use crossterm::Crossterm;
use dirs;
use keyring::{Keyring, KeyringError};
use serde_yaml;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_filename")]
    filename: String,
    pub idp_url: String,
    pub username: Option<String>,

    #[serde(skip_serializing)]
    pub password: Option<String>,

    pub groups: HashMap<String, Group>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub session_duration: Option<i64>,
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub arn: String,
    pub valid_until: Option<DateTime<FixedOffset>>,
}

fn default_filename() -> String {
    let mut path = dirs::home_dir().unwrap();
    path.push(".saml2aws-auto.yml");

    format!("{}", path.to_str().unwrap())
}

fn get_filename(paths: Vec<&str>) -> Option<&str> {
    for path in &paths {
        if Path::new(path).exists() {
            return Some(path);
        }
    }

    None
}

pub fn load_or_default() -> Result<Config, io::Error> {
    let default = default_filename();
    match get_filename(vec!["./saml2aws-auto.yml", &default]) {
        Some(path) => {
            let mut f = File::open(path)?;

            let mut buf = String::new();

            f.read_to_string(&mut buf)?;

            match serde_yaml::from_str::<Config>(&buf) {
                Ok(mut cfg) => {
                    cfg.filename = path.to_owned().into();

                    if let Some(ref username) = cfg.username {
                        cfg.password = match get_password(username) {
                            Ok(p) => Some(p),
                            Err(_) => None,
                        };
                    }

                    Ok(cfg)
                }
                Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.description())),
            }
        }
        None => Ok(Config::default()),
    }
}

pub fn get_password(username: &str) -> Result<String, KeyringError> {
    Keyring::new("saml2aws-auto", username).get_password()
}

pub fn set_password(username: &str, password: &str) -> Result<(), KeyringError> {
    Keyring::new("saml2aws-auto", username).set_password(password)
}

pub fn prompt(question: &str, default: Option<&str>) -> Option<String> {
    let crossterm = Crossterm::new();

    let mut buf = String::new();
    if let Some(default) = default {
        print!(
            "{} {}",
            crossterm.paint("?").with(Color::Green),
            crossterm.paint(&format!("{} [{}]: ", question, default)),
        );
    } else {
        print!(
            "{} {}",
            crossterm.paint("?").with(Color::Green),
            crossterm.paint(&format!("{}: ", question)),
        );
    }

    if let Err(_) = io::stdin().read_line(&mut buf) {
        println!("Could not read line");
        return default.map(|d| d.into());
    }

    if buf.len() == 0 {
        return match default {
            Some(default) => Some(default.into()),
            None => prompt(question, default),
        };
    }

    return Some(buf.trim().into());
}

pub fn interactive_create(default: Config) {
    let crossterm = Crossterm::new();

    println!("\nWelcome to saml2aws-auto. It looks like you do not have a configuration file yet.");
    println!("Currently, only Keycloak is supported as Identity Provider. When setting the");
    println!(
        "IDP URL, please note that you will have to pass {} of Keycloak.\n",
        crossterm
            .paint("the exact path to the saml client")
            .with(Color::Yellow)
    );

    let mut cfg = default;

    if let Some(idp_url) = prompt("IDP URL", Some(&cfg.idp_url)) {
        cfg.idp_url = idp_url.into();
    }

    if let Some(username) = prompt(
        "IDP Username",
        match cfg.username {
            Some(ref s) => Some(s),
            None => None,
        },
    ) {
        cfg.username = Some(username);
        if let Some(password) = prompt(
            "IDP Password",
            match get_password(&cfg.username.as_ref().unwrap()) {
                Ok(ref p) => Some(p),
                Err(e) => {
                    println!("{}", e);
                    Some("")
                }
            },
        ) {
            cfg.password = password.into();
            set_password(
                &cfg.username.as_ref().unwrap(),
                &cfg.password.as_ref().unwrap(),
            ).expect("Could not save password in credentials storage");
        }
    }

    println!("{}", cfg.username.as_ref().unwrap());

    cfg.save().unwrap();
    println!("\nAll set!\n");
}

pub fn check_or_interactive_create() {
    if get_filename(vec!["./saml2aws-auto.yml", &default_filename()]).is_some() {
        let cfg = load_or_default().expect("Could not load config");

        if let Some(ref username) = cfg.username {
            if let Err(_) = get_password(username) {
                if let Some(password) = prompt("IDP Password", Some("")) {
                    set_password(username, &password)
                        .expect("Could not save password in credentials storage");
                }
            }
        }
        return;
    }

    interactive_create(Config::default());
}

impl Config {
    pub fn default() -> Self {
        Config {
            filename: default_filename(),
            idp_url: "localhost".into(),
            username: None,
            password: None,
            groups: HashMap::new(),
        }
    }

    pub fn save(&self) -> Result<(), io::Error> {
        let f = File::create(&self.filename)?;

        serde_yaml::to_writer(f, self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.description()))
    }
}

impl Account {
    pub fn session_valid(&self) -> bool {
        if self.valid_until.is_none() {
            return false;
        }

        Local::now() < self.valid_until.unwrap().with_timezone::<Local>(&Local)
    }
}
