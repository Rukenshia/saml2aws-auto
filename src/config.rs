use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::panic;
use std::path::Path;

use chrono::prelude::*;

use crossterm::style::Color;
use crossterm::Crossterm;
use dirs;
use keyring::{Keyring, KeyringError};
use rpassword;
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

#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";

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

pub fn ask_question(ct: &Crossterm, question: &str, default: Option<&str>) {
    if let Some(default) = default {
        print!(
            "{} {}",
            ct.paint("?").with(Color::Green),
            ct.paint(&format!("{} [{}]: ", question, default)),
        );
    } else {
        print!(
            "{} {}",
            ct.paint("?").with(Color::Green),
            ct.paint(&format!("{}: ", question)),
        );
    }
}

pub fn password_prompt(question: &str, default: Option<&str>) -> Option<String> {
    let masked: Option<String> = match default {
        Some(s) => {
            if s.len() == 0 {
                None
            } else if s.len() < 4 {
                let formatted = format!("{}***", s.get(0..1).unwrap()).to_owned();
                Some(formatted)
            } else {
                let formatted = format!("{}{}", s.get(0..4).unwrap(), "*".repeat(s.len() - 4));
                Some(formatted)
            }
        }
        None => None,
    };

    let crossterm = Crossterm::new();
    ask_question(&crossterm, question, masked.as_ref().map(|s| s.as_str()));

    let password = match rpassword::read_password() {
        Ok(p) => p,
        Err(_) => {
            println!("Could not read password");
            return default.map(|d| d.into());
        }
    };

    if password == LINE_ENDING || password.len() == 0 {
        return match default {
            Some(default) => Some(default.into()),
            None => password_prompt(question, default),
        };
    }

    Some(password.trim().into())
}

pub fn prompt(question: &str, default: Option<&str>) -> Option<String> {
    let crossterm = Crossterm::new();
    let mut buf = String::new();

    ask_question(&crossterm, question, default);

    if let Err(_) = io::stdin().read_line(&mut buf) {
        println!("Could not read line");
        return default.map(|d| d.into());
    }

    if buf == LINE_ENDING {
        return match default {
            Some(default) => Some(default.into()),
            None => prompt(question, default),
        };
    }

    Some(buf.trim().into())
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
        if let Some(password) = password_prompt(
            "IDP Password",
            match get_password(&cfg.username.as_ref().unwrap()) {
                Ok(ref p) => {
                    if p.len() == 0 {
                        None
                    } else {
                        Some(p)
                    }
                }
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

    cfg.save().unwrap();
    println!(
        "\nAll set!\nIf you need to reconfigure your details, use {}",
        crossterm
            .paint("saml2aws-auto configure")
            .with(Color::Yellow)
    );
}

pub fn check_or_interactive_create() -> bool {
    let crossterm = Crossterm::new();

    if get_filename(vec!["./saml2aws-auto.yml", &default_filename()]).is_some() {
        let cfg = match load_or_default() {
            Ok(c) => c,
            Err(e) => {
                println!(
                    "{}: {}",
                    crossterm
                        .paint("Could not load the saml2aws-auto config file")
                        .with(Color::Red),
                    e
                );
                println!("\nPlease check that if you did any manual modifications that your YAML is still valid.");
                println!("If you cannot fix this error, delete the saml2aws-auto.yml file and re-add your groups.");
                return false;
            }
        };

        if let Some(ref username) = cfg.username {
            if let Err(_) = panic::catch_unwind(|| {
                if let Err(_) = get_password(username) {
                    if let Some(password) = prompt("IDP Password", Some("")) {
                        set_password(username, &password)
                            .expect("Could not save password in credentials storage");
                    }
                }
            }) {
                println!("\n{}: It seems like there is a problem with managing your credentials. Please use the '--password' flag in all commands for now.\nWe are working on a fix.",
                         crossterm.paint("WARNING").with(Color::Yellow));
                return false;
            };
        }
        return true;
    }

    interactive_create(Config::default());
    return true;
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
