use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::panic;
use std::path::Path;

use chrono::prelude::*;

use crossterm::style::Stylize;
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
    pub mfa_device: Option<String>,

    #[serde(skip_serializing)]
    pub password: Option<String>,

    pub groups: HashMap<String, Group>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub session_duration: Option<i64>,
    pub sts_endpoint: Option<String>,
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

pub fn default_filename() -> String {
    let mut path = dirs::home_dir().unwrap();
    path.push(".saml2aws-auto.yml");

    format!("{}", path.to_str().unwrap())
}

pub fn load_or_default(path: &str) -> Result<Config, io::Error> {
    if Path::new(path).exists() {
        let mut f = File::open(path)?;

        let mut buf = String::new();

        f.read_to_string(&mut buf)?;

        match serde_yaml::from_str::<Config>(&buf) {
            Ok(mut cfg) => {
                cfg.filename = path.to_owned();

                if let Some(ref username) = cfg.username {
                    cfg.password = match get_password(username) {
                        Ok(p) => Some(p),
                        Err(_) => None,
                    };
                }

                Ok(cfg)
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    } else {
        Ok(Config::default(path))
    }
}

pub fn get_password(username: &str) -> Result<String, KeyringError> {
    Keyring::new("saml2aws-auto", username).get_password()
}

pub fn set_password(username: &str, password: &str) -> Result<(), KeyringError> {
    Keyring::new("saml2aws-auto", username).set_password(password)
}

pub fn ask_question(question: &str, default: Option<&str>) {
    match default {
        Some(default) => {
            print!(
                "{} {}",
                "?".green(),
                format!("{} [{}]: ", question, default),
            );
        }
        None => {
            print!("{} {}", "?".green(), format!("{}: ", question),);
        }
    }
    io::stdout().flush().unwrap();
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

    ask_question(question, masked.as_ref().map(|s| s.as_str()));

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
    let mut buf = String::new();

    ask_question(question, default);

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
    println!("\nWelcome to saml2aws-auto. Let's configure a few things to get started.");
    println!("Currently, only Keycloak is supported as Identity Provider. When setting the");
    println!(
        "IDP URL, please note that you will have to pass {} of Keycloak.\n",
        "the exact path to the saml client".yellow(),
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
                Err(_) => Some(""),
            },
        ) {
            trace!("interactive_create.set_password");
            trace!("interactive_create.password={}", password);

            cfg.password = password.into();
            match set_password(
                &cfg.username.as_ref().unwrap(),
                &cfg.password.as_ref().unwrap(),
            ) {
                Ok(_) => {}
                Err(e) => {
                    error!("error saving password: {:?}", e);
                    println!("Could not save password");
                }
            };
        }
    }

    if let Some(mfa_device) = prompt(
        "IDP MFA Device (leave empty if only using one device)",
        None,
    ) {
        cfg.mfa_device = Some(mfa_device);
    }

    cfg.save().unwrap();
    println!(
        "\nAll set!\nIf you need to reconfigure your details, use {}",
        "saml2aws-auto configure".yellow(),
    );
}

pub fn check_or_interactive_create(config_path: &str, skip_password_prompt: bool) -> bool {
    if !Path::new(config_path).exists() {
        interactive_create(Config::default(config_path));
        return true;
    }

    let cfg = match load_or_default(config_path) {
        Ok(c) => c,
        Err(e) => {
            println!(
                "{}: {}",
                "Could not load the saml2aws-auto config file".red(),
                e
            );
            println!("\nPlease check that if you did any manual modifications that your YAML is still valid.");
            println!("If you cannot fix this error, delete the saml2aws-auto.yml file and re-add your groups.");
            return false;
        }
    };

    if let Some(ref username) = cfg.username {
        if skip_password_prompt {
            return true;
        }

        if let Err(_) = panic::catch_unwind(|| {
            if let Err(_) = get_password(username) {
                if let Some(password) = password_prompt("IDP Password", Some("")) {
                    set_password(username, &password)
                        .expect("Could not save password in credentials storage");
                }
            }
        }) {
            println!("\n{}: It seems like there is a problem with managing your credentials. Please use the '--password' flag in all commands for now.\nWe are working on a fix.",
                         "WARNING".yellow());
            return false;
        };
    }
    return true;
}

impl Config {
    pub fn default(filename: &str) -> Self {
        Config {
            filename: filename.to_owned(),
            idp_url: "localhost".into(),
            username: None,
            password: None,
            groups: HashMap::new(),
            mfa_device: None,
        }
    }

    pub fn save(&self) -> Result<(), io::Error> {
        let f = File::create(&self.filename)?;

        serde_yaml::to_writer(f, self).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
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
