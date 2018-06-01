use regex::Regex;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chrono::prelude::*;

use config::Account;

#[derive(Debug)]
pub struct Saml2AwsError {
    description: String,
}

impl Error for Saml2AwsError {
    fn description(&self) -> &str {
        &self.description
    }
}

impl fmt::Display for Saml2AwsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("saml2aws: {}", self.description))
    }
}

impl Saml2AwsError {
    pub fn new(message: &str) -> Self {
        Saml2AwsError {
            description: message.into(),
        }
    }
}

pub struct Saml2Aws {
    mfa: String,
    password: Option<String>,

    pub debug: bool,
}

impl Saml2Aws {
    /// Create a new instance of Saml2Aws.
    ///
    /// This struct is mainly used to call the actual 'saml2aws' command.
    pub fn new(mfa: &str, password: Option<&str>) -> Self {
        Saml2Aws {
            mfa: mfa.into(),
            password: password.map(|p| p.into()),
            debug: false,
        }
    }

    /// Creates a new saml2aws subcommand call
    fn new_command(&self, subcommand: &str) -> Command {
        let mut c = Command::new("saml2aws");

        c.arg(subcommand)
            .arg("--skip-prompt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref p) = self.password {
            c.arg("--password").arg(p);
        }

        c
    }

    /// Checks if the saml2aws binary exists by calling it
    pub fn exists(&self) -> Result<(), Saml2AwsError> {
        match Command::new("saml2aws")
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(s) => {
                if s.success() {
                    return Ok(());
                }

                Err(Saml2AwsError::new(
                    "saml2aws binary not found in PATH. Did you install saml2aws?",
                ))
            }
            Err(_) => Err(Saml2AwsError::new(
                "saml2aws binary not found in PATH. Did you install saml2aws?",
            )),
        }
    }

    /// Checks that saml2aws is configured
    pub fn is_configured(&self) -> Result<(), Saml2AwsError> {
        if let Err(e) = self.exists() {
            return Err(e);
        }

        // load the configuartion file, $HOME/.saml2aws
        let mut f = match File::open(
            PathBuf::new()
                .join(env::home_dir().unwrap())
                .join(".saml2aws"),
        ) {
            Ok(f) => f,
            Err(_) => {
                return Err(Saml2AwsError::new(
                    "saml2aws does not seem to be configured. Did you run saml2aws configure?",
                ));
            }
        };

        // naive check, should use rust-ini to parse the file
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();

        if buf.contains("KeyCloak") {
            return Ok(());
        }

        Err(Saml2AwsError::new("saml2aws does not seem to be configured (only KeyCloak is supported at the moment). Did you run saml2aws configure?"))
    }

    /// Lists all available roles
    pub fn list_roles(&self) -> Result<Vec<Account>, Saml2AwsError> {
        if let Err(e) = self.is_configured() {
            return Err(e);
        }

        let mut c = match self.new_command("list-roles").spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(Saml2AwsError::new(&format!(
                    "i/o error {}",
                    e.description()
                )));
            }
        };

        {
            let mut stdin = c.stdin.as_mut().unwrap();
            let mut writer = BufWriter::new(&mut stdin);

            writer
                .write_all(format!("{}\n", self.mfa).as_bytes())
                .unwrap();
        }

        let output = c.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.code().unwrap() != 0 {
            if self.debug {
                println!("\nstdout: {}\n", stdout);
                println!("\nstderr: {}\n", stderr);
            }

            if stdout.contains("Please check your username and password is correct") {
                return Err(Saml2AwsError::new(
                    "Invalid credentials. Check your MFA token and saml2aws configuration",
                ));
            }

            if stderr.contains("unable to locate IDP authentication form submit URL") {
                return Err(Saml2AwsError::new("Invalid credentials, supposedly password. Check your credentials and saml2aws configuration."));
            }
            return Err(Saml2AwsError::new("Error executing saml2aws list-roles"));
        }

        Ok(self.parse_role_response(&stdout))
    }

    /// Logs in to a account
    pub fn login(
        &self,
        arn: &str,
        profile: &str,
        session_duration: i64,
    ) -> Result<DateTime<FixedOffset>, Saml2AwsError> {
        if let Err(e) = self.is_configured() {
            return Err(e);
        }

        let mut c = match self
            .new_command("login")
            .arg("--profile")
            .arg(profile)
            .arg("--role")
            .arg(arn)
            .arg("--session-duration")
            .arg(&session_duration.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return Err(Saml2AwsError::new(&format!(
                    "i/o error {}",
                    e.description()
                )));
            }
        };

        {
            let mut stdin = c.stdin.as_mut().unwrap();
            let mut writer = BufWriter::new(&mut stdin);

            writer
                .write_all(format!("{}\n", self.mfa).as_bytes())
                .unwrap();
        }

        let output = c.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.code().unwrap() != 0 {
            if self.debug {
                println!("\n\nstdout: {}\n", stdout);
                println!("\nstderr: {}\n\n", stderr);
            }

            if stdout.contains("Please check your username and password is correct") {
                return Err(Saml2AwsError::new(
                    "Invalid credentials. Check your MFA token and saml2aws configuration",
                ));
            }

            if stderr.contains("unable to locate IDP authentication form submit URL") {
                return Err(Saml2AwsError::new("Invalid credentials, supposedly password. Check your credentials and saml2aws configuration."));
            }

            return Err(Saml2AwsError::new("Error executing saml2aws login"));
        }

        // parse stdout, check expiry time
        let re_expiration = Regex::new(r"(?m)^Note that it will expire at (.*?\+[0-9]+)").unwrap();

        let expiration = re_expiration.captures(&stdout);
        if expiration.is_none() {
            return Err(Saml2AwsError::new(
                "Could not find token expiration time, you might have credentials though.",
            ));
        }

        let expiration = &expiration.unwrap()[1];
        match DateTime::parse_from_str(expiration, "%Y-%m-%d %H:%M:%S %z") {
            Ok(e) => Ok(e),
            Err(e) => {
                println!("{}", e);

                Err(Saml2AwsError::new(
                    "Could not parse token expiration time, you might have credentials though.",
                ))
            }
        }
    }

    fn parse_role_response(&self, output: &str) -> Vec<Account> {
        let re_account = Regex::new(r"Account: (.*?) \(([0-9]+)\)\n(?m)^(.*)$(?-m)").unwrap();

        let mut accounts: Vec<Account> = vec![];

        for cap in re_account.captures_iter(output) {
            accounts.push(Account {
                id: cap[2].into(),
                name: cap[1].into(),
                arn: cap[3].into(),
                valid_until: None,
            });
        }

        accounts
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_role_response() {
        let output = "Using IDP Account default to access KeyCloak https://example.com/protocol/saml/clients/aws
? Security Token [000000] 123568

Account: example-account-dev (123456890)
arn:aws:iam::1234567890:role/Administrator";

        let s = Saml2Aws::new("000000", None);
        let res = s.parse_role_response(output);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, "example-account-dev");
        assert_eq!(res[0].id, "123456890");
        assert_eq!(res[0].arn, "arn:aws:iam::1234567890:role/Administrator");
    }
}
