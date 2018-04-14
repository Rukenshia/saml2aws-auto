use std::io;
use std::io::{BufWriter, Write};
use std::process::{Command, Stdio};

use regex::Regex;

use config::Account;

pub struct Saml2Aws {
}

impl Saml2Aws {
    /// Create a new instance of Saml2Aws.
    ///
    /// This struct is mainly used to call the actual 'saml2aws' command.
    pub fn new() -> Self {
        Saml2Aws{}
    }

    /// Checks if the saml2aws binary exists by calling it
    pub fn exists(&self) -> bool {
        match Command::new("saml2aws")
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status() {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }

    /// Lists all available roles
    pub fn list_roles(&self, mfa: &str) -> Result<Vec<Account>, io::Error> {
        // Create a fake stdin where we input our MFA token

        let mut c = match Command::new("saml2aws")
            .arg("list-roles")
            .arg("--skip-prompt")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn() {
                Ok(c) => c,
                Err(e) => {
                    return Err(e);
                },
            };

        {
            let mut stdin = c.stdin.as_mut().unwrap();
            let mut writer = BufWriter::new(&mut stdin);

            writer.write_all(format!("{}\n", mfa).as_bytes()).unwrap();
        }

        let output = c.wait_with_output().unwrap();
        if output.status.code().unwrap() != 0 {
            // TODO: Parse error
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Error executing saml2aws"));
        }

        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));

        Ok(self.parse_role_response(&String::from_utf8_lossy(&output.stdout)))
    }

    fn parse_role_response(&self, output: &str) -> Vec<Account> {
		let re_account = Regex::new(r"Account: (.*?) \(([0-9]+)\)\n(?m)^(.*)$(?-m)").unwrap();	

		let mut accounts: Vec<Account> = vec![];

		for cap in re_account.captures_iter(output) {
			accounts.push(Account{
				id: cap[2].into(),
				name: cap[1].into(),
                arn: cap[3].into(),
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

		let s = Saml2Aws::new();
		let res = s.parse_role_response(output);

		assert_eq!(res.len(), 1);
        assert_eq!(res[0].name, "example-account-dev");
        assert_eq!(res[0].id, "123456890");
        assert_eq!(res[0].arn, "arn:aws:iam::1234567890:role/Administrator");
    }
}
