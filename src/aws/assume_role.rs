use super::client;
use crate::aws::xml::{AssumeRoleResponse, AssumeRoleResult, Credentials};
use reqwest::blocking::Response;
use serde_xml_rs;
use std::error::Error;
use std::io;

pub fn assume_role(
    arn: &str,
    principal: &str,
    saml_assertion: &str,
    session_duration: Option<i64>,
    sts_endpoint: Option<&str>,
) -> Result<Credentials, impl Error> {
    let res: Response = match client::get_proxied_client_builder()
        .build()
        .unwrap()
        .post(sts_endpoint.unwrap_or("https://sts.amazonaws.com/"))
        .query(&[("Version", "2011-06-15"), ("Action", "AssumeRoleWithSAML")])
        .form(&[
            ("PrincipalArn", principal),
            ("RoleArn", arn),
            ("SAMLAssertion", saml_assertion),
            (
                "DurationSeconds",
                &format!("{}", session_duration.or(Some(3600)).unwrap()),
            ),
        ])
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
    };

    if res.status() != 200 {
        let status = res.status();
        println!("response: '{:?}'", res.text());
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("sts assume role returned {}", status),
        ));
    }

    let text = res.text().unwrap();

    let response: AssumeRoleResponse = serde_xml_rs::from_str(&text).unwrap();

    let credentials = (&response.response[0].result)
        .into_iter()
        .find(|r| match r {
            AssumeRoleResult::Credentials(_) => true,
            _ => false,
        })
        .unwrap();

    let credentials = match credentials {
        AssumeRoleResult::Credentials(ref c) => c,
        _ => panic!("this should never, ever happen. It did. awesome."),
    };

    Ok(credentials.clone())
}
