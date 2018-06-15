use aws::xml::{AssumeRoleResponse, AssumeRoleResult, Credentials};
use reqwest::{Client, Error};
use serde_xml_rs;

pub fn assume_role(
    arn: &str,
    principal: &str,
    saml_assertion: &str,
    session_duration: Option<i64>,
) -> Result<Credentials, Error> {
    let mut res = match Client::new()
        .post("https://sts.amazonaws.com/")
        .query(&[
            ("Version", "2011-06-15"),
            ("Action", "AssumeRoleWithSAML"),
            ("PrincipalArn", principal),
            ("RoleArn", arn),
            ("SAMLAssertion", saml_assertion),
        ])
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            return Err(e);
        }
    };

    let text = res
        .text()
        .unwrap()
        .replace(" xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"", "");

    println!("text is {}", text);

    let response: AssumeRoleResponse = serde_xml_rs::deserialize(text.as_bytes()).unwrap();

    let credentials = (&response.response[0].result)
        .into_iter()
        .find(|r| match r {
            AssumeRoleResult::Credentials(_) => true,
            _ => false,
        })
        .unwrap();

    let credentials = match credentials {
        AssumeRoleResult::Credentials(ref c) => c,
        _ => panic!("wtf"),
    };

    Ok(credentials.clone())
}
