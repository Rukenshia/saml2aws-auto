use std::io;

use super::client;
use super::dirs;
use super::ini;
use super::regex;

use scraper::{Html, Selector};

pub mod assume_role;
pub mod credentials;
pub mod xml;

use saml::parse_assertion;

#[derive(Debug)]
pub struct AWSAccountInfo {
    pub name: String,
    pub arn: String,
}

pub fn extract_saml_accounts(body: &str, saml_response_b64: &str) -> Result<Vec<AWSAccountInfo>, io::Error> {
    trace!("html={:?}", body);
    let doc = Html::parse_document(body);

    let name_selector = Selector::parse("div.saml-account-name").unwrap();
    let arn_selector = Selector::parse("label.saml-role-description").unwrap();
    let re = regex::Regex::new(r"Account: (.*?) \(").unwrap();

    let info_from_html: Vec<AWSAccountInfo> = doc
        .select(&Selector::parse("fieldset > div.saml-account").unwrap())
        .map(|div| {
            let name = div.select(&name_selector).next().unwrap();
            let arn = div.select(&arn_selector).next().unwrap();

            let name = re.captures(&name.inner_html()).unwrap()[1].into();

            AWSAccountInfo {
                name: name,
                arn: arn.value().attr("for").unwrap().into(),
            }
        })
        .collect();

    if info_from_html.len() > 0 {
        return Ok(info_from_html);
    }

    // This branch is run when the HTML Response did not contain any AWS accounts
    // but the SAML Assertion might include a single account. We will now parse
    // the assertion and hopefully find a single account in this.
    // Since the SAML Assertion will *not* include the account alias, the result
    // will be returned with the account number as "name".
    let parsed_assertion = parse_assertion(saml_response_b64)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.description()))?;

    if parsed_assertion.roles.len() == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No role was found in the HTML or SAML Assertion"));
    }

    // Take the first account
    Ok(vec![AWSAccountInfo{
        name: parsed_assertion.roles[0].account_id.clone(),
        arn: parsed_assertion.roles[0].arn.clone(),
    }])
}
