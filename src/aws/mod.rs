use std::io;

use super::ini;
use super::regex;

use scraper::{Html, Selector};

pub mod assume_role;
pub mod credentials;
pub mod xml;

#[derive(Debug)]
pub struct AWSAccountInfo {
    pub name: String,
    pub arn: String,
}

pub fn extract_saml_accounts(body: &str) -> Result<Vec<AWSAccountInfo>, io::Error> {
    let doc = Html::parse_document(body);

    let name_selector = Selector::parse("div.saml-account-name").unwrap();
    let arn_selector = Selector::parse("label.saml-role-description").unwrap();
    let re = regex::Regex::new(r"Account: (.*?) \(").unwrap();

    Ok(
        doc.select(&Selector::parse("fieldset > div.saml-account").unwrap())
            .map(|div| {
                let name = div.select(&name_selector).next().unwrap();
                let arn = div.select(&arn_selector).next().unwrap();

                let name = re.captures(&name.inner_html()).unwrap()[1].into();

                AWSAccountInfo {
                    name: name,
                    arn: arn.value().attr("for").unwrap().into(),
                }
            })
            .collect(),
    )
}
