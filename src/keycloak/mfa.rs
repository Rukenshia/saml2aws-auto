use std::io::{self, ErrorKind};

use scraper::Html;

use super::form::FormInfo;

pub fn get_totp_form(document: &str) -> Result<FormInfo, io::Error> {
    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form#kc-totp-login-form") {
        Some(f) => f,
        None => {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Could not find totp form",
            ))
        }
    };

    Ok(form)
}
