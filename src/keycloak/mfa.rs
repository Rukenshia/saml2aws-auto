use scraper::Html;

use super::form::FormInfo;
use super::{KeycloakError, KeycloakErrorKind};

pub fn get_totp_form(document: &str) -> Result<FormInfo, KeycloakError> {
    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form#kc-totp-login-form") {
        Some(f) => f,
        None => {
            return Err(KeycloakError::new(
                KeycloakErrorKind::FormNotFound,
                "Could not find TOTP form",
            ))
        }
    };

    Ok(form)
}
