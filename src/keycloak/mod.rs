use std::error::Error;
use std::fmt::{Display, Formatter, Result};

use super::cookie;
use super::reqwest;
use super::scraper;

mod form;
pub mod login;
pub mod mfa;

#[derive(Debug)]
pub struct KeycloakError {
    description: String,

    pub kind: KeycloakErrorKind,
}

#[derive(Debug, PartialEq)]
pub enum KeycloakErrorKind {
    Io,
    Http,
    InvalidCredentials,
    InvalidToken,
    InvalidMFADevice,
    InvalidForm,
    FormNotFound,
    PasswordUpdateRequired,
    TermsAndConditionsNotAccepted,
}

impl KeycloakError {
    pub fn new(kind: KeycloakErrorKind, message: &str) -> Self {
        KeycloakError {
            description: message.into(),
            kind,
        }
    }
}

impl Error for KeycloakError {
    fn description(&self) -> &str {
        &self.description
    }
}

impl Display for KeycloakError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.write_str(&self.description)
    }
}
