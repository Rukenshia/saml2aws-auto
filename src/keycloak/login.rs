use std::error::Error;
use std::io::{self, ErrorKind, Read};

use super::cookie::{self, CookieJar};
use super::reqwest;
use super::scraper::Html;

use super::form::{extract_saml_response, FormInfo};
use super::mfa::get_totp_form;

pub fn get_assertion_response(
    cookie_jar: &mut CookieJar,
    url: &str,
    username: &str,
    password: &str,
    token: &str,
    do_aws_page_request: bool,
) -> Result<(String, Option<String>), io::Error> {
    let client = reqwest::Client::new();
    let mut doc = get_login_page(&client, cookie_jar, url)?;
    let form = get_login_form(&doc);

    if let Ok(form) = form {
        doc = do_login_flow(&client, cookie_jar, &form.action, username, password, token)?;
    }

    let (saml_response, aws_form) = get_intermediate_response(&doc)?;

    let aws_web = match do_aws_page_request {
        true => Some(submit_saml_response_form(
            &client,
            cookie_jar,
            &aws_form.action,
            &saml_response,
        )?),
        false => None,
    };

    Ok((saml_response, aws_web))
}

fn do_login_flow(
    client: &reqwest::Client,
    cookie_jar: &mut CookieJar,
    login_url: &str,
    username: &str,
    password: &str,
    token: &str,
) -> Result<String, io::Error> {
    // Submit User+Pass
    let params = [("username", username), ("password", password)];
    let doc = submit_form(&client, cookie_jar, login_url, &params)?;
    let totp = get_totp_form(&doc)?;

    // Submit TOTP
    let params = [("totp", token)];
    let doc = submit_form(&client, cookie_jar, &totp.action, &params)?;

    Ok(doc)
}

pub fn submit_form(
    client: &reqwest::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
    params: &[(&str, &str)],
) -> Result<String, io::Error> {
    let mut cookie = reqwest::header::Cookie::new();
    {
        cookie_jar.iter().for_each(|cookie_from_jar| {
            cookie.set(
                cookie_from_jar.name().to_string(),
                cookie_from_jar.value().to_string(),
            );
        });
    }

    let mut res = client
        .post(url)
        .form(&params)
        .header(cookie)
        .send()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?;

    // Then we add cookies in the jar given the response
    if let Some(raw_cookies) = res.headers().get::<reqwest::header::SetCookie>() {
        raw_cookies.iter().for_each(|raw_cookie| {
            let cookie = cookie::Cookie::parse(format!("{}", raw_cookie)).unwrap();
            cookie_jar.add(cookie)
        })
    }

    let body = res
        .text()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?;

    Ok(body)
}

pub fn get_login_page(
    client: &reqwest::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
) -> Result<String, io::Error> {
    let mut cookie = reqwest::header::Cookie::new();
    {
        cookie_jar.iter().for_each(|cookie_from_jar| {
            cookie.set(
                cookie_from_jar.name().to_string(),
                cookie_from_jar.value().to_string(),
            );
        });
    }

    let mut res = client
        .get(url)
        .header(cookie)
        .send()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?;

    // Then we add cookies in the jar given the response
    if let Some(raw_cookies) = res.headers().get::<reqwest::header::SetCookie>() {
        raw_cookies.iter().for_each(|raw_cookie| {
            let cookie = cookie::Cookie::parse(format!("{}", raw_cookie)).unwrap();
            cookie_jar.add(cookie)
        })
    }

    Ok(res
        .text()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?)
}

pub fn get_login_form(document: &str) -> Result<FormInfo, io::Error> {
    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form#form-login") {
        Some(f) => f,
        None => {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Could not find login form",
            ))
        }
    };

    Ok(form)
}

pub fn get_intermediate_response(document: &str) -> Result<(String, FormInfo), io::Error> {
    if document.contains("Invalid authenticator code") {
        return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid MFA Token"));
    }

    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form") {
        Some(f) => f,
        None => {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Could not find saml response submit form",
            ))
        }
    };

    let saml_response = match extract_saml_response(&doc) {
        Some(r) => r,
        None => {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Could not find saml response data",
            ))
        }
    };

    Ok((saml_response, form))
}

pub fn submit_saml_response_form(
    client: &reqwest::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
    response: &str,
) -> Result<String, io::Error> {
    let params = [("SAMLResponse", response)];

    let mut cookie = reqwest::header::Cookie::new();
    {
        cookie_jar.iter().for_each(|cookie_from_jar| {
            cookie.set(
                cookie_from_jar.name().to_string(),
                cookie_from_jar.value().to_string(),
            );
        });
    }

    let mut res = client
        .post(url)
        .form(&params)
        .header(cookie)
        .send()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?;

    // Then we add cookies in the jar given the response
    if let Some(raw_cookies) = res.headers().get::<reqwest::header::SetCookie>() {
        raw_cookies.iter().for_each(|raw_cookie| {
            let cookie = cookie::Cookie::parse(format!("{}", raw_cookie)).unwrap();
            cookie_jar.add(cookie)
        })
    }

    Ok(res
        .text()
        .map_err(|e| io::Error::new(ErrorKind::Other, e.description()))?)
}
