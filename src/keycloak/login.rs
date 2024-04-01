use super::cookie::{self, CookieJar};
use super::reqwest;
use super::scraper::Html;

use super::form::{extract_saml_response, FormInfo};
use super::mfa::get_totp_form;
use super::{KeycloakError, KeycloakErrorKind};
use crate::client;

pub fn get_assertion_response(
    cookie_jar: &mut CookieJar,
    url: &str,
    username: &str,
    password: &str,
    mfa_device: Option<&str>,
    token: &str,
    do_aws_page_request: bool,
) -> Result<(String, Option<String>), KeycloakError> {
    trace!("get_assertion_response.start");
    let client = client::get_proxied_client_builder().build().unwrap();
    let mut doc = get_login_page(&client, cookie_jar, url)?;
    let form = get_login_form(&doc);

    if let Ok(form) = form {
        trace!("get_assertion_response.do_login_flow");
        doc = do_login_flow(
            &client,
            cookie_jar,
            &form.action,
            username,
            password,
            mfa_device,
            token,
        )?;
    } else {
        trace!("get_assertion_response.skip_login_flow");
    }

    trace!("get_assertion_response.get_intermediate_response");
    let (saml_response, aws_form) = get_intermediate_response(&doc)?;

    let aws_web = match do_aws_page_request {
        true => {
            trace!("get_assertion_response.submit_saml_response_form");
            Some(submit_saml_response_form(
                &client,
                cookie_jar,
                &aws_form.action,
                &saml_response,
            )?)
        }
        false => None,
    };

    trace!("get_assertion_response.ok");

    Ok((saml_response, aws_web))
}

fn do_login_flow(
    client: &reqwest::blocking::Client,
    cookie_jar: &mut CookieJar,
    login_url: &str,
    username: &str,
    password: &str,
    mfa_device: Option<&str>,
    token: &str,
) -> Result<String, KeycloakError> {
    trace!("do_login_flow.start");
    // Submit User+Pass
    let params = [("username", username), ("password", password)];

    trace!("do_login_flow.submit_form");
    let doc = submit_form(&client, cookie_jar, login_url, &params)?;
    trace!("do_login_flow.get_totp_form");
    let totp = get_totp_form(&doc)?;

    // Submit TOTP
    let mut params = vec![("otp", token), ("totp", token)];

    if let Some(mfa_device) = mfa_device {
        trace!("mfa configured, trying to find device in form");

        if let Some(device) = totp
            .mfa_devices
            .iter()
            .find(|&device| device.name == mfa_device)
        {
            trace!("mfa device found with id {}", &device.id);
            params.push(("selectedCredentialId", &device.id));
        } else {
            trace!("mfa device not found, skipping param");
        }
    }
    trace!("do_login_flow.submit_form_totp");
    let doc = submit_form(&client, cookie_jar, &totp.action, &params)?;

    Ok(doc)
}

pub fn submit_form(
    client: &reqwest::blocking::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
    params: &[(&str, &str)],
) -> Result<String, KeycloakError> {
    let cookie = cookie_jar
        .iter()
        .map(|cookie_from_jar| format!("{}={}", cookie_from_jar.name(), cookie_from_jar.value()))
        .collect::<Vec<String>>()
        .join("; ");

    let res = client
        .post(url)
        .form(&params)
        .header("Cookie", cookie)
        .send()
        .map_err(|e| KeycloakError::new(KeycloakErrorKind::Http, &e.to_string()))?;

    // Then we add cookies in the jar given the response
    res.headers().iter().for_each(|(name, raw_cookie)| {
        if name != "set-cookie" {
            return;
        }

        trace!("submit_form.raw_cookie={}", raw_cookie.to_str().unwrap());
        let cookie = cookie::Cookie::parse(format!("{}", raw_cookie.to_str().unwrap())).unwrap();

        cookie_jar.add(cookie);
    });

    let body = res
        .text()
        .map_err(|e| KeycloakError::new(KeycloakErrorKind::Http, &e.to_string()))?;

    if body.contains("Invalid username or password") {
        return Err(KeycloakError::new(
            KeycloakErrorKind::InvalidCredentials,
            "Invalid username or password. If you changed your password recently, please run saml2aws-auto configure",
        ));
    } else if body.contains("kc-terms-text") {
        return Err(KeycloakError::new(
            KeycloakErrorKind::TermsAndConditionsNotAccepted,
            "Terms and Conditions not accepted. Please log in via your web browser to accept them",
        ));
    } else if body.contains("Update password") {
        return Err(KeycloakError::new(KeycloakErrorKind::PasswordUpdateRequired, "You need to update your password in Keycloak before you can login. Please visit the website to change your password."));
    } else if body
        .contains("Unexpected error when handling authentication request to identity provider.")
    {
        return Err(KeycloakError::new(KeycloakErrorKind::InvalidMFADevice, "A MFA device is configured, but the name could not be found. Double check your config with `saml2aws-auto configure`"));
    }

    Ok(body)
}

pub fn get_login_page(
    client: &reqwest::blocking::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
) -> Result<String, KeycloakError> {
    trace!("get_login_page.start");
    let cookie = cookie_jar
        .iter()
        .map(|cookie_from_jar| format!("{}={}", cookie_from_jar.name(), cookie_from_jar.value()))
        .collect::<Vec<String>>()
        .join("; ");

    trace!("get_login_page.cookie={}", &cookie);

    trace!("get_login_page.send");
    let res = client
        .get(url)
        .header("Cookie", cookie)
        .send()
        .map_err(|e| {
            trace!("get_login_page.map_err");
            error!("get_login_page: {:?}", e);

            KeycloakError::new(KeycloakErrorKind::Http, &e.to_string())
        })?;

    // Then we add cookies in the jar given the response
    trace!("get_login_page.cookies");
    res.headers().iter().for_each(|(name, raw_cookie)| {
        if name != "set-cookie" {
            return;
        }

        trace!("get_login_page.raw_cookie={}", raw_cookie.to_str().unwrap());
        let cookie = cookie::Cookie::parse(format!("{}", raw_cookie.to_str().unwrap())).unwrap();

        cookie_jar.add(cookie);
    });

    Ok(res.text().map_err(|e| {
        trace!("get_login_page.end.map_err");
        error!("get_login_page: {:?}", e);
        KeycloakError::new(KeycloakErrorKind::Io, &e.to_string())
    })?)
}

pub fn get_login_form(document: &str) -> Result<FormInfo, KeycloakError> {
    trace!("get_login_form.start");
    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form#form-login") {
        Some(f) => f,
        None => {
            trace!("get_login_page.no_form");
            debug!("{}", document);
            return Err(KeycloakError::new(
                KeycloakErrorKind::FormNotFound,
                "Could not find login form",
            ));
        }
    };

    trace!("get_login_form.ok");
    Ok(form)
}

pub fn get_intermediate_response(document: &str) -> Result<(String, FormInfo), KeycloakError> {
    trace!("get_intermediate_response.start");

    if document.contains("Invalid authenticator code") {
        trace!("get_intermediate_response.invalid_code");
        return Err(KeycloakError::new(
            KeycloakErrorKind::InvalidToken,
            "Invalid MFA token. Check if you are using the correct MFA device. If you have multiple MFA devices set up in Keycloak, update your config with `saml2aws-auto configure`",
        ));
    }

    let doc = Html::parse_document(document);

    let form = match FormInfo::from_html(&doc, "form") {
        Some(f) => f,
        None => {
            trace!("get_intermediate_response.no_form");
            debug!("{}", document);
            return Err(KeycloakError::new(
                KeycloakErrorKind::FormNotFound,
                "Could not find saml submit form",
            ));
        }
    };

    trace!("get_intermediate_response.extract_saml_response");
    let saml_response = match extract_saml_response(&doc) {
        Some(r) => r,
        None => {
            trace!("get_intermediate_response.no_response");
            return Err(KeycloakError::new(
                KeycloakErrorKind::Io,
                "Could not find saml response",
            ));
        }
    };

    trace!("get_intermediate_response.ok");
    Ok((saml_response, form))
}

pub fn submit_saml_response_form(
    client: &reqwest::blocking::Client,
    cookie_jar: &mut CookieJar,
    url: &str,
    response: &str,
) -> Result<String, KeycloakError> {
    let params = [("SAMLResponse", response)];

    let cookie = cookie_jar
        .iter()
        .map(|cookie_from_jar| format!("{}={}", cookie_from_jar.name(), cookie_from_jar.value()))
        .collect::<Vec<String>>()
        .join("; ");
    trace!("submit_saml_response_form.cookie={}", &cookie);

    let res = client
        .post(url)
        .form(&params)
        .header("Cookie", cookie)
        .send()
        .map_err(|e| KeycloakError::new(KeycloakErrorKind::Http, &e.to_string()))?;

    // Then we add cookies in the jar given the response
    res.headers().iter().for_each(|(name, raw_cookie)| {
        if name != "set-cookie" {
            return;
        }

        trace!(
            "submit_saml_response_form.raw_cookie={}",
            raw_cookie.to_str().unwrap()
        );
        let cookie = cookie::Cookie::parse(format!("{}", raw_cookie.to_str().unwrap())).unwrap();

        cookie_jar.add(cookie);
    });

    Ok(res
        .text()
        .map_err(|e| KeycloakError::new(KeycloakErrorKind::Io, &e.to_string()))?)
}
