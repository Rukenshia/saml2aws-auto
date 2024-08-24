use scraper::{node::Element, ElementRef, Html, Selector};

#[derive(Debug, PartialEq)]
pub enum FormMethod {
    GET,
    POST,
}

#[derive(Debug)]
pub struct MFADevice {
    pub name: String,
    pub id: String,
}

#[derive(Debug)]
pub struct FormInfo {
    pub method: FormMethod,
    pub action: String,
    pub mfa_devices: Vec<MFADevice>,
}

impl FormInfo {
    pub fn from_html(doc: &Html, selector: &str) -> Option<Self> {
        let forms: Vec<ElementRef> = doc.select(&Selector::parse(selector).unwrap()).collect();

        if forms.len() == 0 {
            return None;
        }

        let form: &Element = forms[0].value();

        let method = match form.attr("method")? {
            "GET" | "get" => FormMethod::GET,
            "POST" | "post" => FormMethod::POST,
            _ => return None,
        };
        let action = form.attr("action")?.into();

        let options: Vec<ElementRef> = doc
            .select(
                &Selector::parse(&format!(
                    "{} select[name=selectedCredentialId] option",
                    selector
                ))
                .unwrap(),
            )
            .collect::<Vec<ElementRef>>();

        let mut mfa_devices: Vec<MFADevice> = vec![];

        for option in options {
            let value: &Element = option.value();

            if value.attr("disabled").is_some() {
                continue;
            }

            mfa_devices.push(MFADevice {
                name: option.text().next().unwrap().to_owned(),
                id: value.attr("value").unwrap().to_owned(),
            });
        }

        trace!("mfa devices: {:?}", mfa_devices);

        Some(FormInfo {
            method,
            action,
            mfa_devices,
        })
    }
}

pub fn extract_saml_response(doc: &Html) -> Option<String> {
    let elements: Vec<ElementRef> = doc
        .select(&Selector::parse("input[name=\"SAMLResponse\"]").unwrap())
        .collect();

    if elements.len() == 0 {
        return None;
    }

    elements[0].value().attr("value").map(|v| v.into())
}
