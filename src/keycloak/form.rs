use scraper::{node::Element, ElementRef, Html, Selector};

#[derive(Debug)]
pub enum FormMethod {
    GET,
    POST,
}

#[derive(Debug)]
pub struct FormInfo {
    pub method: FormMethod,
    pub action: String,
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

        Some(FormInfo { method, action })
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
