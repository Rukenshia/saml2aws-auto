use std::str::FromStr;

use super::base64;
use super::serde_xml_rs;

#[derive(Deserialize, Debug)]
pub struct SAML {
    #[serde(rename = "Response")]
    pub response: SAMLResponse,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Response")]
pub struct SAMLResponse {
    #[serde(rename = "Assertion")]
    pub assertion: SAMLAssertion,
}

#[derive(Deserialize, Debug)]
pub struct SAMLAssertion {
    #[serde(rename = "AttributeStatement")]
    pub attribute_statement: AttributeStatement,
}

#[derive(Deserialize, Debug)]
pub struct AttributeStatement {
    #[serde(rename = "Attribute")]
    pub attributes: Vec<Attribute>,
}

#[derive(Deserialize, Debug)]
pub struct Attribute {
    #[serde(rename = "AttributeValue")]
    pub values: Vec<AttributeValue>,

    #[serde(rename = "FriendlyName", default)]
    pub friendly_name: String,

    #[serde(rename = "Name", default)]
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct AttributeValue {
    #[serde(rename = "$value")]
    pub value: String,
}

/// Assertion is the prettified SAML Assertion struct. It already
/// contains the parsed fields from the raw assertion without further
/// need to move elements around. It is also stripped of unnecessary information
#[derive(Debug)]
pub struct Assertion {
    pub role_session_name: String,
    pub session_duration: i64,
    pub roles: Vec<Role>,
}

#[derive(Debug)]
pub struct Role {
    pub arn: String,
    pub principal_arn: String,
}

pub fn parse_assertion(assertion_b64: &str) -> Result<Assertion, serde_xml_rs::Error> {
    let mut buf: String = String::from_utf8(base64::decode(&assertion_b64).unwrap()).unwrap();

    // https://github.com/RReverser/serde-xml-rs/issues/64
    // remove all namespaces (this is ugly)
    buf = buf
        .replace("<saml:", "<")
        .replace("<samlp:", "<")
        .replace("xmlns:", "")
        .replace("xsi:", "")
        .replace("dsig:", "")
        .replace("</saml:", "</")
        .replace("</samlp:", "</");

    let raw_assertion: SAMLResponse = serde_xml_rs::deserialize(buf.as_bytes())?;

    let mut assertion = Assertion {
        role_session_name: String::new(),
        session_duration: 3600,
        roles: vec![],
    };

    for attribute in &raw_assertion.assertion.attribute_statement.attributes {
        match attribute.friendly_name.as_str() {
            "RoleSessionName" => {
                assertion.role_session_name = attribute.values.get(0).unwrap().value.clone();
            }
            "SessionDuration" => {
                assertion.session_duration =
                    i64::from_str(&attribute.values.get(0).unwrap().value.clone()).unwrap();
            }
            "Role" => {
                for value in &attribute.values {
                    let split = value.value.split(",").collect::<Vec<&str>>();

                    assertion.roles.push(Role {
                        arn: split[0].into(),
                        principal_arn: split[1].into(),
                    });
                }
            }
            _ => {}
        };
    }

    Ok(assertion)
}
