use std::str::FromStr;

use super::serde_xml_rs;
use base64::prelude::*;

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
    #[allow(dead_code)]
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

    pub account_id: String,

    #[allow(dead_code)]
    pub role_name: String,
}

pub fn parse_assertion(assertion_b64: &str) -> Result<Assertion, serde_xml_rs::Error> {
    let mut buf: String =
        String::from_utf8(BASE64_STANDARD.decode(&assertion_b64).unwrap()).unwrap();

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

    let raw_assertion: SAMLResponse = serde_xml_rs::from_str(&buf)?;

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
                    let arn: String = split[0].into();
                    let principal_arn = split[1].into();
                    let (account_id, role_name) = arn_to_role_info(&arn);

                    assertion.roles.push(Role {
                        arn,
                        principal_arn,
                        account_id,
                        role_name,
                    });
                }
            }
            _ => {}
        };
    }

    Ok(assertion)
}

// Returns the Account ID and Role Name
fn arn_to_role_info(arn: &str) -> (String, String) {
    let split = arn.split(":").collect::<Vec<&str>>();

    return (split[4].into(), split[5].to_owned().replace("role/", ""));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arn_to_role_info_returns_account_id() {
        let given = "arn:aws:iam::123456789012:role/ARoleName";

        let (account_id, _) = arn_to_role_info(given);

        assert_eq!(account_id, "123456789012");
    }

    #[test]
    fn arn_to_role_info_returns_role_name() {
        let given = "arn:aws:iam::123456789012:role/ARoleName";

        let (_, role_name) = arn_to_role_info(given);

        assert_eq!(role_name, "ARoleName");
    }
}
