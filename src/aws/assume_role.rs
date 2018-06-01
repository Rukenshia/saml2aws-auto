use rusoto_core::Region;
use rusoto_sts::{
    AssumeRoleWithSAMLError, AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient,
};

pub fn assume_role(
    arn: &str,
    principal: &str,
    saml_assertion: &str,
    session_duration: i64,
) -> Result<AssumeRoleWithSAMLResponse, AssumeRoleWithSAMLError> {
    let c = StsClient::simple(Region::EuCentral1);

    c.assume_role_with_saml(&AssumeRoleWithSAMLRequest {
        role_arn: arn.into(),
        principal_arn: principal.into(),
        policy: None,
        saml_assertion: saml_assertion.into(),
        duration_seconds: Some(session_duration),
    }).sync()
}
