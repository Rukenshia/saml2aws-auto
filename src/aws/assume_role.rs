use rusoto_core::{reactor::RequestDispatcher, Region};
use rusoto_credential::StaticProvider;
use rusoto_sts::{
    AssumeRoleWithSAMLError, AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient,
};

pub fn assume_role(
    arn: &str,
    principal: &str,
    saml_assertion: &str,
    session_duration: Option<i64>,
) -> Result<AssumeRoleWithSAMLResponse, AssumeRoleWithSAMLError> {
    let c = StsClient::new(
        RequestDispatcher::default(),
        StaticProvider::new_minimal("UNSET".into(), "UNSET".into()),
        Region::EuCentral1,
    );

    c.assume_role_with_saml(&AssumeRoleWithSAMLRequest {
        role_arn: arn.into(),
        principal_arn: principal.into(),
        policy: None,
        saml_assertion: saml_assertion.into(),
        duration_seconds: session_duration,
    }).sync()
}
