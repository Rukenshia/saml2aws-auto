#[derive(Debug, Deserialize)]
#[serde(rename = "Response")]
pub struct AssumeRoleResponse {
    #[serde(rename = "$value")]
    pub response: Vec<SAMLResponse>,
}

#[derive(Debug, Deserialize)]
pub struct SAMLResponse {
    #[serde(rename = "$value")]
    pub result: Vec<AssumeRoleResult>,
}
#[derive(Debug, Deserialize)]
pub struct AssumedRoleUser {
    #[serde(rename = "Arn")]
    pub arn: String,
}
#[derive(Debug, Deserialize)]
pub struct ResponseMetadata {
    #[serde(rename = "RequestId")]
    pub request_id: String,
}
#[derive(Debug, Deserialize)]
pub enum AssumeRoleResult {
    Audience(String),
    AssumedRoleUser(Vec<AssumedRoleUser>),
    Subject(String),
    NameQualifier(String),
    SubjectType(String),
    Issuer(String),
    Credentials(Credentials),
    ResponseMetadata(Vec<ResponseMetadata>),
    RequestId(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct Credentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}
