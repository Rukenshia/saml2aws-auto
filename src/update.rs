use std::time::Duration;

use reqwest;

#[derive(Deserialize)]
pub struct VersionInfo {
    pub html_url: String,
    pub tag_name: String,
    pub body: Option<String>,
}

// TODO: actually check for "newer" version using semver comparison
pub enum VersionComparison {
    IsDifferent,
    IsSame,
}

fn get_latest_version() -> Result<VersionInfo, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(400))
        .build()?
        .get("https://api.github.com/repos/Rukenshia/saml2aws-auto/releases/latest")
        .send()?
        .json()
}

pub fn compare_version(to: &str) -> Result<VersionComparison, reqwest::Error> {
    let info = get_latest_version()?;

    if to != info.tag_name {
        Ok(VersionComparison::IsDifferent)
    } else {
        Ok(VersionComparison::IsSame)
    }
}
