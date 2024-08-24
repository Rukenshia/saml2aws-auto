use std::time::Duration;

use client;
use reqwest;

extern crate semver;

#[derive(Deserialize)]
pub struct VersionInfo {
    pub tag_name: String,
}

pub enum VersionComparison {
    HasNewer,
    IsSame,
}

fn get_latest_version() -> Result<VersionInfo, reqwest::Error> {
    client::get_proxied_client_builder()
        .timeout(Duration::from_millis(400))
        .build()?
        .get("https://api.github.com/repos/Rukenshia/saml2aws-auto/releases/latest")
        .send()?
        .json()
}

pub fn compare_version(to: &str) -> Result<VersionComparison, reqwest::Error> {
    let info = get_latest_version()?;
    let remote_version = semver::Version::parse(&info.tag_name).unwrap();
    let current_version = semver::Version::parse(to).unwrap();

    if remote_version > current_version {
        Ok(VersionComparison::HasNewer)
    } else {
        Ok(VersionComparison::IsSame)
    }
}
