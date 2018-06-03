use std::env;
use std::path::PathBuf;

use super::ini;

pub fn load_credentials_file() -> Result<(ini::Ini, PathBuf), ini::ini::Error> {
    let filename = env::home_dir().unwrap().join(".aws").join("credentials");

    ini::Ini::load_from_file(&filename).map(|o| (o, filename))
}
