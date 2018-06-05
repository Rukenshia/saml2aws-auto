use std::env;
use std::fs::File;
use std::path::PathBuf;

use super::ini;

pub fn load_credentials_file() -> Result<(ini::Ini, PathBuf), ini::ini::Error> {
    let filename = env::home_dir().unwrap().join(".aws").join("credentials");

    if !filename.exists() {
        File::create(&filename).expect(
            "Could not create $HOME/.aws/credentials. Does the directory $HOME/.aws exist?",
        );
    }

    ini::Ini::load_from_file(&filename).map(|o| (o, filename))
}
