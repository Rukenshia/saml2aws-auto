use std::env;
use std::fs::{self, File};
use std::path::PathBuf;

use super::ini;

pub fn load_credentials_file() -> Result<(ini::Ini, PathBuf), ini::ini::Error> {
    let filename = env::home_dir().unwrap().join(".aws");

    if !filename.exists() {
        fs::create_dir(filename).expect(
            "Could not create $HOME/.aws directory. Please check permissions"
        );
    }
    
    let filename = filename.join("credentials");

    if !filename.exists() {
        File::create(&filename).expect(
            "Could not create $HOME/.aws/credentials. Does the directory $HOME/.aws exist?",
        );
    }

    ini::Ini::load_from_file(&filename).map(|o| (o, filename))
}
