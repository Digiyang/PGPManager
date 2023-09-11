use std::{fs, io, path::Path};

pub fn list_directory_contents(dir: &Path) -> Result<Vec<String>, io::Error> {
    fs::read_dir(dir)?
        .map(|res| res.map(|e| e.path().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
}
