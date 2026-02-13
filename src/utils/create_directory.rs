use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn create_directory(
    path: &Path,
    secret_key_path: &Path,
    cert_path: &Path,
    rev_path: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    fs::create_dir_all(secret_key_path)?;
    fs::create_dir_all(cert_path)?;
    fs::create_dir_all(rev_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let restricted = fs::Permissions::from_mode(0o700);
        fs::set_permissions(secret_key_path, restricted.clone())?;
        fs::set_permissions(rev_path, restricted)?;
    }

    Ok(())
}

pub fn init_directory() -> Result<(), anyhow::Error> {
    let home_dir =
        home::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let main_path = PathBuf::from(format!("{}/.pgpman", &home_dir.display()));
    let sk_path = PathBuf::from(format!("{}/.pgpman/secrets", &home_dir.display()));
    let cert_path = PathBuf::from(format!("{}/.pgpman/certificates", &home_dir.display()));
    let rev_path = PathBuf::from(format!("{}/.pgpman/revocation", &home_dir.display()));
    create_directory(&main_path, &sk_path, &cert_path, &rev_path)?;

    Ok(())
}

pub fn create_file(
    f: Option<&str>,
) -> Result<Option<Box<dyn io::Write + Sync + Send>>, anyhow::Error> {
    match f {
        None | Some("-") => Ok(Some(Box::new(io::stdout()))),
        Some(f) => Ok(Some(Box::new(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(f)?,
        ))),
    }
}

pub fn create_secret_file(
    f: Option<&str>,
) -> Result<Option<Box<dyn io::Write + Sync + Send>>, anyhow::Error> {
    match f {
        None | Some("-") => Ok(Some(Box::new(io::stdout()))),
        #[cfg(unix)]
        Some(f) => {
            let file = OpenOptions::new()
                .write(true)
                .truncate(false)
                .create(true)
                .mode(0o600)
                .open(f)?;
            // Enforce 0o600 even if the file already existed with looser permissions.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.set_len(0)?;
            Ok(Some(Box::new(file)))
        }
        #[cfg(not(unix))]
        Some(f) => Ok(Some(Box::new(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(f)?,
        ))),
    }
}

#[test]
fn test_create_folder() {
    // Create a temporary directory for testing
    let temp_dir = tempfile::tempdir().unwrap();

    // Create a subdirectory within the temporary directory
    let test_dir = temp_dir.path().join("test_folder");
    let test_dir1 = temp_dir.path().join("test_folder/sk");
    let test_dir2 = temp_dir.path().join("test_folder/cert");
    let test_dir3 = temp_dir.path().join("test_folder/rev");
    // Create the directory
    assert!(create_directory(&test_dir, &test_dir1, &test_dir2, &test_dir3).is_ok());

    // Check that the directory exists
    assert!(test_dir.is_dir());

    // Clean up the temporary directory
    temp_dir.close().unwrap();
}

#[test]
#[cfg(unix)]
fn test_create_secret_file_enforces_permissions_on_existing_file() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("secret.pgp");

    // Create a file with world-readable permissions (0o644).
    fs::write(&file_path, b"old secret").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
        0o644
    );

    // Overwrite via create_secret_file — permissions must be tightened.
    let path_str = file_path.to_str().unwrap();
    let _writer = create_secret_file(Some(path_str)).unwrap();
    assert_eq!(
        fs::metadata(&file_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
