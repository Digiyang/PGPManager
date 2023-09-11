use crossterm::{
    event::EnableMouseCapture,
    execute,
    terminal::{enable_raw_mode, EnterAlternateScreen},
};
use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use tui::{backend::CrosstermBackend, text::Spans, Terminal};

use crate::app::ui::{draw_input_prompt, show_input_popup};

fn create_directory(
    path: &PathBuf,
    secret_key_path: &PathBuf,
    cert_path: &PathBuf,
    rev_path: &PathBuf,
) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    fs::create_dir_all(secret_key_path)?;
    fs::create_dir_all(cert_path)?;
    fs::create_dir_all(rev_path)?;
    Ok(())
}

pub fn init_directory() -> std::io::Result<()> {
    let home_dir = home::home_dir().unwrap();
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
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    match f {
        None => Ok(Some(Box::new(io::stdout()))),
        Some(p) if p == "-" => Ok(Some(Box::new(io::stdout()))),
        Some(f) => {
            let p = Path::new(f);
            if !p.exists() {
                Ok(Some(Box::new(
                    OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(f)?,
                )))
            } else {
                let should_override = draw_input_prompt(
                    &mut terminal,
                    &[Spans::from(
                        format!("File {:?} already exists! Override? (y/N)", p).as_str(),
                    )],
                    true,
                )
                .unwrap();
                if should_override.to_lowercase() == "y" {
                    Ok(Some(Box::new(
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .create(true)
                            .open(f)?,
                    )))
                } else {
                    show_input_popup(&mut terminal, "Operation cancelled!").unwrap();
                    Ok(None)
                }
            }
        }
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
