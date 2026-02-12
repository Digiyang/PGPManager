use crate::{
    sequoia_openpgp::{
        certificate_manager::CertificateManager,
        wrapper_fun::{
            add_user_tui, edit_expiration_time_tui, edit_password_tui, export_certificate_tui,
            generate_keypair_tui, revoke, split_users_tui,
        },
    },
    utils::{
        check_valid_cert::{check_certificate, CertificateType},
        extract_users::extract_users_from_certificate,
        list_directory_content::list_directory_contents,
    },
    widgets::list::StatefulList,
};
use crossterm::event::{self, Event, KeyCode};

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use ratatui::{backend::CrosstermBackend, Terminal};

use super::{
    app::App,
    ui::{show_input_popup, ui},
};

// todo: move the function to a separate file
pub fn clear_screen() {
    if let Ok(output) = Command::new("clear").output() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

pub fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    mut app: App,
) -> Result<(), Box<dyn std::error::Error>> {
    let manager = CertificateManager;
    let (tx, rx) = mpsc::channel();

    // Spawn a separate thread to receive events from Crossterm
    thread::spawn(move || {
        let mut last_event_time = Instant::now();
        loop {
            let event = if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                match event::read() {
                    Ok(ev) => ev,
                    Err(_) => break,
                }
            } else if Instant::now().duration_since(last_event_time) > Duration::from_secs(1) {
                crossterm::event::Event::Resize(0, 0)
            } else {
                continue;
            };
            last_event_time = Instant::now();
            // Exit thread when receiver is dropped (app has quit)
            if tx.send(event).is_err() {
                break;
            }
        }
    });

    loop {
        terminal.draw(|f| ui(f, &mut app))?;
        if let Event::Key(key) = rx.recv()? {
            if app.help_active {
                match key.code {
                    KeyCode::Char('h') | KeyCode::Esc => {
                        app.help_active = false;
                    }
                    KeyCode::Up => {
                        app.help_items.previous();
                    }
                    KeyCode::Down => {
                        app.help_items.next();
                    }
                    KeyCode::Char('q') => {
                        return Ok(());
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('h') => {
                        app.help_active = true;
                    }
                    KeyCode::Char('q') => {
                        return Ok(());
                    }
                    // get key details
                    KeyCode::Char('d') => {
                        if app.key_details.is_none() {
                            if let Some(cert_path) = app.items.selected() {
                                let cert_path = Path::new(&cert_path);
                                match check_certificate(cert_path) {
                                    CertificateType::Cert(_) => {
                                        match manager.get_key_details(&cert_path.to_string_lossy())
                                        {
                                            Ok(cert_details) => {
                                                app.key_details = Some(cert_details);
                                                app.scroll_state = 0;
                                            }
                                            Err(_) => {
                                                app.key_details = Some(
                                                    "Error retrieving key details".to_string(),
                                                );
                                                app.scroll_state = 0;
                                            }
                                        }
                                    }
                                    CertificateType::Sig(_) => {
                                        match manager
                                            .get_signature_details(&cert_path.to_string_lossy())
                                        {
                                            Ok(details) => {
                                                app.key_details = Some(details);
                                                app.scroll_state = 0;
                                            }
                                            Err(_) => {
                                                app.key_details = Some(
                                                    "Error retrieving signature details"
                                                        .to_string(),
                                                );
                                                app.scroll_state = 0;
                                            }
                                        }
                                    }
                                    CertificateType::Invalid => {
                                        show_input_popup(terminal, "Not a valid certificate!")?;
                                    }
                                }
                            }
                        } else {
                            app.key_details = None;
                        }
                    }

                    // generate a new keypair (secret + revocation certificate)
                    KeyCode::Char('g') => match generate_keypair_tui(&manager, terminal) {
                        Ok(()) => {
                            show_input_popup(terminal, "Key pair generated successfully.")?;
                            app.items = StatefulList::with_items(list_directory_contents(
                                &app.current_dir,
                            )?);
                        }
                        Err(e) => {
                            show_input_popup(
                                terminal,
                                &format!("Error generating key pair: {}", e),
                            )?;
                        }
                    },
                    // export certificate from keypair
                    KeyCode::Char('e') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    match export_certificate_tui(
                                        &manager,
                                        terminal,
                                        &cert_path.to_string_lossy(),
                                    ) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "Certificate exported successfully.",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(terminal, &format!("Error: {}", e))?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    // change secret key password
                    KeyCode::Char('p') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    match edit_password_tui(
                                        &manager,
                                        terminal,
                                        &cert_path.to_string_lossy(),
                                    ) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "Password changed successfully.",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(terminal, &format!("Error: {}", e))?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    // change expiration time
                    KeyCode::Char('t') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    match edit_expiration_time_tui(
                                        &manager,
                                        terminal,
                                        &cert_path.to_string_lossy(),
                                    ) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "Expiration time changed successfully.",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(terminal, &format!("Error: {}", e))?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    // add user id
                    KeyCode::Char('a') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    match add_user_tui(
                                        &manager,
                                        terminal,
                                        &cert_path.to_string_lossy(),
                                    ) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "UserID added successfully.",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(terminal, &format!("Error: {}", e))?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    // export a new public key for selected user(s)
                    KeyCode::Char('u') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    let user_emails = extract_users_from_certificate(cert_path)?;
                                    let users = StatefulList::with_items(user_emails);
                                    match split_users_tui(
                                        &manager,
                                        terminal,
                                        &cert_path.to_string_lossy(),
                                        users,
                                    ) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "Split users operation completed successfully",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(
                                                terminal,
                                                &format!("Split users operation failed: {}", e),
                                            )?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        if let Some(cert_path) = app.items.selected() {
                            let cert_path = Path::new(&cert_path);
                            match check_certificate(cert_path) {
                                CertificateType::Cert(_) => {
                                    match revoke(&manager, terminal, &cert_path.to_string_lossy()) {
                                        Ok(()) => {
                                            show_input_popup(
                                                terminal,
                                                "Certificate revoked successfully.",
                                            )?;
                                        }
                                        Err(e) => {
                                            show_input_popup(terminal, &format!("Error: {}", e))?;
                                        }
                                    }
                                }
                                _ => {
                                    show_input_popup(terminal, "Not a valid certificate!")?;
                                }
                            }
                        }
                    }
                    KeyCode::Left => app.items.unselect(),
                    KeyCode::Down => {
                        if let Some(details) = &app.key_details {
                            app.scroll_state =
                                (app.scroll_state + 1).min(details.lines().count() - 1);
                        } else {
                            app.items.next();
                        }
                    }
                    KeyCode::Up => {
                        if app.key_details.is_some() {
                            app.scroll_state = app.scroll_state.saturating_sub(1);
                        } else {
                            app.items.previous();
                        }
                    }
                    KeyCode::Enter => {
                        let selected_path = app
                            .items
                            .selected()
                            .map(|s| PathBuf::from(s.as_str()))
                            .unwrap_or_else(|| app.current_dir.clone());
                        if selected_path.is_dir() {
                            let new_files = list_directory_contents(&selected_path)?;
                            app.current_dir = selected_path;
                            app.items = StatefulList::with_items(new_files.into_iter().collect());
                        }
                    }
                    KeyCode::Char(' ') => {
                        if let Some(parent) = app.current_dir.parent() {
                            let new_files = list_directory_contents(parent)?;
                            app.current_dir = parent.to_path_buf();
                            app.items = StatefulList::with_items(new_files.into_iter().collect());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
