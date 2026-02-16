use std::{fs::File, io::BufReader};

use ratatui::{
    backend::CrosstermBackend,
    style::{Color, Style},
    text::{Line, Span},
    Terminal,
};
use sequoia_openpgp::{crypto::Password, parse::Parse, Cert};

use crate::app::ui::{draw_input_prompt, show_input_popup, show_user_selection_popup};

use super::certificate_manager::CertificateManager;

const MIN_PASSWORD_LENGTH: usize = 8;

fn validate_password(password: &str) -> Result<(), anyhow::Error> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(anyhow::anyhow!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        ));
    }
    Ok(())
}

fn validate_not_empty(value: &str, field_name: &str) -> Result<(), anyhow::Error> {
    if value.trim().is_empty() {
        return Err(anyhow::anyhow!("{} must not be empty", field_name));
    }
    Ok(())
}

fn validate_filename(name: &str) -> Result<(), anyhow::Error> {
    validate_not_empty(name, "Filename")?;
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(anyhow::anyhow!(
            "Invalid filename: must not contain '..', '/' or '\\'"
        ));
    }
    Ok(())
}

// wrapper function for generating a keypair
pub fn generate_keypair_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<(), anyhow::Error> {
    let style = Style::default().fg(Color::Yellow);
    let user_id_prompt = [Line::from(Span::styled(
        "Enter user id (e.g 'Bob <Bob@domain.de>):",
        style,
    ))];
    let user_id = loop {
        let input = draw_input_prompt(terminal, &user_id_prompt, true)?;
        match validate_not_empty(&input, "User ID") {
            Ok(()) => break input,
            Err(e) => {
                show_input_popup(terminal, &e.to_string())?;
            }
        }
    };

    let prompt_validity = vec![
        "Please specify a validity duration for your key:",
        "    n   = does not expire",
        "    0   = default (2y)",
        "   <n>d = expires in n days",
        "   <n>w = expires in n weeks",
        "   <n>m = expires in n months",
        "   <n>y = expires in n years",
    ];
    let validity_spans: Vec<Line> = prompt_validity
        .into_iter()
        .map(|line| Line::from(Span::styled(line, style)))
        .collect();

    let prompt_cipher = vec![
        "Please select a cypher (default: Cv25519):",
        "    (1) Cv25519",
        "    EdDSA and ECDH over Curve25519 with SHA512 and AES256",
        "    (2) RSA2k",
        "    2048 bit RSA with SHA512 and AES256",
        "    (3) RSA3k",
        "    3072 bit RSA with SHA512 and AES256",
        "    (4) RSA4k",
        "    4096 bit RSA with SHA512 and AES256",
        "    (5) P256",
        "    EdDSA and ECDH over NIST P-256 with SHA256 and AES256",
        "    (6) P384",
        "    EdDSA and ECDH over NIST P-384 with SHA384 and AES256",
        "    (7) P521",
        "    EdDSA and ECDH over NIST P-521 with SHA512 and AES256",
    ];

    let cipher_spans: Vec<Line> = prompt_cipher
        .into_iter()
        .map(|line| Line::from(Span::styled(line, Style::default().fg(Color::Yellow))))
        .collect();

    let validity = draw_input_prompt(terminal, &validity_spans, true)?;
    let cipher = draw_input_prompt(terminal, &cipher_spans, true)?;
    let pw_prompt = [Line::from(Span::styled(
        "Enter password (min. 8 chars, a passphrase is recommended):",
        style,
    ))];
    let pw = loop {
        let input = draw_input_prompt(terminal, &pw_prompt, false)?;
        match validate_password(&input) {
            Ok(()) => break input,
            Err(e) => {
                show_input_popup(terminal, &e.to_string())?;
            }
        }
    };

    let rpw_prompt = [Line::from(Span::styled("Repeat password:", style))];
    let rpw = loop {
        let input = draw_input_prompt(terminal, &rpw_prompt, false)?;
        if pw == input {
            break input;
        }
        show_input_popup(terminal, "Passwords do not match!")?;
    };

    cert_manager.generate_keypair(user_id, validity, cipher, pw, rpw)?;
    Ok(())
}

// wrapper function for the export_certificate function
pub fn export_certificate_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    cert_path: &str,
) -> Result<(), anyhow::Error> {
    let cert = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;

    if !cert.is_tsk() {
        return Err(anyhow::anyhow!("Not a secret key!"));
    } else {
        let secret = cert.primary_key().key().clone().parts_into_secret()?;
        let password =
            draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?.into();
        match secret.decrypt_secret(&password) {
            Ok(_) => {
                let file_name_prompt = [Line::from(
                    "Enter exported certificate name (e.g. name.certificate.pgp):",
                )];
                let file_name = loop {
                    let input = draw_input_prompt(terminal, &file_name_prompt, true)?;
                    match validate_filename(&input) {
                        Ok(()) => break input,
                        Err(e) => {
                            show_input_popup(terminal, &e.to_string())?;
                        }
                    }
                };

                cert_manager.export_certificate(cert_path, &file_name)?;
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Wrong password!"));
            }
        }
    }

    Ok(())
}

pub fn edit_password_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    certificate: &str,
) -> Result<(), anyhow::Error> {
    let key = Cert::from_reader(BufReader::new(File::open(certificate)?))?;
    if !key.is_tsk() {
        return Err(anyhow::anyhow!("Not a secret key!"));
    } else {
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        let original_pw_str =
            draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw_str);
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                let new_pw_prompt = [Line::from(
                    "Enter new password (min. 8 chars, a passphrase is recommended):",
                )];
                let new_password = loop {
                    let input = draw_input_prompt(terminal, &new_pw_prompt, false)?;
                    match validate_password(&input) {
                        Ok(()) => break input,
                        Err(e) => {
                            show_input_popup(terminal, &e.to_string())?;
                        }
                    }
                };

                let repeat_pw_prompt = [Line::from("Repeat new password")];
                let repeat_password = loop {
                    let input = draw_input_prompt(terminal, &repeat_pw_prompt, false)?;
                    if new_password == input {
                        break input;
                    }
                    show_input_popup(terminal, "Passwords do not match!")?;
                };
                cert_manager.edit_password(
                    certificate,
                    &original_pw,
                    new_password,
                    repeat_password,
                )?;
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Wrong password!"));
            }
        }
    }
    Ok(())
}

pub fn edit_expiration_time_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    certificate: &str,
) -> Result<(), anyhow::Error> {
    let style = Style::default().fg(Color::Yellow);
    let prompt_validity = vec![
        "Please specify a validity duration for your key:",
        "    0   = does not expire",
        "   <n>d = expires in n days",
        "   <n>w = expires in n weeks",
        "   <n>m = expires in n months",
        "   <n>y = expires in n years",
    ];
    let validity_spans: Vec<Line> = prompt_validity
        .into_iter()
        .map(|line| Line::from(Span::styled(line, style)))
        .collect();

    let key = Cert::from_reader(BufReader::new(File::open(certificate)?))?;

    if !key.is_tsk() {
        return Err(anyhow::anyhow!("Not a secret key!"));
    } else {
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        let original_pw_str =
            draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw_str);
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                let new_expiration_time = draw_input_prompt(terminal, &validity_spans, true)?;
                cert_manager.edit_expiration_time(
                    certificate,
                    &original_pw,
                    new_expiration_time,
                )?;
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Wrong password!"));
            }
        }
    }

    Ok(())
}

pub fn add_user_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    cert_path: &str,
) -> Result<(), anyhow::Error> {
    let key = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;

    let secret = key.primary_key().key().clone().parts_into_secret()?;
    let original_pw_str = draw_input_prompt(terminal, &[Line::from("Enter key secret:")], false)?;
    let original_pw = Password::from(original_pw_str);
    match secret.decrypt_secret(&original_pw) {
        Ok(_) => {
            let new_user_prompt = [Line::from("Enter new user:")];
            let new_user = loop {
                let input = draw_input_prompt(terminal, &new_user_prompt, true)?;
                match validate_not_empty(&input, "User ID") {
                    Ok(()) => break input,
                    Err(e) => {
                        show_input_popup(terminal, &e.to_string())?;
                    }
                }
            };
            cert_manager.add_user(cert_path, &original_pw, new_user)?;
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Wrong password!"));
        }
    }
    Ok(())
}

pub fn split_users_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    cert_path: &str,
    users: crate::widgets::list::StatefulList<String>,
) -> Result<(), anyhow::Error> {
    let mut users = users;
    if users.items.is_empty() {
        return Err(anyhow::anyhow!("No users found in the certificate!"));
    }

    let mut selected_items = vec![false; users.items.len()];
    let should_continue = show_user_selection_popup(terminal, &mut users, &mut selected_items)?;

    if let Some(true) = should_continue {
        let file_name_prompt = [Line::from(
            "Enter exported certificate name (e.g. name.certificate.pgp):",
        )];
        let file_name = loop {
            let input = draw_input_prompt(terminal, &file_name_prompt, true)?;
            match validate_filename(&input) {
                Ok(()) => break input,
                Err(e) => {
                    show_input_popup(terminal, &e.to_string())?;
                }
            }
        };

        let selected_users: Vec<String> = users
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, user)| {
                if selected_items[index] {
                    Some(user.clone())
                } else {
                    None
                }
            })
            .collect();

        cert_manager.split_users(cert_path, &file_name, selected_users)?;
    }

    Ok(())
}

pub fn revoke(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    certificate: &str,
) -> Result<(), anyhow::Error> {
    let style = Style::default().fg(Color::Yellow);
    let prompt_revocation_reason = vec![
        "Please specify a revocation reason:",
        "    (d) No reason specified",
        "    (1) Key is retired and no longer used",
        "    (2) Key is superseded",
        "    (3) Key material has been compromised",
    ];

    let revocation_reason_spans: Vec<Line> = prompt_revocation_reason
        .into_iter()
        .map(|line| Line::from(Span::styled(line, style)))
        .collect();

    let key = Cert::from_reader(BufReader::new(File::open(certificate)?))?;
    if !key.is_tsk() {
        let revocation_path = draw_input_prompt(
            terminal,
            &[Line::from("Enter revocation certificate path:")],
            true,
        )?;
        cert_manager.revoke_certificate(certificate, &revocation_path)?;
    } else {
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        let original_pw_str =
            draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw_str);
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                let revocation_reason =
                    draw_input_prompt(terminal, &revocation_reason_spans, true)?;
                cert_manager.revoke_key(certificate, &original_pw, &revocation_reason)?
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Wrong password!"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_password_rejects_too_short() {
        assert!(validate_password("short").is_err());
    }

    #[test]
    fn validate_password_accepts_min_length() {
        assert!(validate_password("12345678").is_ok());
    }

    #[test]
    fn validate_password_rejects_empty() {
        assert!(validate_password("").is_err());
    }

    #[test]
    fn validate_not_empty_rejects_empty() {
        assert!(validate_not_empty("", "field").is_err());
    }

    #[test]
    fn validate_not_empty_rejects_whitespace_only() {
        assert!(validate_not_empty("   ", "field").is_err());
    }

    #[test]
    fn validate_not_empty_accepts_valid() {
        assert!(validate_not_empty("hello", "field").is_ok());
    }

    #[test]
    fn validate_filename_rejects_empty() {
        assert!(validate_filename("").is_err());
    }

    #[test]
    fn validate_filename_rejects_dot_dot() {
        assert!(validate_filename("../etc/passwd").is_err());
    }

    #[test]
    fn validate_filename_rejects_forward_slash() {
        assert!(validate_filename("path/file").is_err());
    }

    #[test]
    fn validate_filename_rejects_backslash() {
        assert!(validate_filename("path\\file").is_err());
    }

    #[test]
    fn validate_filename_accepts_valid_name() {
        assert!(validate_filename("my_key.pgp").is_ok());
    }
}
