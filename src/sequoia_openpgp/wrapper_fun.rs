use std::{fs::File, io::BufReader};

use ratatui::{
    backend::CrosstermBackend,
    style::{Color, Style},
    text::{Line, Span},
    Terminal,
};
use sequoia_openpgp::{crypto::Password, parse::Parse, Cert};

use crate::app::ui::{draw_input_prompt, show_user_selection_popup};

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

// wrapper function for generating a keypair
pub fn generate_keypair_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<(), anyhow::Error> {
    let style = Style::default().fg(Color::Yellow);
    let user_id = draw_input_prompt(
        terminal,
        &[Line::from(Span::styled(
            "Enter user id (e.g 'Bob <Bob@domain.de>):",
            style,
        ))],
        true,
    )?;

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
        "Please select a cypher:",
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
    let pw = draw_input_prompt(
        terminal,
        &[Line::from(Span::styled(
            "Enter password (min. 8 chars, a passphrase is recommended):",
            style,
        ))],
        false,
    )?;
    validate_password(&pw)?;

    let rpw = draw_input_prompt(
        terminal,
        &[Line::from(Span::styled("Repeat password:", style))],
        false,
    )?;

    if pw != rpw {
        return Err(anyhow::anyhow!("Passwords do not match!"));
    }

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
                let file_name = draw_input_prompt(
                    terminal,
                    &[Line::from(
                        "Enter exported certificate name (e.g. name.certificate.pgp):",
                    )],
                    true,
                )?;

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
                let new_password = draw_input_prompt(
                    terminal,
                    &[Line::from(
                        "Enter new password (min. 8 chars, a passphrase is recommended):",
                    )],
                    false,
                )?;
                validate_password(&new_password)?;

                let repeat_password =
                    draw_input_prompt(terminal, &[Line::from("Repeat new password")], false)?;
                if new_password == repeat_password {
                    cert_manager.edit_password(
                        certificate,
                        &original_pw,
                        new_password,
                        repeat_password,
                    )?;
                } else {
                    return Err(anyhow::anyhow!("Passwords do not match!"));
                }
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
            let new_user = draw_input_prompt(terminal, &[Line::from("Enter new user:")], true)?;
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
        let file_name = draw_input_prompt(
            terminal,
            &[Line::from(
                "Enter exported certificate name (e.g. name.certificate.pgp):",
            )],
            true,
        )?;

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
