use std::{fs::File, io::BufReader};

use ratatui::{
    backend::CrosstermBackend,
    style::{Color, Style},
    text::{Line, Span},
    Terminal,
};
use sequoia_openpgp::{crypto::Password, parse::Parse, Cert};

use crate::{
    app::ui::{draw_input_prompt, show_user_selection_popup},
    widgets::list::StatefulList,
};

use super::certificate_manager::CertificateManager;

// wrapper function for generating a keypair
pub fn generate_keypair_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    user_id: &mut String,
    validity: &mut String,
    cipher: &mut String,
    pw: &mut String,
    rpw: &mut String,
) -> Result<(), anyhow::Error> {
    let style = Style::default().fg(Color::Yellow);
    *user_id = draw_input_prompt(
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

    *validity = draw_input_prompt(terminal, &validity_spans, true)?;
    *cipher = draw_input_prompt(terminal, &cipher_spans, true)?;
    *pw = draw_input_prompt(
        terminal,
        &[Line::from(Span::styled("Enter password:", style))],
        false,
    )?;
    *rpw = draw_input_prompt(
        terminal,
        &[Line::from(Span::styled("Repeat password:", style))],
        false,
    )?;

    if pw != rpw {
        return Err(anyhow::anyhow!("Passwords do not match!"));
    }

    cert_manager.generate_keypair(
        user_id.to_string(),
        validity.to_string(),
        cipher.to_string(),
        pw.to_string(),
        rpw.to_string(),
    )?;
    Ok(())
}

// wrapper function for the export_certificate function
pub fn export_certificate_tui(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    cert_path: &str,
    file_name: &mut String,
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
                *file_name = draw_input_prompt(
                    terminal,
                    &[Line::from(
                        "Enter exported certificate name (e.g. name.certificate.pgp):",
                    )],
                    true,
                )?;

                cert_manager.export_certificate(cert_path, file_name)?;
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
    original_pw: &mut String,
    new_password: &mut String,
    repeat_password: &mut String,
) -> Result<(), anyhow::Error> {
    let key = Cert::from_reader(BufReader::new(File::open(certificate)?))?;
    if !key.is_tsk() {
        return Err(anyhow::anyhow!("Not a secret key!"));
    } else {
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        *original_pw = draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw.clone());
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                *new_password =
                    draw_input_prompt(terminal, &[Line::from("Enter new password")], false)?;
                *repeat_password =
                    draw_input_prompt(terminal, &[Line::from("Repeat new password")], false)?;
                if new_password == repeat_password {
                    cert_manager.edit_password(
                        certificate,
                        &original_pw,
                        new_password.to_string(),
                        repeat_password.to_string(),
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
    original_pw: &mut String,
    new_expiration_time: &mut String,
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
        *original_pw = draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw.clone());
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                *new_expiration_time = draw_input_prompt(terminal, &validity_spans, true)?;
                cert_manager.edit_expiration_time(
                    certificate,
                    &original_pw,
                    new_expiration_time.to_string(),
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
    original_pw: &mut String,
    new_user: &mut String,
) -> Result<(), anyhow::Error> {
    let key = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;

    let secret = key.primary_key().key().clone().parts_into_secret()?;
    *original_pw = draw_input_prompt(terminal, &[Line::from("Enter key secret:")], false)?;
    let original_pw = Password::from(original_pw.clone());
    match secret.decrypt_secret(&original_pw) {
        Ok(_) => {
            *new_user = draw_input_prompt(terminal, &[Line::from("Enter new user:")], true)?;
            cert_manager.add_user(cert_path, &original_pw, new_user.to_string())?;
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
    file_name: &mut String,
    users: &mut StatefulList<String>,
    selected_items: &mut Vec<bool>,
) -> Result<(), anyhow::Error> {
    if users.items.is_empty() {
        return Err(anyhow::anyhow!("No users found in the certificate!"));
    }

    selected_items.resize(users.items.len(), false);
    let should_continue = show_user_selection_popup(terminal, users, selected_items)?;

    if let Some(true) = should_continue {
        *file_name = draw_input_prompt(
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

        cert_manager.split_users(cert_path, file_name, selected_users.clone())?;
    }

    Ok(())
}

pub fn revoke(
    cert_manager: &CertificateManager,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    certificate: &str,
    original_pw: &mut String,
    revocation_reason: &mut String,
    revocation_path: &mut String,
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
        *revocation_path = draw_input_prompt(
            terminal,
            &[Line::from("Enter revocation certificate path:")],
            true,
        )?;
        cert_manager.revoke_certificate(certificate, revocation_path)?;
    } else {
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        *original_pw = draw_input_prompt(terminal, &[Line::from("Enter key secret")], false)?;
        let original_pw = Password::from(original_pw.clone());
        match secret.decrypt_secret(&original_pw) {
            Ok(_) => {
                *revocation_reason = draw_input_prompt(terminal, &revocation_reason_spans, true)?;
                cert_manager.revoke_key(certificate, &original_pw, revocation_reason)?
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Wrong password!"));
            }
        }
    }
    Ok(())
}
