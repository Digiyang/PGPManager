use std::{fs::File, io::BufReader, path::Path};

use sequoia_openpgp::{parse::Parse, Cert};

pub fn extract_users_from_certificate(cert_path: &Path) -> Result<Vec<String>, anyhow::Error> {
    let cert = Cert::from_reader(BufReader::new(File::open(cert_path).unwrap())).unwrap();
    let mut users = Vec::new();
    if cert.is_tsk() {
        return Err(anyhow::anyhow!("Not a certificate!"));
    } else {
        for ua in cert.userids() {
            if let Ok(Some(address)) = ua.component().email() {
                users.push(address.to_string());
            }
        }
    }
    Ok(users)
}
