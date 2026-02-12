#![allow(dead_code)]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use sequoia_openpgp::armor::{Kind, Writer};
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::Cert;

/// Generate a test keypair and write to the given directory.
/// Returns (secret_key_path, public_cert_path, revocation_cert_path).
pub fn generate_test_keypair(
    dir: &Path,
    user_id: &str,
    password: &str,
) -> (String, String, String) {
    let (cert, revocation) = CertBuilder::new()
        .add_userid(user_id)
        .set_password(Some(Password::from(password)))
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .generate()
        .expect("Failed to generate test keypair");

    let sk_path = dir.join("secret.pgp").to_string_lossy().into_owned();
    let pub_path = dir.join("public.pgp").to_string_lossy().into_owned();
    let rev_path = dir.join("revocation.rev").to_string_lossy().into_owned();

    // Write armored secret key
    {
        let file = File::create(&sk_path).unwrap();
        let mut w = Writer::new(file, Kind::SecretKey).unwrap();
        cert.as_tsk().serialize(&mut w).unwrap();
        w.finalize().unwrap();
    }

    // Write armored public certificate (stripped of secret material)
    {
        let mut file = File::create(&pub_path).unwrap();
        cert.strip_secret_key_material()
            .armored()
            .serialize(&mut file)
            .unwrap();
    }

    // Write armored revocation certificate
    {
        let file = File::create(&rev_path).unwrap();
        let mut w = Writer::new(file, Kind::Signature).unwrap();
        Packet::Signature(revocation).serialize(&mut w).unwrap();
        w.finalize().unwrap();
    }

    (sk_path, pub_path, rev_path)
}

/// Read a Cert from a file path.
pub fn read_cert(path: &str) -> Cert {
    Cert::from_reader(BufReader::new(File::open(path).unwrap())).unwrap()
}
