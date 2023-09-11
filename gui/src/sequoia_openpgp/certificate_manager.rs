use anyhow::Context;
use openpgp::armor::{Kind, Writer};
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::Password;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::Signature;
use openpgp::packet::{signature, UserID};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Marshal;
use openpgp::types::{ReasonForRevocation, RevocationStatus::*, SignatureType};
use openpgp::{Cert, Packet, PacketPile};

use sequoia_openpgp as openpgp;

use std::time;

use std::{fs::File, io::BufReader, time::SystemTime as StdTime};

use crate::app::launch::clear_screen;
use crate::utils::create_directory::create_file;
use crate::utils::parse_iso8610_duration::parse_iso8601_duration;

#[derive(Debug, Clone, Copy)]
pub struct CertificateManager;

pub enum CertificateOperation {
    GetCertificateDetails,
    GetSignatureDetails,
    GenerateKeypair {
        user_id: String,
        validity: String,
        cipher: String,
        pw: String,
        rpw: String,
    },
    ExportCertificate,
    EditPassword {
        original_pw: Password,
        new_password: String,
        repeat_password: String,
    },
    ModifyExpirationTime {
        original_pw: Password,
        validity: String,
    },
    SplitUsers {
        selected_users: Vec<String>,
    },
    AddUser {
        original_pw: Password,
        user_id: String,
    },
    RevokeKey {
        original_pw: Password,
        reason: String,
    },
    RevokeCertificate {
        rev_cert: String,
    },
    /*
    DeleteUser,
    */
}

#[derive(Debug)]
pub enum CertificateOperationOutput {
    Details(Result<String, anyhow::Error>),
    Result(Result<(), anyhow::Error>),
}

impl CertificateManager {
    pub fn execute(
        &self,
        operation: CertificateOperation,
        cert_path: Option<&String>,
        file_name: Option<&String>,
    ) -> Result<CertificateOperationOutput, anyhow::Error> {
        match operation {
            CertificateOperation::GetCertificateDetails => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Details(
                        self.get_key_details(cert_path),
                    ))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for GetKeyDetails operation"
                    ))
                }
            }
            CertificateOperation::GetSignatureDetails => {
                // Handle the GetRevocationDetails operation
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Details(
                        self.get_signature_details(cert_path),
                    ))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for GetRevocationDetails operation"
                    ))
                }
            }
            CertificateOperation::GenerateKeypair {
                user_id,
                validity,
                cipher,
                pw,
                rpw,
            } => Ok(CertificateOperationOutput::Result(self.generate_keypair(
                user_id,
                validity,
                cipher,
                pw.into(),
                rpw.into(),
            ))),
            CertificateOperation::ExportCertificate => {
                if let Some(cert_path) = cert_path {
                    if let Some(file_name) = file_name {
                        Ok(CertificateOperationOutput::Result(
                            self.export_certificate(cert_path, file_name),
                        ))
                    } else {
                        Err(anyhow::anyhow!(
                            "A file name is required for ExportCertificate operation"
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for ExportCertificate operation"
                    ))
                }
            }
            CertificateOperation::EditPassword {
                original_pw,
                new_password,
                repeat_password,
            } => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Result(self.edit_password(
                        cert_path,
                        &original_pw,
                        new_password,
                        repeat_password,
                    )))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for EditPassword operation"
                    ))
                }
            }
            CertificateOperation::ModifyExpirationTime {
                original_pw,
                validity,
            } => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Result(
                        self.edit_expiration_time(cert_path, &original_pw, validity),
                    ))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for EditExpirationTime operation"
                    ))
                }
            }
            CertificateOperation::SplitUsers { selected_users } => {
                if let Some(cert_path) = cert_path {
                    if let Some(file_name) = file_name {
                        Ok(CertificateOperationOutput::Result(self.split_users(
                            cert_path,
                            file_name,
                            selected_users,
                        )))
                    } else {
                        Err(anyhow::anyhow!(
                            "A file name is required for SplitKey operation"
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for SplitKey operation"
                    ))
                }
            }
            CertificateOperation::AddUser {
                original_pw,
                user_id,
            } => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Result(self.add_user(
                        cert_path,
                        &original_pw,
                        user_id,
                    )))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for AddUser operation"
                    ))
                }
            }
            CertificateOperation::RevokeKey {
                original_pw,
                reason,
            } => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Result(self.revoke_key(
                        cert_path,
                        &original_pw,
                        &reason,
                    )))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for RevokeKey operation"
                    ))
                }
            }
            CertificateOperation::RevokeCertificate { rev_cert } => {
                if let Some(cert_path) = cert_path {
                    Ok(CertificateOperationOutput::Result(
                        self.revoke_certificate(cert_path, &rev_cert),
                    ))
                } else {
                    Err(anyhow::anyhow!(
                        "A file path is required for RevokeCertificate operation"
                    ))
                }
            }
        }
    }

    fn get_key_details(&self, cert_path: &String) -> Result<String, anyhow::Error> {
        cert_path.trim().to_string();
        let cert = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;
        let mut key_details = String::new();

        // check if public key or secret key
        if cert.is_tsk() {
            key_details.push_str(&format!("\nThis is a Secret key\n"));
        } else {
            key_details.push_str(&format!("\nThis is a Public key\n"));
        }

        // key decryption
        // 1-print user-ids and attributes
        for ua in cert.userids() {
            key_details.push_str(&format!(
                "\nUser-ID:      {}",
                String::from_utf8_lossy(ua.value())
            ));
            for sig in ua.signatures() {
                let creation_time = sig.signature_creation_time().unwrap();
                key_details.push_str(&format!("\nSignature version: {}", sig.version()));
                key_details.push_str(&format!("\nSignature type: {}", sig.typ()));
                key_details.push_str(&format!(
                    "\nSignature creation time: {}",
                    chrono::DateTime::<chrono::offset::Utc>::from(creation_time)
                ));
                key_details.push_str(&format!("\nHash Algorithm: {}", sig.hash_algo()));
                key_details.push_str(&format!(
                    "\nSignature validity period: {:?}",
                    sig.signature_validity_period()
                ));
            }
        }

        for u_att in cert.user_attributes() {
            key_details.push_str(&format!(
                "\nUser attributes: {}",
                String::from_utf8_lossy(u_att.value())
            ));
        }

        // 2-print key fingerprint
        key_details.push_str(&format!("\nFingerprint: {}", cert.fingerprint()));

        // 3-check if key is revoked or not
        let p = &StandardPolicy::new();
        match cert.revocation_status(p, None) {
            Revoked(sigs) => {
                key_details.push_str(&format!("\nRevocation status: Revoked"));
                for sig in sigs {
                    if let Some((r, msg)) = sig.reason_for_revocation() {
                        key_details.push_str(&format!("\n                    -{}", r));
                        key_details.push_str(&format!(
                            "\n       Issued by: {}",
                            if let Some(issuer) = sig.get_issuers().into_iter().next() {
                                issuer.to_spaced_hex()
                            } else {
                                "\n unknown certificate".into()
                            }
                        ));
                        key_details.push_str(&format!(
                            "\n       Message: {:?}",
                            String::from_utf8_lossy(msg)
                        ));
                    } else {
                        key_details.push_str(&format!(
                            "            Issued by {}",
                            if let Some(issuer) = &sig.get_issuers().into_iter().next() {
                                issuer.to_spaced_hex()
                            } else {
                                "unknown certificate".into()
                            }
                        ));
                    }
                }
            }
            CouldBe(sigs) => {
                key_details.push_str(&format!("\nRevocation status: Possibly revoked:"));
                for sig in sigs {
                    if let Some((r, msg)) = sig.reason_for_revocation() {
                        key_details.push_str(&format!("\n                    -{}", r));
                        key_details.push_str(&format!(
                            "       Issued by: {}",
                            if let Some(issuer) = sig.get_issuers().into_iter().next() {
                                issuer.to_spaced_hex()
                            } else {
                                " unknown certificate".into()
                            }
                        ));
                        key_details.push_str(&format!(
                            "       Message: {:?}",
                            String::from_utf8_lossy(msg)
                        ));
                    } else {
                        key_details.push_str(&format!(
                            "            Issued by {}",
                            if let Some(issuer) = &sig.get_issuers().into_iter().next() {
                                issuer.to_spaced_hex()
                            } else {
                                "unknown certificate".into()
                            }
                        ));
                    }
                }
            }
            NotAsFarAsWeKnow => {
                key_details.push_str(&format!("\nRevocation status: Not as far as we know"));
            }
        }

        let key_amalgation = cert.keys().next().unwrap();
        let key = key_amalgation.key();

        // 4-check key validity
        let validation = match key_amalgation.with_policy(p, None) {
            Ok(valid) => {
                if let Err(e) = valid.alive() {
                    key_details.push_str(&format!("\nKey not valid: {}", e));
                }
                Some(valid)
            }
            Err(e) => {
                key_details.push_str(&format!("\nKey not valid: {}", e));
                None
            }
        };

        // 5-display public key algorithm and size
        key_details.push_str(&format!("\nPublic Key algorithm: {}", key.pk_algo()));
        if let Some(bits) = key.mpis().bits() {
            // return the length of the public key in bits
            key_details.push_str(&format!("\nPublic Key size: {}", bits));
        }

        if let Some(secret) = key.optional_secret() {
            key_details.push_str(&format!(
                "\nSecret Key: {}",
                if let SecretKeyMaterial::Encrypted(_) = secret {
                    "Encrypted"
                } else {
                    "Unencrypted"
                }
            ));
        }

        // 6-key creation time
        let time = key.creation_time();
        key_details.push_str(&format!(
            "\nCreation time:   {}",
            chrono::DateTime::<chrono::offset::Utc>::from(time)
        ));

        // 7-key expiration time
        if let Some(vka) = validation {
            if let Some(expiration) = vka.key_validity_period() {
                let expiration_time = time + expiration;
                key_details.push_str(&format!(
                    "\nExpiration time: {}",
                    chrono::DateTime::<chrono::offset::Utc>::from(expiration_time)
                ));
            }
            // 8-check capabilities
            key_details.push_str(&format!("\nCapabilities:"));
            //writeln!(output, "\nCapabilities:")?;
            if let Some(flags) = vka.key_flags() {
                let mut capabilities = Vec::new();
                if flags.for_signing() {
                    capabilities.push("     Sign")
                }
                if flags.for_certification() {
                    capabilities.push("     Certify")
                }
                if flags.for_authentication() {
                    capabilities.push("     Authenticate")
                }
                if flags.for_storage_encryption() {
                    capabilities.push("     Storage encryption")
                }
                if flags.for_transport_encryption() {
                    capabilities.push("     Transport encryption")
                }
                if flags.is_group_key() {
                    capabilities.push("     Group Key")
                }
                if flags.is_split_key() {
                    capabilities.push("     Split Key")
                }

                // check if vec is empty
                if !capabilities.is_empty() {
                    key_details.push_str(&format!("\n{}", capabilities.join("\n")));
                } else {
                    key_details.push_str(&format!("\nNo capabilities!"));
                }
            }
        };

        for sub in cert.keys().subkeys() {
            key_details.push_str(&format!("\nSubkey fingerprint: {}", sub.fingerprint()));
            key_details.push_str(&format!("\nSubkey algorithm: {}", sub.pk_algo()));
            if let Some(bits) = sub.mpis().bits() {
                // return the length of the subkey in bits
                key_details.push_str(&format!("\nSubkey size: {}", bits));
            }
        }

        Ok(key_details)
    }

    fn get_signature_details(&self, signature_path: &String) -> Result<String, anyhow::Error> {
        let mut revocation_details = String::new();

        let file = File::open(signature_path).context("Failed to open the file")?;
        let mut reader = BufReader::new(file);
        let packet_pile = PacketPile::from_reader(&mut reader)
            .context("Failed to read the signature from the file")?;

        let signature = packet_pile.descendants().find_map(|packet| {
            if let Packet::Signature(sig) = packet {
                Some(sig.clone())
            } else {
                None
            }
        });

        if let Some(sig) = signature {
            if let Some(sig_creation_time) = sig.signature_creation_time() {
                let kind = sig.typ();
                let fingerprint = sig.issuer_fingerprints().next().unwrap();
                revocation_details.push_str(&format!(
                    "Signature creation time: {}",
                    chrono::DateTime::<chrono::offset::Utc>::from(sig_creation_time)
                ));
                revocation_details.push_str(&format!("\nSignature type: {}", kind));
                revocation_details.push_str(&format!(
                    "\nSignature issuer: {}",
                    fingerprint.to_spaced_hex()
                ));
            } else {
                revocation_details.push_str("Signature creation time: Not available");
            }
        } else {
            return Err(anyhow::Error::msg("No signature found in the file"));
        }

        Ok(revocation_details)
    }

    pub fn generate_keypair(
        &self,
        user_id: String,
        validity: String,
        cipher: String,
        pw: String,
        rpw: String,
    ) -> Result<(), anyhow::Error> {
        clear_screen();
        let mut builder = CertBuilder::new();

        let uid_clone = user_id.clone();
        builder = builder.add_userid(user_id);

        match validity.as_str() {
            "n" | "N" => {
                builder = builder
                    .set_creation_time(StdTime::now())
                    .set_validity_period(None);
            }
            "0" | "" => {
                // setting default validity period to 2 years
                builder = builder
                    .set_creation_time(StdTime::now())
                    .set_validity_period(Some(std::time::Duration::new(2 * 31536000, 0)));
            }
            _ => {
                let duration = parse_iso8601_duration(validity.as_str()).unwrap();
                builder = builder
                    .set_creation_time(StdTime::now())
                    .set_validity_period(Some(duration));
            }
        }

        // todo: implement default
        match cipher.as_str() {
            "1" => builder = builder.set_cipher_suite(CipherSuite::Cv25519),
            "2" => builder = builder.set_cipher_suite(CipherSuite::RSA2k),
            "3" => builder = builder.set_cipher_suite(CipherSuite::RSA3k),
            "4" => builder = builder.set_cipher_suite(CipherSuite::RSA4k),
            "5" => builder = builder.set_cipher_suite(CipherSuite::P256),
            "6" => builder = builder.set_cipher_suite(CipherSuite::P384),
            "7" => builder = builder.set_cipher_suite(CipherSuite::P521),
            _ => builder = builder.set_cipher_suite(CipherSuite::Cv25519),
        }

        // check if both passwords are the same
        if pw == rpw {
            builder = builder.set_password(Some(pw.into()));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match!"));
        }

        // todo: give the user the choice which subkeys to generate
        // todo: be able to set expiration time for each subkey
        // todo: implement the ability to add subkeys to an existent key later
        // default: generate all subkeys
        builder = builder.add_signing_subkey();
        builder = builder.add_authentication_subkey();
        builder = builder.add_storage_encryption_subkey();
        builder = builder.add_transport_encryption_subkey();

        // genrates a private key + revocation certificate
        let (key, revocation_cert) = builder.generate()?;

        // Note: certificate on the context of the sequoia openpgp crate means the public key that can be shared
        let home_dir = home::home_dir().unwrap();
        let key_path = String::from(
            format!("{}/.pgpman/secrets/{}.pgp", &home_dir.display(), uid_clone).replace(" ", ""),
        );
        let revcert_path = String::from(
            format!(
                "{}/.pgpman/revocation/{}.rev",
                &home_dir.display(),
                uid_clone
            )
            .replace(" ", ""),
        );
        // export key to path
        {
            if let Some(w) = create_file(Some(&key_path.as_str())).unwrap() {
                let mut w = Writer::new(w, Kind::SecretKey)?;
                key.as_tsk().serialize(&mut w)?;
                w.finalize()?;
            }
        }

        // export revocation certificate to path
        {
            if let Some(w) = create_file(Some(&revcert_path.as_str())).unwrap() {
                let mut w = Writer::new(w, Kind::Signature)?;
                Packet::Signature(revocation_cert).serialize(&mut w)?;
                w.finalize()?;
            }
        }

        Ok(())
    }

    pub fn export_certificate(
        &self,
        cert_path: &String,
        ex_file_name: &String,
    ) -> Result<(), anyhow::Error> {
        let cert = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;

        let home_dir = home::home_dir().unwrap();
        let export_path = String::from(format!(
            "{}/.pgpman/certificates/{}",
            &home_dir.display(),
            ex_file_name
        ));
        if let Some(mut out_cert) = create_file(Some(&export_path.as_str()))? {
            cert.armored().serialize(&mut out_cert)?;
        }

        Ok(())
    }

    pub fn edit_password(
        &self,
        secret_key: &String,
        original: &Password,
        npw: String,
        rnpw: String,
    ) -> Result<(), anyhow::Error> {
        let mut key = Cert::from_reader(BufReader::new(File::open(&secret_key)?))?;

        // decrypt secret first
        let secret = key.primary_key().key().clone().parts_into_secret()?;
        let dec = secret.decrypt_secret(&original)?;
        key = key.insert_packets(dec)?;
        if npw == rnpw {
            let enc = key
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()?
                .encrypt_secret(&rnpw.into())?;
            key = key.insert_packets(enc)?;

            if let Some(mut out) = create_file(Some(&secret_key))? {
                key.as_tsk().armored().serialize(&mut out)?;
            }
        }
        Ok(())
    }

    pub fn edit_expiration_time(
        &self,
        cert_path: &String,
        original: &Password,
        validity: String,
    ) -> Result<(), anyhow::Error> {
        let cert = Cert::from_reader(BufReader::new(File::open(&cert_path)?))?;
        let p = &StandardPolicy::new();
        let vc = cert.with_policy(p, None)?;
        let sig;

        let secret = vc.primary_key().key().clone().parts_into_secret()?;
        let mut keypair = secret.decrypt_secret(&original)?.into_keypair()?;

        match validity.as_str() {
            "0" | "" => {
                sig = vc.primary_key().set_expiration_time(&mut keypair, None)?;
            }
            _ => {
                let duration = parse_iso8601_duration(&validity.as_str()).unwrap();
                let t = time::SystemTime::now() + duration;
                sig = vc
                    .primary_key()
                    .set_expiration_time(&mut keypair, Some(t))?;
            }
        }

        let cert = cert.insert_packets(sig)?;
        if let Some(mut out_cert) = create_file(Some(&cert_path))? {
            cert.as_tsk().armored().serialize(&mut out_cert)?;
        }

        Ok(())
    }

    pub fn add_user(
        &self,
        cert_path: &String,
        original: &Password,
        new_userid: String,
    ) -> Result<(), anyhow::Error> {
        let mut key = Cert::from_reader(BufReader::new(File::open(&cert_path)?))?;

        // always check if it's a secret key
        if !key.is_tsk() {
            Err(anyhow::anyhow!("This is not a secret key"))?;
        }

        // decrypt secret
        let secret = key.primary_key().key().clone().parts_into_secret()?;

        let mut keypair = secret.decrypt_secret(&original)?.into_keypair()?;
        let new_userid = UserID::from(new_userid);
        let builder = signature::SignatureBuilder::new(SignatureType::PositiveCertification);
        let binding = new_userid.bind(&mut keypair, &key, builder)?;

        // Now merge the User ID and binding signature into the Cert.
        key = key.insert_packets(vec![Packet::from(new_userid), binding.into()])?;

        if let Some(mut out) = create_file(Some(&cert_path))? {
            key.as_tsk().armored().serialize(&mut out)?;
        }

        Ok(())
    }

    pub fn split_users(
        &self,
        cert_path: &String,
        new_cert_name: &String,
        selected_users: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        /*
            This function is meant to provide multiple users of a public key, one for each of them.
                1- Parsing the public key into a Cert::from_reader method
                2- Checking the number of users of the public key
                3- Clone the public key for each userID
                4- Cut the clone down using retain_userids
                5- Serialize the clone
            todo: should the original public key be maintained or deleted ?
        */
        let cert = Cert::from_reader(BufReader::new(File::open(cert_path)?))?;
        let home_dir = home::home_dir().unwrap();
        let export_path = String::from(format!(
            "{}/.pgpman/certificates/{}",
            &home_dir.display(),
            new_cert_name
        ));

        let cp = cert.clone().retain_userids(|ua| {
            if let Ok(Some(address)) = ua.email() {
                selected_users.contains(&address)
            } else {
                true
            }
        });
        if let Some(mut out_cert) = create_file(Some(&export_path.as_str()))? {
            cp.serialize(&mut out_cert).unwrap();
        }

        Ok(())
    }

    pub fn revoke_key(
        &self,
        cert_path: &String,
        original: &Password,
        reason: &String,
    ) -> Result<(), anyhow::Error> {
        let key = Cert::from_reader(BufReader::new(File::open(&cert_path)?))?;
        let rev: Signature;

        let secret = key.primary_key().key().clone().parts_into_secret()?;

        let mut signer = secret.decrypt_secret(&original)?.into_keypair()?;

        match reason.as_str() {
            "1" => {
                rev = key.revoke(
                    &mut signer,
                    ReasonForRevocation::KeyRetired,
                    b"Key is retired",
                )?
            }
            "2" => {
                rev = key.revoke(
                    &mut signer,
                    ReasonForRevocation::KeySuperseded,
                    b"Key is superseded",
                )?
            }
            "3" => {
                rev = key.revoke(
                    &mut signer,
                    ReasonForRevocation::KeyCompromised,
                    b"Key is compromised",
                )?
            }
            _ => {
                rev = key.revoke(
                    &mut signer,
                    ReasonForRevocation::Unspecified,
                    b"No reason specified",
                )?
            }
        }

        let key = key.insert_packets(rev)?;
        if let Some(mut out) = create_file(Some(&cert_path))? {
            key.as_tsk().armored().serialize(&mut out)?;
        }

        Ok(())
    }

    pub fn revoke_certificate(
        &self,
        cert_path: &String,
        rev_cert: &String,
    ) -> Result<(), anyhow::Error> {
        let cert = Cert::from_reader(BufReader::new(File::open(&cert_path).unwrap())).unwrap();

        let pile = PacketPile::from_reader(BufReader::new(File::open(&rev_cert).unwrap()))?;
        // extract packets from the revocation certificate
        let packets: Vec<Packet> = pile.into();

        // if there is no signature packet in the revocation certificate, return an error
        let revcert_signature = packets
            .iter()
            .find_map(|packet| match packet {
                Packet::Signature(sig) => Some(sig),
                _ => None,
            })
            .ok_or(anyhow::anyhow!(
                "No signature packet in revocation certificate"
            ))?;

        // Get the issuers of the revocation signature.
        let revcert_issuers = revcert_signature.get_issuers();

        // If none of the issuers of the revocation signature match any key in the original certificate, return an error.
        if !cert.keys().any(|key| {
            revcert_issuers
                .iter()
                .any(|issuer| *issuer == key.key_handle())
        }) {
            return Err(anyhow::anyhow!(
                "Revocation certificate does not match original certificate"
            ));
        }

        let cert = cert.insert_packets(packets.into_iter())?;

        if let Some(mut out) = create_file(Some(&cert_path))? {
            cert.armored().serialize(&mut out)?;
        }

        Ok(())
    }
}
