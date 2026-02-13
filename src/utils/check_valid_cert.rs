use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Packet;
use sequoia_openpgp::{Cert, PacketPile};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub enum CertificateType {
    Cert(Box<Cert>),
    Sig(Box<Signature>),
    Invalid(String),
}

pub fn check_certificate(cert_path: &Path) -> CertificateType {
    let file = match File::open(cert_path) {
        Ok(file) => file,
        Err(e) => return CertificateType::Invalid(format!("Cannot open file: {}", e)),
    };
    let mut reader = BufReader::new(file);
    let packet_pile = match PacketPile::from_reader(&mut reader) {
        Ok(pile) => pile,
        Err(e) => return CertificateType::Invalid(format!("Failed to parse PGP data: {}", e)),
    };

    let mut signature: Option<Signature> = None;
    let mut is_key = false;

    for packet in packet_pile.descendants() {
        match packet {
            Packet::Signature(sig) => {
                if signature.is_some() {
                    // If we already found a signature, this is a second one, so it's not a standalone signature.
                    return CertificateType::Invalid(
                        "Multiple signatures found; not a standalone signature".into(),
                    );
                }

                signature = Some(sig.clone());
            }
            Packet::PublicKey(_)
            | Packet::PublicSubkey(_)
            | Packet::SecretKey(_)
            | Packet::SecretSubkey(_) => {
                is_key = true;
                break;
            }
            // Any other packet type means it's not a valid file.
            _ => {
                return CertificateType::Invalid(
                    "Unexpected packet type; not a valid certificate or signature".into(),
                )
            }
        }
    }

    if is_key {
        // If we found a key packet, attempt to parse the file as a Cert.
        match Cert::from_packets(
            packet_pile
                .into_children()
                .collect::<Vec<Packet>>()
                .into_iter(),
        ) {
            Ok(cert) => CertificateType::Cert(Box::new(cert)),
            Err(e) => CertificateType::Invalid(format!("Failed to parse certificate: {}", e)),
        }
    } else {
        // If we didn't find a key packet, it must be a standalone signature.
        match signature {
            Some(sig) => CertificateType::Sig(Box::new(sig)),
            None => CertificateType::Invalid("No signature found in file".into()),
        }
    }
}
