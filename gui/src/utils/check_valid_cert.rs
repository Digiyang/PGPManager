use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Packet;
use sequoia_openpgp::{Cert, PacketPile};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub enum CertificateType {
    Cert(Cert),
    Sig(Signature),
    Invalid,
}

pub fn check_certificate(cert_path: &Path) -> CertificateType {
    let file = match File::open(cert_path) {
        Ok(file) => file,
        Err(_) => return CertificateType::Invalid,
    };
    let mut reader = BufReader::new(file);
    let packet_pile = match PacketPile::from_reader(&mut reader) {
        Ok(pile) => pile,
        Err(_) => return CertificateType::Invalid,
    };

    let mut signature: Option<Signature> = None;
    let mut is_key = false;

    for packet in packet_pile.descendants() {
        match packet {
            Packet::Signature(sig) => {
                if signature.is_some() {
                    // If we already found a signature, this is a second one, so it's not a standalone signature.
                    return CertificateType::Invalid;
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
            _ => return CertificateType::Invalid,
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
            Ok(cert) => return CertificateType::Cert(cert),
            Err(_) => return CertificateType::Invalid,
        }
    } else {
        // If we didn't find a key packet, it must be a standalone signature.
        match signature {
            Some(sig) => CertificateType::Sig(sig),
            None => CertificateType::Invalid, // No signature found at all.
        }
    }
}
