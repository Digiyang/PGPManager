use std::{collections::HashMap, path::PathBuf};

use crate::widgets::list::StatefulList;

pub struct App {
    pub items: StatefulList<String>,
    pub key_details: Option<String>,
    pub scroll_state: usize,
    pub current_dir: PathBuf,
    pub help_items: StatefulList<String>,
    pub help_descriptions: HashMap<String, String>,
    pub help_active: bool,
}

impl App {
    pub fn new(current_dir: PathBuf, items: Vec<String>) -> App {
        let mut help_descriptions = HashMap::new();
        help_descriptions.insert(
            "- h/Esc: Show/hide this help".to_string(),
            "Show/hide the help menu".to_string(),
        );
        help_descriptions.insert("- q: Quit".to_string(), "Exit the CLI".to_string());
        help_descriptions.insert(
            "- d: Display key details".to_string(),
            "Display key/certificate details\nYou can scroll inside the popup using the arrow keys"
                .to_string(),
        );
        help_descriptions.insert(
            "- g: Generate a new keypair".to_string(),
            "This will generate a new keypair and a revocation certificate and save it to pgpman directory\n-User-ID\n-Expiration time\n-Cipher\n-Password".to_string());
        help_descriptions.insert("- e: Export a public key".to_string(), "Export the certificate of the selected secret key\nYou will need to specify the name of the exported certificate\ne.g name.certificate.pgp".to_string());
        help_descriptions.insert(
            "- p: Change password".to_string(),
            "Let you change the password of the secret key\nOnly works for secret keys".to_string(),
        );
        help_descriptions.insert("- t: Change expiration time".to_string(), "Let you change the expiration time of the secret key\nOnly works for secret keys\nYou will need extract the certificate again".to_string());
        help_descriptions.insert("- a: Add a user ID".to_string(), "Let you add a new User-ID to a secret key\nOnly works for secret keys\nYou will need extract the certificate again".to_string());
        help_descriptions.insert(
            "- u: Export a new public key for selected user(s)".to_string(),
            "Export a new certificate for the selected user(s)\nselect/deselect users using the 'Space' key and hit 'Enter' to export the certificate\ne.g we have 3 users and you want each user to have it's own certificate but with the same secret key\nThis is very useful to avoid having a secret key for each user\nYou will need to specify the name of the exported certificate".to_string(),
        );
        help_descriptions.insert(
            "- r: Revoke key/certificate".to_string(),
            "Let you revoke a key or a certificate\nIf you want to revoke a key you will need to specify the password of the secret key\nIf you want to revoke a certificate you will need to specify the path of the revocation certificate \n(useful when forgetting the key password or when the key is lost/stolen)".to_string(),
        );
        help_descriptions.insert(
            "- Up/Down: Navigate the list".to_string(),
            "Navigate through the directories/files".to_string(),
        );
        help_descriptions.insert(
            "- Enter: Open directory".to_string(),
            "Open directory".to_string(),
        );
        help_descriptions.insert(
            "- Esc: Go up a directory".to_string(),
            "Go up a directory\nNote: it will be available in a future update to abort from an operation".to_string(),
        );

        App {
            items: StatefulList::with_items(items),
            key_details: None,
            scroll_state: 0,
            current_dir,
            help_items: StatefulList::with_items(vec![
                "- h/Esc: Show/hide this help".to_string(),
                "- q: Quit".to_string(),
                "- d: Display key details".to_string(),
                "- g: Generate a new keypair".to_string(),
                "- e: Export a public key".to_string(),
                "- p: Change password".to_string(),
                "- t: Change expiration time".to_string(),
                "- a: Add a user ID".to_string(),
                "- u: Export a new public key for selected user(s)".to_string(),
                "- r: Revoke key/certificate".to_string(),
                "- Up/Down: Navigate the list".to_string(),
                "- Enter: Open directory".to_string(),
                "- Esc: Go up a directory".to_string(),
            ]),
            help_descriptions,
            help_active: false,
        }
    }
}
