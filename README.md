# PGPManager
![](banner.jpg)

[![CI](https://github.com/Digiyang/PGPManager/actions/workflows/ci.yml/badge.svg)](https://github.com/Digiyang/PGPManager/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub issues](https://img.shields.io/github/issues/Digiyang/PGPManager.svg)](https://github.com/Digiyang/PGPManager/issues)

PGPmanager is a Terminal User Interface (TUI) designed to facilitate and manage the process of PGP (Pretty Good Privacy) key management.

The primary purpose of PGPmanager is to provide an intuitive and interactive interface for users to perform various PGP key operations, such as:
- generating key pairs
- exporting and importing certificates
- editing passwords and expiration times
- revoking keys
- and more

The application serves as a bridge between the user and the underlying functionality provided by the [Sequoia-OpenPGP](https://sequoia-pgp.org/) crate, a powerful library for PGP key management in Rust.

---

## Releases

PGPManager is currently in its *Alpha* stage.

### Release Notes
This tool was developed as part of a bachelor thesis and my first project written in [Rust](https://www.rust-lang.org/), leveraging [PGP](https://www.openpgp.org/). As such, it may have security flaws, bugs or contain boilerplate code. Reviews, critiques, and contributions are highly appreciated.

I plan to release stable versions on popular package managers like Cargo, Homebrew, and others in the near future. Stay tuned for updates!

---

## Features
![](help.png)

- Generate PGP keypair & revocation certificates
- Export public keys
- Edit key passwords and expiration times
- Add/Delete users
- Revoke keys
- Extract a public key for each user with the same private key
- User-friendly and robust interface.

---

## Table of Contents

- [PGPManager](#pgpmanager)
  - [Releases](#releases)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Installation Steps](#installation-steps)
  - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)
  - [Contact](#contact)
  - [Copyright](#copyright)

---

## Installation

### Prerequisites

Before you can run the Terminal User Interface, you must first ensure that your system meets the necessary requirements.

1. Rust programming language:

The TUI is written in Rust, so Rustup, the installation and version management program for Rust, is required. If Rust is not installed on your system, please visit [the official Rust website](https://www.rust-lang.org/) for installation instructions.

1. Sequoia OpenPGP Crate:

The TUI relies on the Sequoia OpenPGP crates for certificate management. You must have certain dependencies installed in your system. Visit [the Sequoia repository](https://gitlab.com/sequoia-pgp/sequoia) for detailed instructions on the required libraries for different platforms.

### Installation Steps

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/Digiyang/PGPManager.git
   ```

2. Change to the project directory:

   ```bash
   cd PGPManager
   ```

3. Build the application:
      ```bash
      cargo build --release
      ```

4. Run the application:
      ```bash
      cargo run --release
      ```

---

## Usage
- Use the arrow keys to navigate through the interface.
- Press `h` to view the help menu.
- Press `q` to quit the application.
- Press `Enter` to select an open a directory.
- Press `Space Bar` to go back to the previous directory.
- Press `Esc` to abort the current operation.
- Press `d` to get key details.
- Press `g` to generate a key.
- Press `e` to export a key.
- Press `a` to add a user.
- Press `p` to change a password.
- Press `t` to modify a key expiration time.
- Press `u` to export a new public key for selected user(s).
- Press `r` to revoke a key.
- Follow the on-screen prompts to perform various key operations.

---

## Contributing
Contributions are welcome! Feel free to open [issues](https://github.com/Digiyang/PGPManager/issues) for any improvements or bug fixes.

---

## License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

## Contact
- Email: [moez@rjiba.de](mailto:moez@rjiba.de) | [PK](https://keys.openpgp.org/vks/v1/by-fingerprint/DBCFECCE54271ACE2AAF80268DD7310FF3E0913F)
- LinkedIn: [Moez Rjiba](https://www.linkedin.com/in/moez-rjiba-1a3ab21a2/)

## Copyright
Copyright © 2025, [Moez Rjiba](https://rjiba.de). All rights reserved.
