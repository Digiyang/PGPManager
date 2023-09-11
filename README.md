# PGPManager
![Banner](banner.jpg)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub issues](https://img.shields.io/github/issues/Digiyang/PGPManager.svg)](https://github.com/Digiyang/PGPManager/issues)
<!-- [![GitHub stars](https://img.shields.io/github/stars/Digiyang/PGPManager.svg)] (https://github.com/Digiyang/PGPManager/stargazers) -->
<!-- [![GitHub forks](https://img.shields.io/github/forks/Digiyang/PGPManager.svg)](https://github.com/Digiyang/PGPManager/network) -->

PGPmanager is a Terminal User Interface (TUI) designed to facilitate and manage the process of PGP (Pretty Good Privacy) key management.

PGP is a widely-used encryption standard that allows users to secure their communication and data by encrypting messages and files with public and private keys.The primary purpose of PGPmanager is to provide an intuitive and interactive interface for users to perform various PGP key operations, such as generating key pairs, exporting and importing certificates, editing passwords and expiration times, revoking keys, and more. The application serves as a bridge between the user and the underlying functionality provided by the Sequoia-OpenPGP crate, a powerful library for PGP key management in Rust.

## Future Releases

PGPManager is currently in its ALPHA stage. 

This tool was developed as part of a bachelor's thesis and represents my first attempt with Rust and PGP. As such, it may have security flaws, bugs or boilerplate code.

I plan to release stable versions on popular package managers like Cargo, Homebrew, and others in the near future. Stay tuned for updates!
## Features
![help](help.png)

- Generate PGP keypair + revocation certificate
- Export public keys
- Edit key passwords and expiration times
- Add/Delete users
- Revoke keys
- User can choose to extract a public key for each user and with the same private key 
- User-friendly and robust interface.

## Table of Contents

- [PGPManager](#pgpmanager)
  - [Future Releases](#future-releases)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Installation Steps](#installation-steps)
  - [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Copyright](#copyright)

## Getting Started

To get started with PGPManager, follow the installation instructions below.

## Installation

### Prerequisites

Before you can run the Terminal User Interface, you must first ensure that your system meets the necessary requirements.

1. Rust programming language:

The TUI is written in Rust, so Rustup, the installation and version management program for Rust, is required. If Rust is not installed on your system, please visit [the official Rust website](https://www.rust-lang.org/). for installation instructions.

1. Sequoia OpenPGP Crate:

The TUI relies on the Sequoia OpenPGP crates for certificate management. You must have certain dependencies installed in your system. Visit [the Sequoia repository](https://gitlab.com/sequoia-pgp/sequoia) for detailed instructions on the required libraries for different
different platforms

### Installation Steps

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/Digiyang/PGPManager.git
   ```

2. Change to the project directory:

   ```bash
   cd gui
   ```

3. Build the application:
      ```bash
      cargo build --release
      ```

4. Run the application:
      ```bash
      cargo run --release
      ```
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
# Contributing
Contributions are welcome! Feel free to open issues for any improvements or bug fixes.

# License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

# Contact
- [Email](mailto:Zeom@proton.me)
- [LinkedIn](https://www.linkedin.com/in/moez-rjiba-1a3ab21a2/)
- [Github](github.com/Digiyang)

# Copyright
Copyright © 2023, [Moez Rjiba](mailto:Zeom@proton.me). All rights reserved.
