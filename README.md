# bice-rs client

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows-lightgrey.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-x64%20|%20ARM-lightgrey.svg)]()

**bice-rs** is a high-security, Zero-Knowledge, cross-platform password manager written in **Rust**. Designed with a focus on data integrity, cryptographic rigor, and hardware-isolated security, it mitigates standard software-only attack vectors.

The ecosystem consists of a lightweight local TUI client and a self-hosted synchronization server **([bice-rs-server](https://github.com/herabel/bice-rs-server))**.

bice-rs is a password manager project that implements powerful cryotography algorithms to protect your passwords.

## Implemented features:</br>
- [x] XChaCha20-Poly1305 for both files and channel encryption</br>
- [x] Argon2id KDF</br>
- [x] Handshake with your own hosted server via KyberX25519 (ML-KEM-1024)</br>
- [x] TUI via ratatui crate</br>
- [x] ESP32 integration for 2FA in Challenge-Response model</br>
- [x] entropy via cpu registers (rdrand and rdseed) with references on NIST SP 800-90</br>
- [x] Full Linux integration </br>
- [x] ARM integration </br>
- [x] Fuzzing </br>

## Roadmap: </br>

- [ ] Docs </br>
- [ ] Editing of password entires </br>

## Usage and installation:</br>
### First: Pre-compiled binary
Just download .exe file from [Releases](https://github.com/herabel/bice-rs/releases) page</br>
### Second: Build from source
To build `bice-rs` locally, ensure you have the latest stable Rust toolchain installed.

```bash
# Clone the repository
git clone https://github.com/herabel/bice-rs.git
cd bice-rs

# Compile and run in release mode
cargo run --release
```
