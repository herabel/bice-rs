bice-rs client app 

bice-rs is a password manager project that implements powerful cryotography algorithms to protect your passwords.

there's also a [bice-rs-server](https://github.com/herabel/bice-rs-server) (License: **AGPL-3.0**) for self-hosted passwords sync.

for now, readme is dull</br>

implemented features:</br>
- [x] XChaCha20-poly1305</br>
- [x] Argon2id</br>
- [x] handshake with your own hosted server via KyberX25519</br>
- [x] TUI via ratatui lib</br>
- [x] ESP32 integration for 2FA in Challenge-Response model</br>
- [x] entropy via cpu registers (rdrand and rdseed) with references on NIST SP 800-90</br>

roadmap: </br>
- [ ] Full Linux integration </br>
- [ ] Fuzzing </br>
- [ ] ARM integration </br>
- [ ] Docs </br>

usage, there's two variants:</br>
First: Just download .exe file from Releases page</br>
Second: Copy repo and use `cargo run --release` in your folder
