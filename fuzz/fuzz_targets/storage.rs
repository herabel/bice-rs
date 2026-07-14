#![no_main]
use libfuzzer_sys::fuzz_target;
use bice_rs::storage::BiceFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(bice_file) = BiceFile::from_bytes(data) {
        let fake_password = [0u8; 32];
        let _ = bice_file.decrypt(fake_password);
    }
});