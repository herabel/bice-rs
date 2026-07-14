#![no_main]
use libfuzzer_sys::fuzz_target;
use bice_rs::models::Vault; 

fuzz_target!(|original_vault: Vault| {
    if let Ok(encoded) = postcard::to_stdvec(&original_vault) {
        let decoded_result: Result<Vault, _> = postcard::from_bytes(&encoded);
        if let Ok(recovered_vault) = decoded_result {
            assert_eq!(original_vault, recovered_vault);
        }
    }
});