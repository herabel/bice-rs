use getrandom;
use rdrand::{self, RdRand, RdSeed};
use tiny_keccak::{Hasher, Shake, Xof};
// TODO: Общий реворк модуля в соответствии с NIST SP800-90C (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.pdf)

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut vec_buf = vec![0u8; size];

    let mut hasher= Shake::v256();

    let hardw_gen_rdrand = match RdRand::new() {
        Ok(r#gen) => Some(r#gen),
        Err(_) => {
            eprintln!("[WARN] RDRAND не поддерживается.");
            None
        }
    };
    let hardw_gen_rdseed = match RdSeed::new() {
        Ok(r#gen) => Some(r#gen),
        Err(_) => {
            eprintln!("[WARN] RDSEED не поддерживается.");
            None
        }
    };

    let mut os_buf = [0u8; 64];
    getrandom::fill(&mut os_buf).expect("[ERROR] ОС не продоставила энтропию");

    if let Some(rdrand) = hardw_gen_rdrand{
        let hard_random_number_rdrand = rdrand.try_next_u64().expect("Ошибка получения значения RdRand из процессора.");
        hasher.update(&hard_random_number_rdrand.to_le_bytes());
    }
    
    if let Some(rdseed) = hardw_gen_rdseed{
        let hard_random_number_rdseed = rdseed.try_next_u64().expect("Ошибка получения значения RdSeed из процессора.");
        hasher.update(&hard_random_number_rdseed.to_le_bytes());
    }

    hasher.update(&os_buf);

    hasher.squeeze(&mut vec_buf);

    vec_buf
}