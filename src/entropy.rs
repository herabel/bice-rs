use getrandom;
use tiny_keccak::{Hasher, Shake, Xof};
use crate::cpu_entropy;
// TODO: Общий реворк модуля в соответствии с NIST SP800-90C (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.pdf)

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut vec_buf = vec![0u8; size];

    let mut hasher= Shake::v256();

    let mut os_buf = [0u8; 64];
    getrandom::fill(&mut os_buf).expect("[ERROR] : ОС не продоставила энтропию");

    let hard_random_number_rdrand = cpu_entropy::gen_rdrand(50).unwrap_or(0);
    if hard_random_number_rdrand != 0 {
        hasher.update(&hard_random_number_rdrand.to_le_bytes());
    } else {
        println!("[WARN] : rdrand returned 0 (entropy.rs) so this source degraded");
    }
    

    let hard_random_number_rdseed = cpu_entropy::gen_rdseed(50).unwrap_or(0);
    if hard_random_number_rdseed != 0 {
        hasher.update(&hard_random_number_rdseed.to_le_bytes());
    } else {
        println!("[WARN] : rdseed returned 0 (entropy.rs) so this source degraded")
    }

    hasher.update(&os_buf);

    hasher.squeeze(&mut vec_buf);

    vec_buf
}