use getrandom;
use rand_core::TryRng;
use tiny_keccak::{Hasher, Shake, Xof};
use crate::cpu_entropy;
use rand_core_06::{self};

pub struct HardwareEntropyPool{
    state: tiny_keccak::Shake,
    counter: usize,
}

impl HardwareEntropyPool {
    pub fn new() -> Self {

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

        Self { state: (hasher), counter: (0) }
    }
}

impl rand_core_06::RngCore for HardwareEntropyPool {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = rand_core::TryRng::try_fill_bytes(self, dest);
    }

    fn next_u32(&mut self) -> u32 {
        self.try_next_u32().unwrap()
    }

    fn next_u64(&mut self) -> u64 {
        self.try_next_u64().unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

}