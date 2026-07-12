//! Entropy generation source leveraging CPU hardware jitter/instructions.
//! 
//! This module provides a Deterministic Random Bit Generator (DRBG)
//! backed by [`cpu_entropy`].
//! 
//! ### Traits
//! - Implements [rand_core::RngCore](https://docs.rs/rand_core/0.6.4/rand_core/trait.RngCore.html) (v0.6) for standard sampling.
//! - Implements [rand_core::TryRng](https://docs.rs/rand_core/0.10/rand_core/trait.TryRng.html) (v0.10) for fallible entropy retrieval.
//! 
//! ### Security note
//! Uses direct CPU instructions. Ensure the target architecture supports
//! the necessary features (`rdrand`, `rdseed` via [`cpu_entropy`]) before deployment.

use getrandom;
use rand_core::TryRng;
use tiny_keccak::{Hasher, Shake, Xof};
use crate::cpu_entropy;
use rand_core_06::{self};

pub struct HardwareEntropyPool{
    state: tiny_keccak::Shake,
    counter: usize,
}

impl Default for HardwareEntropyPool {
    fn default() -> Self {
        Self::new()
    }
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
    fn next_u32(&mut self) -> u32 {
        self.try_next_u32().unwrap()
    }

    fn next_u64(&mut self) -> u64 {
        self.try_next_u64().unwrap()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = rand_core::TryRng::try_fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::TryRng for HardwareEntropyPool{
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.state.squeeze(dst);
        self.counter += dst.len();
        Ok(())
    }

    fn try_next_u32(&mut self) -> Result<u32,Self::Error> {
        let mut local_array = [0u8;4];
        let _ = rand_core::TryRng::try_fill_bytes(self, &mut local_array);
        let output = u32::from_le_bytes(local_array);
        Ok(output)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut local_array = [0u8;8];
        let _ = rand_core::TryRng::try_fill_bytes(self, &mut local_array);
        let output = u64::from_le_bytes(local_array);
        Ok(output)
    }
    
    type Error = core::convert::Infallible;
}

impl rand_core::TryCryptoRng for HardwareEntropyPool {}
impl rand_core_06::CryptoRng for HardwareEntropyPool {}


pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut pool = HardwareEntropyPool::new();
    let mut vec = vec![0u8; size];
    HardwareEntropyPool::try_fill_bytes(&mut pool, &mut vec);
    vec
}