#![cfg(target_arch = "x86_64")]

/// Loops to gather entropy from [`try_rdseed`]. Returns `None` if the attempt is blank.
pub fn gen_rdseed(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdseed();
        if attempt.is_some() {
            return attempt;
        }
        std::hint::spin_loop();
    }
    None
}

/// Loops to gather entropy from [`try_rdrand`]. Returns `None` if the output is blank.
pub fn gen_rdrand(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdrand();
        if attempt.is_some() {
            return attempt;
        }
        std::hint::spin_loop();
    }
    None
}

/// Queries the hardware `RDRAND` processor register.
///
/// Returns `None` if the operation status is 0 or the feature is unsupported by the CPU.
pub fn try_rdseed() -> Option<u64> {
    if is_x86_feature_detected!("rdseed") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdseed64_step(&mut val);
            if status == 1 {
                Some(val)
            } else {
                None
            }
        }
    } else {
        None
    }
}

/// Queries the hardware `RDSEED` processor register.
///
/// Returns `None` if the operation status is 0 or the feature is unsupported by the CPU.
pub fn try_rdrand() -> Option<u64> {
    if is_x86_feature_detected!("rdrand") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdrand64_step(&mut val);
            if status == 1 {
                Some(val)
            } else {
                None
            }
        }
    } else {
        None
    }
}