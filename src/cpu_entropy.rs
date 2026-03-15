#[cfg(any(target_arch = "x86_64"))]
pub fn get_entropy_from_cpu() {
/// Does a query to "rdseed" processor register and returns None if status == 0 or unsupported feature
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

/// Does a query to "rdrand" processor register and returns None if status == 0 or unsupported feature
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