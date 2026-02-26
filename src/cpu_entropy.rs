#[cfg(any(target_arch = "x86_64"))]
pub fn get_entropy_from_cpu() {
    println!("{}", gen_rdseed());
}

pub fn gen_rdseed() -> u64 {
    if is_x86_feature_detected!("rdseed") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdseed64_step(&mut val);
            assert_eq!(status, 1, "RDSEED failed: hardware entropy source exhausted");
            val
        }
    } else {
        println!("rdseed not found");
        0
    }
}

pub fn gen_rdrand() -> u64 {
    if is_x86_feature_detected!("rdrand") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = std::arch::x86_64::_rdrand64_step(&mut val);
            assert_eq!(status, 1, "RDRAND failed: hardware entropy source exhausted");
            val
        }
    } else {
        println!("rdrand not found");
        0
    }
}