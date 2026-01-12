use crate::entropy;

pub fn generate_password(length: usize, use_uppercase: bool, use_digits: bool, use_specials: bool) -> String {
    pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
    pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    pub const DIGITS: &str = "0123456789";
    pub const SPECIAL: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut charset = String::from(LOWERCASE);

    if use_uppercase { charset.push_str(UPPERCASE) };
    if use_digits { charset.push_str(DIGITS) };
    if use_specials { charset.push_str(SPECIAL) };

    let chars: Vec<char> = charset.chars().collect();
    let chars_len = chars.len();

    let mut password = String::with_capacity(length);

    for _ in 1..length {
        let rand_byte = entropy::generate_random_bytes(1)[0];
        let index = (rand_byte as usize) % chars_len;
        let symbol = chars[index];
        password.push(symbol);
    }

    password
}