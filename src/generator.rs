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

    let threshold = (256 / chars_len) * chars_len;

    let mut password = String::with_capacity(length);

    while password.len() < length {
        let rand_byte_buf = entropy::generate_random_bytes(length*2);
        for byte in rand_byte_buf {
            if password.len() == length {
                break;
            }
            let value = byte as usize;
            
            if value >= threshold{
                println!("[DEBUG] Произошёл отсев байта {} ({:02X})", value, value);
                continue;
            }
            
            let index = value % chars_len;
            password.push(chars[index]);
        }
    }
    password
}