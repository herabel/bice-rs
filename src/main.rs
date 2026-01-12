pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;

use std::time::Instant;
use std::io::{self, Write};

fn main() {
    println!("[INFO] Запуск генератора энтропии...");

    let entropy_data = entropy::generate_512_bit_entropy();

    let hex_output: String = (&entropy_data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("Сгенерированная энтропия: {}", hex_output);

    let mut input = String::new();
    print!("Введите пароль: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut input).expect("[ERROR] Не получилось получить строку");

    let start_vault = Instant::now();
    let password_hash = vault::get_master_key(&input.trim(), &entropy_data).expect("Не удалось сгенерировать мастер-ключ");
    let duration_vault = start_vault.elapsed();

    println!("[PERF] Argon2id выполнен за: {:?}", duration_vault);

    let hex_output_hash: String = (&password_hash)
        .iter()
        .map(|c| format!("{:02x}", c))
        .collect();
    println!("{}", hex_output_hash);

    print!("Введите данные: ");
    let _ = io::stdout().flush();
    let mut data = String::new();
    io::stdin().read_line(&mut data).expect("[ERROR] Не получилось получить строку");

    let cypher_data = encryption::encrypt(data.trim().as_bytes(), &password_hash).expect("[ERROR] Ошибка шифрования данных");
    println!("Зашифрованый вектор с nonce и прочим: {:?}", cypher_data);
    let decrypted_bytes = encryption::decrypt(&cypher_data, &password_hash).expect("[ERROR] Ошибка дешифровки данных");
    let decrypted_data = String::from_utf8(decrypted_bytes).map_err(|e| format!("Ошибка кодировки UTF-8: {}", e));
    println!("Расшифрованные данные: {:?}", decrypted_data);

    println!("Сгенерированный пароль: {}", generator::generate_password(26, true, true, true));

    let _ = storage::save_bice("B1CE.bice", &entropy_data, &cypher_data).map_err(|e| format!("[ERROR] Ошибка записи в файл: {}", e));

    println!("\n[INFO] Проверка чтения из файла...");
    
    match storage::read_bice("B1CE.bice") {
        Ok(file_content) => {
            println!("[SUCCESS] Файл успешно прочитан!");
            println!("Соль из файла (первые 8 байт): {:02x?}", &file_content.salt[..8]);
            println!("Размер зашифрованных данных: {} байт", file_content.encrypted_data.len());

            let decrypted_from_file = encryption::decrypt(&file_content.encrypted_data, &password_hash)
                .expect("[ERROR] Не удалось расшифровать данные из файла");
            
            let final_text = String::from_utf8(decrypted_from_file)
                .expect("[ERROR] Ошибка кодировки при чтении файла");

            println!("Данные, восстановленные из файла: {}", final_text);
        },
        Err(e) => println!("[ERROR] Не удалось прочитать файл: {}", e),
    }
}
