pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;

use std::convert::TryInto;
use std::path::Path;
use std::time::Instant;
use std::io::{self, Write};

use crate::vault::get_master_key;

// TODO: Общий реворк, добавление TUI, стилизация, zeroize и надёжные связи.
fn main() {
    println!("[INFO] Запуск генератора энтропии...");
    let entropy_data = entropy::generate_random_bytes(512);

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
    let password_hash = vault::get_master_key(&input.trim(), &entropy_data, vault::SecurityProfile::Paranoid).expect("Не удалось сгенерировать мастер-ключ");
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
    let decrypted_data = String::from_utf8(decrypted_bytes).map_err(|e| format!("Ошибка кодировки UTF-8: {}", e)).expect("[ERROR] Ошибка чтения данных");
    println!("Расшифрованные данные: {:?}", decrypted_data);

    println!("Сгенерированный пароль: {}", generator::generate_password(26, true, true, true));

    let _ = storage::save_bice("B1CE.bice", &entropy_data, &cypher_data).map_err(|e| format!("[ERROR] Ошибка записи в файл: {}", e));

    println!("\n[INFO] Проверка чтения из файла...");
    
    let file_path = "B1CE.bice";

    if Path::new(file_path).exists() {
        let mut master_key_login = String::new();
        println!("[INFO] Файл БД найден. Необходим вход.");
        print!("[LOGIN] Введите пароль: ");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut master_key_login);

        match storage::read_bice(file_path) {
            Ok(file_content) => {
                println!("[SUCCESS] Файл успешно прочитан!");
                println!("Соль из файла (первые 8 байт): {:02x?}", &file_content.salt[..8]);
                let bice_salt = &file_content.salt.to_vec();
                println!("Размер зашифрованных данных: {} байт", file_content.encrypted_data.len());
                
                let login_password_hash = get_master_key(&master_key_login.trim(), bice_salt, vault::SecurityProfile::Paranoid).expect("[ERROR] Не удалось сгенерировать мастер-ключ для разблокировки БД.");
                match encryption::decrypt(&file_content.encrypted_data, &login_password_hash) {
                    Ok(decrypted_bytes) => {
                        match String::from_utf8(decrypted_bytes) {
                            Ok(final_text) => {
                                println!("Данные, восстановленные из файла: {}", final_text);
                            }
                            Err(_) => {
                                println!("[ERR] Ошибка расшифровки файла, битые данные.")
                            }
                        };
                    },
                    Err(_) =>{
                        println!("[DENIED] Неверный пароль. Доступ запрещён.")
                    }
                };
            },
            Err(e) => println!("[ERROR] Не удалось прочитать файл: {}", e),
        }
    }
}
