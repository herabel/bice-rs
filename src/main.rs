pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;

use std::path::Path;
use std::time::Instant;
use std::io::{self, Write};

use crate::vault::get_master_key;

// TODO: Общий реворк, добавление TUI, стилизация, zeroize и надёжные связи.
// TODO 2(в данный момент основное): Рефакторинг, больше инкапсуляции, минимум логики. main.rs должен стать тонкой прослойкой, не более.
fn main() {

    let hex_output = |output_to_hex: &[u8], description: &str| {
        let output: Vec<_> = (output_to_hex)        
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
        println!("Вывод HEX ({}): {:?}", description, output);
    };

    println!("[INFO] Запуск генератора энтропии...");
    let entropy_data = entropy::generate_random_bytes(512);

    hex_output(&entropy_data, "данные энтропии");

    let mut input = String::new();
    print!("Введите пароль: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut input).expect("[ERROR] Не получилось получить строку");

    let start_vault = Instant::now();
    let password_hash = vault::get_master_key(&input.trim(), &entropy_data, vault::SecurityProfile::Paranoid).expect("Не удалось сгенерировать мастер-ключ");
    let duration_vault = start_vault.elapsed();

    println!("[PERF] Argon2id выполнен за: {:?}", duration_vault);

    hex_output(&password_hash, "хэш пароля");

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
    // let _ = storage::save_password_bice("B1CE.bice", vault::get_master_key(&input.trim(), &entropy_data, vault::SecurityProfile::Paranoid).map_err(|e| format!("[ERROR] Ошибка записи в файл: {}", e));

    let master_key_to_save = match vault::get_master_key(input.trim(), &entropy_data, vault::SecurityProfile::Paranoid) {
        Ok(hash) => {
            hash
        },
        Err(e) => {
            println!("[ERROR] Не удалось сохранить файл! {}", e);
            return;
        }
    };

    let file_path = "B1CE.bice";

    let _ = storage::save_password_bice(file_path, &master_key_to_save);

    println!("\n[INFO] Проверка чтения из файла...");
    

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
