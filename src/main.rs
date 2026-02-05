pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;
mod models;

use std::path::Path;
use std::io::{self, Write};
use crate::models::Vault;
#[allow(unused)]
use crate::vault::get_master_key;

// TODO: Общий реворк, добавление TUI, стилизация, zeroize и надёжные связи.
// TODO 2(в данный момент основное): Рефакторинг, больше инкапсуляции, минимум логики. main.rs должен стать тонкой прослойкой, не более.
fn main() {

    #[allow(unused)]
    let file_path = "B1CE.bice";
    print!("Введите пароль:");
    let _ = io::stdout().flush();
    let mut pwd = String::new();
    io::stdin().read_line(&mut pwd).unwrap();
    let mut pwd = pwd.trim();

    let mut my_vault = if Path::new(file_path).exists(){
        println!("[INFO] Загрузка базы данных..");
        match Vault::load_from_disk(file_path, pwd){
            Ok(v) => {
                println!("[SUCCESS] Успешный вход. Записей: {}", v.entries.len());
                v
            }
            Err(e) => {
                println!("[ERROR] Ошибка входа: {e}");
                return;
            }
        }
    } else {
        println!("[INFO] Файл не найден. Создание новой базы.");
        Vault::new()
    };

    loop {
        println!("\n=== BICE MENU ===");
        println!("1. Показать пароли");
        println!("2. Добавить пароль");
        println!("3. Сохранить и Выйти");
        print!("> ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                for (i, entry) in my_vault.entries.iter().enumerate() {
                    println!("{}. {} | Login: {} | Password: {} | Description: {:?} ", i + 1, entry.service, entry.login, entry.password, entry.description);
                }
            }
            "2" => {
                println!("Введите Сервис, Логин, Пароль, Описание (через пробел):");
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                let parts: Vec<&str> = input.trim().split_whitespace().collect();
                if parts.len() >= 4 {
                    my_vault.add(parts[0].to_string(), parts[1].to_string(), parts[2].to_string(), Some(parts[3].to_string()));
                    println!("[OK] Добавлено в память.");
                } else {
                    println!("[ERR] Неверный формат.");
                }
            }
            "3" => {
                println!("[INFO] Сохранение...");
                match my_vault.save_to_disk(file_path, pwd, vault::SecurityProfile::Paranoid) {
                    Ok(_) => {
                        println!("[SUCCESS] Данные зашифрованы и сохранены. Пока!");
                        break;
                    },
                    Err(e) => println!("[ERROR] Не удалось сохранить: {}", e),
                }
            }
            _ => println!("Непонятная команда"),
        }
    }


    // deprecated
    /*
    let hex_output = |output_to_hex: &[u8], description: &str| {
        let output: Vec<_> = (output_to_hex)        
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
        println!("Вывод HEX ({}): {:?}", description, output);
    };

    println!("[INFO] Запуск генератора энтропии...");

    let entropy_data: Vec<u8> = match Path::new(file_path).exists() {
        true => 
            match storage::read_bice(file_path) {
                Ok(file_content) => {
                    file_content.salt.to_vec()
                },
                Err(e) => {
                    println!("[ERROR] Не удалось прочитать файл: {}", e);
                    panic!();
                }
            },
        false => entropy::generate_random_bytes(64),
    };

    hex_output(&entropy_data, "данные энтропии");

    let mut input = String::new();
    print!("Введите пароль: ");
    let _ = io::stdout().flush();
    io::stdin().read_line(&mut input).expect("[ERROR] Не получилось получить строку");

    let start_vault = Instant::now();
    let password_hash = vault::get_master_key(input.trim(), &entropy_data, vault::SecurityProfile::Paranoid).expect("Не удалось сгенерировать мастер-ключ");
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
    #[allow(unused)]
    let file = storage::BiceFile::new(&entropy_data, &master_key_to_save);

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
    }*/
}
