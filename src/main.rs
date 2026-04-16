pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;
mod models;
pub mod cpu_entropy;

use std::path::Path;
use std::io::{self, Write};
use std::usize;

use crate::models::Vault;
#[allow(unused)]
use crate::vault::get_master_key;

// TODO: Общий реворк, добавление TUI, стилизация, zeroize и надёжные связи.
// TODO 2(в данный момент основное): Рефакторинг, больше инкапсуляции, минимум логики. main.rs должен стать тонкой прослойкой, не более.
fn main() {

    let file_path = "B1CE.bice";
    print!("Введите пароль: ");
    let _ = io::stdout().flush();
    let mut pwd = String::new();
    io::stdin().read_line(&mut pwd).unwrap();
    let pwd = pwd.trim();

    let mut current_profile= vault::SecurityProfile::Standard;

    let mut my_vault = if Path::new(file_path).exists(){
        println!("[INFO] Загрузка базы данных..");
        match Vault::load_from_disk(file_path, pwd){
            Ok(v) => {
                println!("[SUCCESS] Успешный вход. Записей: {}", v.entries.len());
                current_profile = Vault::get_profile_id(file_path);
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
        println!("=== Текущий профиль: {:?} ===", current_profile);
        println!("Детальнее ознакомиться с настройками каждого профиля можно в пункте 4 меню\n");
        println!("1. Показать пароли");
        println!("2. Добавить пароль");
        println!("3. Сгенерировать пароль");
        println!("4. Выбрать профиль шифрования Argon");
        println!("5. Запустить тесты");
        println!("0. Сохранить и Выйти");
        print!(">>> ");
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
                println!("Введите через пробел Сервис, Логин, Пароль, Описание (в описании можно пробелы далее - они не будут разделять):");
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                let parts: Vec<&str> = input.trim().split_whitespace().collect();
                if parts.len() >= 3 {
                    
                    let description = if parts.len() >= 4 {
                        Some(parts[3..].join(" ")) 
                    } else {
                        None
                    };

                    my_vault.add(parts[0].to_string(), parts[1].to_string(), parts[2].to_string(), description);
                    println!("[OK] Добавлено в память.");
                } else {
                    println!("[ERR] Неверный формат.");
                }
            }
            "3" => {
                loop {
                    println!("\nПример ввода: 24 true true true false");
                    println!("(length, use_uppercase, use_digits, use_specials, use_ascii)");
                    println!("Введите настройки генератора паролей (через пробел): ");
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).unwrap();
                    let parts: Vec<&str> = input.trim().split_whitespace().collect();
                    if parts.len() == 5 {
                        let length: usize = parts[0].parse().unwrap();
                        let use_uppercase: bool = parts[1].parse().unwrap();
                        let use_digits: bool = parts[2].parse().unwrap();
                        let use_specials: bool = parts[3].parse().unwrap();
                        let use_ascii: bool = parts[4].parse().unwrap();
                        println!("Ваш пароль с параметрами: {}", generator::generate_password(length, use_uppercase, use_digits, use_specials, use_ascii));
                        break;
                    } else {
                        println!("[ERR] Неверный формат.");
                    }
                }
            }
            "4" => {
                let mut selection_profile = String::new();
                loop {
                    println!("\n=== Выбор профиля шифрования для Argon2id ===");
                    println!("[m,t,p] - m - объем используемой памяти в МБ, t - количество итераций, p - параллелизм");
                    println!("Для корректной работы нужен СВОБОДНЫЙ блок памяти в ОЗУ");
                    println!("=============================================");
                    println!("1. Fast [64,6,4]");
                    println!("2. Standard [128,8,4]");
                    println!("3. Paranoid [512,8,4]");
                    println!("4. Extreme [1024,12,4]");
                    print!(">>> ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut selection_profile).unwrap();
                    match selection_profile.trim() {
                        "1" => { current_profile = 
                            vault::SecurityProfile::Fast;
                            break;
                        },
                        "2" => { current_profile = 
                            vault::SecurityProfile::Standard;
                            break;
                        },
                        "3" => { current_profile = 
                            vault::SecurityProfile::Paranoid;
                            break;
                        },
                        "4" => { 
                            current_profile = vault::SecurityProfile::Extreme;
                            break;
                        },
                        _ => println!("[WARN] Такой профиль не найден.")
                    }
                }
            }
            "5" => {
                #[cfg(target_arch = "x86_64")]
                if is_x86_feature_detected!("rdseed") {
                    cpu_entropy::get_entropy_from_cpu();
                } else {
                    println!("Процессор не поддерживает RDSEED");
                }
            }
            "0" => {
                println!("[INFO] Сохранение, не выключайте устройство и программу...");
                println!("[INFO] Сохранение может занять время в зависимости от выбранного профиля Argon и Вашего устройства.");
                match my_vault.save_to_disk(file_path, pwd, current_profile) {
                    Ok(_) => {
                        println!("[SUCCESS] Данные зашифрованы и сохранены. Покеда");
                        break;
                    },
                    Err(e) => println!("[ERROR] Не удалось сохранить: {}", e),
                }
            }
            _ => println!("Непонятная команда."),
        }
    }
}
