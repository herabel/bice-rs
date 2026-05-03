use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Shake, Xof};

pub struct Esp32Response {
    pub pubkey: [u8; 32],
    pub signature: [u8; 64],
}

pub fn derive_challenge(salt: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Shake::v256();
    hasher.update(b"BICE_ESP32_CHALLENGE");
    hasher.update(salt);
    let mut challenge = [0u8; 32];
    hasher.squeeze(&mut challenge);
    challenge
}

pub fn derive_factor(signature: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Shake::v256();
    hasher.update(b"BICE_ESP32_FACTOR");
    hasher.update(signature);
    let mut factor = [0u8; 32];
    hasher.squeeze(&mut factor);
    factor
}

fn all_candidate_ports() -> Vec<String> {
    let mut ports: Vec<String> = Vec::new();

    if let Ok(listed) = serialport::available_ports() {
        for p in &listed {
            if !ports.contains(&p.port_name) {
                ports.push(p.port_name.clone());
            }
        }
    }

    for n in 1..=32 {
        let name = format!("COM{}", n);
        if !ports.contains(&name) {
            ports.push(name);
        }
    }

    ports
}

pub fn find_and_sign(challenge: &[u8; 32]) -> Result<Esp32Response, String> {
    let ports = all_candidate_ports();
    let mut last_err = String::from("No ports available");

    for port_name in &ports {
        match try_port(port_name, challenge) {
            Ok(response) => return Ok(response),
            Err(e) => last_err = format!("{}: {}", port_name, e),
        }
    }

    Err(format!("ESP32 not found. Last: {}", last_err))
}

fn try_port(port_name: &str, challenge: &[u8; 32]) -> Result<Esp32Response, String> {
    let mut port = serialport::new(port_name, 115200)
        .timeout(Duration::from_millis(200))
        .data_bits(serialport::DataBits::Eight)
        .stop_bits(serialport::StopBits::One)
        .parity(serialport::Parity::None)
        .flow_control(serialport::FlowControl::None)
        .open()
        .map_err(|e| format!("Cannot open: {}", e))?;

    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    port.clear(serialport::ClearBuffer::All).ok();

    std::thread::sleep(Duration::from_millis(50));

    port.write_data_terminal_ready(true).ok();
    port.write_request_to_send(true).ok();
    std::thread::sleep(Duration::from_millis(100));
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    port.clear(serialport::ClearBuffer::All).ok();

    let pubkey = find_magic_and_read_pubkey(&mut port, Duration::from_secs(6))?;

    std::thread::sleep(Duration::from_millis(200));

    port.clear(serialport::ClearBuffer::Input).ok();

    port.write_all(challenge)
        .map_err(|e| format!("Write error: {}", e))?;
    port.flush()
        .map_err(|e| format!("Flush error: {}", e))?;

    let signature = read_signature(&mut port, Duration::from_secs(30))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| format!("Invalid pubkey: {}", e))?;
    let sig = Signature::from_bytes(&signature);
    verifying_key.verify(challenge, &sig)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(Esp32Response { pubkey, signature })
}

fn find_magic_and_read_pubkey(
    port: &mut Box<dyn serialport::SerialPort>,
    timeout: Duration,
) -> Result<[u8; 32], String> {
    let start = Instant::now();
    let magic = b"2FA!";
    let mut matched = 0usize;

    while start.elapsed() < timeout {
        let mut byte = [0u8; 1];
        match port.read(&mut byte) {
            Ok(1) => {
                if byte[0] == magic[matched] {
                    matched += 1;
                    if matched == 4 {
                        break;
                    }
                } else if byte[0] == magic[0] {
                    matched = 1;
                } else {
                    matched = 0;
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(format!("Read error: {}", e)),
        }
    }

    if matched < 4 {
        return Err("Magic bytes 2FA! not found".to_string());
    }

    let mut pubkey = [0u8; 32];
    let mut read = 0;
    while read < 32 && start.elapsed() < timeout {
        match port.read(&mut pubkey[read..]) {
            Ok(n) if n > 0 => read += n,
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(format!("Pubkey read error: {}", e)),
        }
    }

    if read < 32 {
        return Err("Incomplete pubkey".to_string());
    }

    Ok(pubkey)
}

fn read_signature(
    port: &mut Box<dyn serialport::SerialPort>,
    timeout: Duration,
) -> Result<[u8; 64], String> {
    let start = Instant::now();
    let mut signature = [0u8; 64];
    let mut read = 0;

    while read < 64 && start.elapsed() < timeout {
        match port.read(&mut signature[read..]) {
            Ok(n) if n > 0 => read += n,
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(format!("Signature read error: {}", e)),
        }
    }

    if read < 64 {
        return Err("Signature timeout (button not pressed?)".to_string());
    }

    Ok(signature)
}
