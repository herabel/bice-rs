use crate::{entropy::generate_random_bytes, models::PasswordEntry, storage::BiceFile, tui::ui::PasswordGenerator};
use arboard;
use color_eyre::eyre::Ok;
use crossterm::event::{self, KeyCode, KeyEvent};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::*,
    widgets::*,
};
use std::{fmt::Debug, fs, path::Path, time::Duration};

use crate::{
    models::{self, Vault},
    tui::ui,
    vault::{SecurityProfile, get_master_key},
    sync::{self, ServerConfig, Session, SyncCommand, SyncResult, spawn_worker},
    esp32,
};

#[derive(PartialEq)]
pub enum ServerField {
    Login,
    Password,
    Url,
}

// TODO: Need to refactor a god object
#[allow(unused)]
pub struct App {
    pub(crate) current_profile: SecurityProfile,
    pub(crate) input: String,
    cursor_position: usize,
    pub vault: Option<Vault>,
    logs: Vec<String>,
    list_state: ListState,
    pub table_state: TableState,
    pub(crate) current_screen: Screen,
    should_quit: bool,
    pub(crate) input_mode: InputMode,
    pub(crate) previous_screen: Screen,
    file_path: String,
    password_hash: Option<[u8; 32]>,
    salt: Option<[u8; 64]>,
    pub generator: PasswordGenerator,
    pub active_field: AddField,
    pub draft: PasswordEntry,
    pub(crate) server_config: ServerConfig,
    pub(crate) server_session: Option<Session>,
    pub(crate) server_input_login: String,
    pub(crate) server_input_password: String,
    pub(crate) server_status: String,
    pub(crate) server_active_field: ServerField,
    pub(crate) sync_cmd_tx: Option<std::sync::mpsc::Sender<SyncCommand>>,
    pub(crate) sync_res_rx: Option<std::sync::mpsc::Receiver<SyncResult>>,
    pub(crate) server_versions: Vec<i32>,
    pub(crate) versions_state: ratatui::widgets::ListState,
    pub(crate) esp32_enabled: bool,
    pub(crate) esp32_pubkey: Option<[u8; 32]>,
    pub(crate) esp32_status: String,
    pub(crate) esp32_rx: Option<std::sync::mpsc::Receiver<Result<esp32::Esp32Response, String>>>,
    pub(crate) esp32_pending_key: Option<[u8; 32]>,
    pub(crate) esp32_pending_bice: Option<BiceFile>,
    pub(crate) esp32_operation: Esp32Operation,
}

#[derive(PartialEq)]
pub enum AddField {
    Service,
    Login,
    Password,
    Note,
}

#[derive(PartialEq, Clone, Copy)]
pub enum Esp32Operation {
    None,
    Decrypt,
    NewDb,
    Attach,
    Detach,
}

impl Debug for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "Auth"),
            Self::Dashboard => write!(f, "Dashboard"),
            Self::Handshake => write!(f, "Handshake"),
            Self::Error => write!(f, "Error"),
            Self::Generator => write!(f, "Generator"),
            Self::Add => write!(f, "Add"),
            Self::Profiles => write!(f, "Profiles"),
            Self::Loading => write!(f, "Loading"),
            Self::Sync => write!(f, "Sync"),
            Self::ServerLogin => write!(f, "ServerLogin"),
            Self::ServerRegister => write!(f, "ServerRegister"),
            Self::ServerSettings => write!(f, "ServerSettings"),
            Self::ServerVersions => write!(f, "ServerVersions"),
            Self::Esp32Setup => write!(f, "Esp32Setup"),
            Self::Esp32Auth => write!(f, "Esp32Auth"),
        }
    }
}

impl PartialEq for Screen {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

impl Clone for Screen {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Screen {}

impl Debug for InputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Editing => write!(f, "Editing"),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> color_eyre::Result<()> {
        while !self.should_quit {
            terminal.draw(|frame: &mut Frame| self.draw(frame))?;
            self.handle_events()?;
        }
        let logs = self.logs.join("\n");
        let _ = fs::write("logs.txt", logs);
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let root_area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Fill(1),
                Constraint::Length(3),
            ])
            .split(root_area);
        let header_block = Block::new().bg(Color::Rgb(48, 54, 51)).padding(Padding {
            left: 0,
            right: 0,
            top: 1,
            bottom: 0,
        });
        let header = Paragraph::new("BICE Password Manager")
            .block(header_block)
            .fg(Color::Rgb(139, 232, 203))
            .centered();
        let footer_text = self.current_screen.footer_hints();
        let footer_block = Block::new().bg(Color::Rgb(48, 54, 51)).padding(Padding {
            left: 0,
            right: 0,
            top: 1,
            bottom: 0,
        });
        let footer = Paragraph::new(footer_text)
            .block(footer_block.clone().padding(Padding {
                left: 5,
                right: 0,
                top: 1,
                bottom: 0,
            }))
            .fg(Color::Rgb(136, 141, 167))
            .left_aligned();

        let kawaii = Paragraph::new("(˵ ͡~ ͜ʖ ͡°˵)ﾉ⌒♡*:・。.")
            .fg(Color::Rgb(156, 122, 151))
            .block(footer_block.clone());

        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(20), Constraint::Fill(1)])
            .split(chunks[2]);
        match self.current_screen {
            Screen::Auth => ui::render_auth(frame, chunks[1], self),
            Screen::Dashboard => ui::render_dashboard(frame, chunks[1], self),
            Screen::Handshake => todo!(),
            Screen::Error => todo!(),
            Screen::Generator => ui::render_generator(frame, chunks[1], self),
            Screen::Add => ui::render_add(frame, chunks[1], self),
            Screen::Profiles => ui::render_profiles(frame, chunks[1], self),
            Screen::Loading => todo!(),
            Screen::Sync => ui::render_sync(frame, chunks[1], self),
            Screen::ServerLogin | Screen::ServerRegister => ui::render_server_auth(frame, chunks[1], self),
            Screen::ServerSettings => ui::render_server_settings(frame, chunks[1], self),
            Screen::ServerVersions => ui::render_server_versions(frame, chunks[1], self),
            Screen::Esp32Setup => ui::render_esp32_setup(frame, chunks[1], self),
            Screen::Esp32Auth => ui::render_esp32_auth(frame, chunks[1], self),
        }
        frame.render_widget(header, chunks[0]); // header
        frame.render_widget(footer, footer_chunks[1]); // footer buttons
        frame.render_widget(kawaii, footer_chunks[0]); // footer kawaii
    }

    fn handle_events(&mut self) -> color_eyre::Result<()> {
        let poll = event::poll(Duration::from_millis(16))?;
        if poll
            && let Some(key) = event::read()?.as_key_press_event() {
                if self.input_mode == InputMode::Normal {
                    self.handle_normal_events(key);
                } else {
                    self.handle_editing_events(key);
                }
            };

        if let Some(rx) = &self.sync_res_rx
            && let std::result::Result::Ok(res) = rx.try_recv() {
                match res {
                    SyncResult::LoginOk(session) => {
                        sync::save_session(&self.file_path, &session);
                        self.server_session = Some(session);
                        self.server_status = "Login successful".to_string();
                        self.server_input_password.clear();
                        if self.current_screen == Screen::ServerLogin {
                            self.current_screen = Screen::Sync;
                            self.input_mode = InputMode::Normal;
                        }
                    }
                    SyncResult::RegisterOk(msg) => {
                        self.server_status = format!("Register ok: {}", msg);
                        if self.current_screen == Screen::ServerRegister {
                            self.current_screen = Screen::Sync;
                            self.input_mode = InputMode::Normal;
                        }
                    }
                    SyncResult::PushOk(ver) => {
                        self.server_status = format!("Push ok, version: {}", ver);
                    }
                    SyncResult::PullOk => {
                        self.server_status = "Pull ok. Vault updated.".to_string();
                        
                        // Try to reload automatically
                        let mut success = false;
                        if let Some(key) = self.password_hash
                            && let std::result::Result::Ok(bice) = BiceFile::open(&self.file_path)
                                && let std::result::Result::Ok(decrypted_data) = bice.decrypt(key)
                                    && let std::result::Result::Ok(vault) = postcard::from_bytes(&decrypted_data) {
                                        self.vault = Some(vault);
                                        self.salt = BiceFile::get_salt_from_file(self.file_path.clone()).ok();
                                        success = true;
                                    }
                        
                        if !success {
                            self.server_status = "Pull ok, but failed to decrypt with current password. Please login again.".to_string();
                            self.vault = None;
                            self.current_screen = Screen::Auth;
                            self.previous_screen = Screen::Auth;
                        }
                    }
                    SyncResult::VersionsOk(versions) => {
                        self.server_status = format!("Loaded {} versions", versions.len());
                        self.server_versions = versions;
                        if !self.server_versions.is_empty() {
                            self.versions_state.select(Some(self.server_versions.len() - 1));
                        }
                        self.current_screen = Screen::ServerVersions;
                    }
                    SyncResult::Error(err) => {
                        self.server_status = format!("Error: {}", err);
                    }
                }
            }
        if let Some(rx) = &self.esp32_rx
            && let std::result::Result::Ok(result) = rx.try_recv() {
                self.esp32_rx = None;
                match result {
                    std::result::Result::Ok(response) => {
                        self.handle_esp32_response(response);
                    }
                    Err(e) => {
                        self.esp32_status = format!("Error: {}", e);
                        self.esp32_pending_key = None;
                        self.esp32_pending_bice = None;
                    }
                }
            }

        Ok(())
    }

fn handle_normal_events(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => {
                self.try_save();
                self.should_quit = true;
            }
            KeyCode::Char('g') | KeyCode::Char(' ') => {
                if self.current_screen == Screen::Generator {
                    self.generator.generate_password();
                } else if key.code == KeyCode::Char('g') {
                    if self.previous_screen != self.current_screen {
                        self.previous_screen = self.current_screen;
                    };
                    self.drop_input();
                    self.current_screen = Screen::Generator;
                }
            }
            KeyCode::Char('1') => {
                if self.current_screen == Screen::Generator {
                    self.generator.params[0] = !self.generator.params[0];
                    self.generator.generate_password();
                } else if self.current_screen == Screen::Profiles {
                    self.current_profile = SecurityProfile::Fast;
                }
            }
            KeyCode::Char('2') => {
                if self.current_screen == Screen::Generator {
                    self.generator.params[1] = !self.generator.params[1];
                    self.generator.generate_password();
                } else if self.current_screen == Screen::Profiles {
                    self.current_profile = SecurityProfile::Standard;
                }
            }
            KeyCode::Char('3') => {
                if self.current_screen == Screen::Generator {
                    self.generator.params[2] = !self.generator.params[2];
                    self.generator.generate_password();
                } else if self.current_screen == Screen::Profiles {
                    self.current_profile = SecurityProfile::Paranoid;
                }
            }
            KeyCode::Char('4') => {
                if self.current_screen == Screen::Generator {
                    self.generator.params[3] = !self.generator.params[3];
                    self.generator.generate_password();
                } else if self.current_screen == Screen::Profiles {
                    self.current_profile = SecurityProfile::Extreme;
                }
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                if self.current_screen == Screen::Generator && self.generator.length < 64 {
                    self.generator.length += 1;
                    self.generator.generate_password();
                }
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                if self.current_screen == Screen::Generator && self.generator.length > 4 {
                    self.generator.length -= 1;
                    self.generator.generate_password();
                }
            }
            KeyCode::Char('p') => {
                if self.current_screen == Screen::Auth {
                    self.previous_screen = self.current_screen;
                    self.current_screen = Screen::Profiles;
                }
            }
            KeyCode::Char('e') => {
                if self.current_screen == Screen::Auth {
                    self.esp32_enabled = !self.esp32_enabled;
                } else if self.current_screen == Screen::Dashboard {
                    self.previous_screen = self.current_screen;
                    self.esp32_status = if self.esp32_pubkey.is_some() {
                        "ESP32: Enabled".to_string()
                    } else {
                        "ESP32: Not configured".to_string()
                    };
                    self.current_screen = Screen::Esp32Setup;
                }
            }
            KeyCode::Char('a') => {
                if self.current_screen == Screen::Esp32Setup && self.esp32_pubkey.is_none() {
                    self.esp32_operation = Esp32Operation::Attach;
                    self.start_esp32_auth();
                }
            }
            KeyCode::Backspace => {
                if self.current_screen == Screen::Esp32Auth {
                    self.esp32_rx = None;
                    self.esp32_pending_key = None;
                    self.esp32_pending_bice = None;
                    self.esp32_operation = Esp32Operation::None;
                    self.current_screen = Screen::Auth;
                } else if self.current_screen != Screen::Auth {
                    self.drop_input();
                    self.current_screen = self.previous_screen;
                }
            }
            KeyCode::Char('i') => self.input_mode = InputMode::Editing,
            KeyCode::Char('c') => {
                if self.current_screen == Screen::Generator && self.generator.password.is_some() {
                    if let Some(password) = &self.generator.password {
                        if let Some(mut clipboard) = arboard::Clipboard::new().ok() {
                            let _ = clipboard.set_text(password);
                        };
                    }
                } else if self.current_screen == Screen::Sync {
                    self.server_status.clear();
                    self.current_screen = Screen::ServerSettings;
                    self.input_mode = InputMode::Editing;
                }
            }
            KeyCode::Char('s') => {
                if self.current_screen == Screen::Dashboard {
                    self.previous_screen = self.current_screen;
                    self.current_screen = Screen::Sync;
                }
            }
            KeyCode::Char('n') => {
                if self.current_screen == Screen::Dashboard {
                    self.previous_screen = self.current_screen;
                    self.current_screen = Screen::Add;
                }
            }
            KeyCode::Char('l') => {
                if self.current_screen == Screen::Sync {
                    self.server_input_login.clear();
                    self.server_input_password.clear();
                    self.server_active_field = ServerField::Login;
                    self.server_status.clear();
                    self.current_screen = Screen::ServerLogin;
                    self.input_mode = InputMode::Editing;
                }
            }
            KeyCode::Char('r') => {
                if self.current_screen == Screen::Sync {
                    self.server_input_login.clear();
                    self.server_input_password.clear();
                    self.server_active_field = ServerField::Login;
                    self.server_status.clear();
                    self.current_screen = Screen::ServerRegister;
                    self.input_mode = InputMode::Editing;
                } else if self.current_screen == Screen::Esp32Setup && self.esp32_pubkey.is_some() {
                    self.esp32_operation = Esp32Operation::Detach;
                    self.start_esp32_auth();
                }
            }
            KeyCode::Char('u') => {
                if self.current_screen == Screen::Sync {
                    // TODO: After App refactoring need to resolve borrow conflicts avoid redundant heap allocations from clone()
                    if let Some(session) = self.server_session.clone() { 
                        if let Some(tx) = self.sync_cmd_tx.clone() { // clone() here is fine
                            self.try_save();
                            let _ = tx.send(sync::SyncCommand::Push {
                                config: self.server_config.clone(),
                                session: session.clone(),
                                file_path: self.file_path.clone(),
                            });
                            self.server_status = "Pushing...".to_string();
                        }
                    } else {
                        self.server_status = "Not logged in".to_string();
                    }
                }
            }
            KeyCode::Char('d') => {
                if self.current_screen == Screen::Sync {
                    if let Some(session) = &self.server_session {
                        if let Some(tx) = &self.sync_cmd_tx {
                            let _ = tx.send(sync::SyncCommand::GetVersions {
                                config: self.server_config.clone(),
                                session: session.clone(),
                            });
                            self.server_status = "Fetching versions...".to_string();
                        }
                    } else {
                        self.server_status = "Not logged in".to_string();
                    }
                }
            }
            KeyCode::Enter => {
                if self.current_screen == Screen::Dashboard {
                    if let Some(vault) = &self.vault
                        && let Some(selected) = self.table_state.selected()
                            && let Some(entry) = vault.entries.get(selected) {
                                let clipboard_tuple = arboard::Clipboard::new().ok();
                                if let Some(mut clipboard) = clipboard_tuple {
                                    let _ = clipboard.set_text(entry.password.clone());
                                }
                            }
                } else if self.current_screen == Screen::ServerVersions
                    && let Some(selected) = self.versions_state.selected()
                        && let Some(&version) = self.server_versions.get(selected)
                            && let Some(session) = &self.server_session
                                && let Some(tx) = &self.sync_cmd_tx {
                                    let _ = tx.send(sync::SyncCommand::Pull {
                                        config: self.server_config.clone(),
                                        session: session.clone(),
                                        version,
                                        file_path: self.file_path.clone(),
                                    });
                                    self.server_status = format!("Pulling version {}...", version);
                                    self.current_screen = Screen::Sync;
                                }
            }
            KeyCode::Tab | KeyCode::Down => {
                if self.current_screen == Screen::Add {
                    self.active_field = match self.active_field {
                        AddField::Service => AddField::Login,
                        AddField::Login => AddField::Password,
                        AddField::Password => AddField::Note,
                        AddField::Note => AddField::Service,
                    };
                } else if self.current_screen == Screen::Dashboard {
                    if let Some(vault) = &self.vault {
                        let i = match self.table_state.selected() {
                            Some(i) => {
                                if i >= vault.entries.len().saturating_sub(1) {
                                    0
                                } else {
                                    i + 1
                                }
                            }
                            None => 0,
                        };
                        self.table_state.select(Some(i));
                    }
                } else if self.current_screen == Screen::ServerVersions
                    && let Some(selected) = self.versions_state.selected()
                        && selected < self.server_versions.len().saturating_sub(1) {
                            self.versions_state.select(Some(selected + 1));
                        }
            }
            KeyCode::Up => {
                if self.current_screen == Screen::Add {
                    self.active_field = match self.active_field {
                        AddField::Service => AddField::Note,
                        AddField::Login => AddField::Service,
                        AddField::Password => AddField::Login,
                        AddField::Note => AddField::Password,
                    };
                } else if self.current_screen == Screen::Dashboard {
                    if let Some(vault) = &self.vault {
                        let i = match self.table_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    vault.entries.len().saturating_sub(1)
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        self.table_state.select(Some(i));
                    }
                } else if self.current_screen == Screen::ServerVersions
                    && let Some(selected) = self.versions_state.selected()
                        && selected > 0 {
                            self.versions_state.select(Some(selected - 1));
                        }
            }
            _ => {}
        };
    }

    fn drop_input(&mut self) {
        self.input.clear();
    }


    ///Keys handler in editing mode, depends on current screen
    fn handle_editing_events(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) => {
                if self.current_screen == Screen::Add {
                    match self.active_field {
                        AddField::Service => self.draft.service.push(c),
                        AddField::Login => self.draft.login.push(c),
                        AddField::Password => self.draft.password.push(c),
                        AddField::Note => {
                            if let Some(desc) = &mut self.draft.description {
                                desc.push(c);
                            } else {
                                self.draft.description = Some(c.to_string());
                            }
                        }
                    }
                } else if self.current_screen == Screen::ServerLogin || self.current_screen == Screen::ServerRegister {
                    match self.server_active_field {
                        ServerField::Login => self.server_input_login.push(c),
                        ServerField::Password => self.server_input_password.push(c),
                        _ => {}
                    }
                } else if self.current_screen == Screen::ServerSettings {
                    self.server_config.url.push(c);
                } else {
                    self.input.push(c);
                }
            }
            KeyCode::Backspace => {
                if self.current_screen == Screen::Add {
                    match self.active_field {
                        AddField::Service => { self.draft.service.pop(); }
                        AddField::Login => { self.draft.login.pop(); }
                        AddField::Password => { self.draft.password.pop(); }
                        AddField::Note => {
                            if let Some(desc) = &mut self.draft.description {
                                desc.pop();
                                if desc.is_empty() {
                                    self.draft.description = None;
                                }
                            }
                        }
                    }
                } else if self.current_screen == Screen::ServerLogin || self.current_screen == Screen::ServerRegister {
                    match self.server_active_field {
                        ServerField::Login => { self.server_input_login.pop(); },
                        ServerField::Password => { self.server_input_password.pop(); },
                        _ => {}
                    }
                } else if self.current_screen == Screen::ServerSettings {
                    self.server_config.url.pop();
                } else {
                    self.input.pop();
                }
            }
            KeyCode::Esc => self.input_mode = InputMode::Normal,
            KeyCode::Tab | KeyCode::Down => {
                if self.current_screen == Screen::Add {
                    self.active_field = match self.active_field {
                        AddField::Service => AddField::Login,
                        AddField::Login => AddField::Password,
                        AddField::Password => AddField::Note,
                        AddField::Note => AddField::Service,
                    };
                } else if self.current_screen == Screen::ServerLogin || self.current_screen == Screen::ServerRegister {
                    self.server_active_field = match self.server_active_field {
                        ServerField::Login => ServerField::Password,
                        ServerField::Password => ServerField::Login,
                        _ => ServerField::Login,
                    };
                }
            }
            KeyCode::Up => {
                if self.current_screen == Screen::Add {
                    self.active_field = match self.active_field {
                        AddField::Service => AddField::Note,
                        AddField::Login => AddField::Service,
                        AddField::Password => AddField::Login,
                        AddField::Note => AddField::Password,
                    };
                } else if self.current_screen == Screen::ServerLogin || self.current_screen == Screen::ServerRegister {
                    self.server_active_field = match self.server_active_field {
                        ServerField::Login => ServerField::Password,
                        ServerField::Password => ServerField::Login,
                        _ => ServerField::Login,
                    };
                }
            }
            KeyCode::Enter => match self.current_screen {
                Screen::Auth => {
                    self.vault = self.try_password();
                    if let Some(_vault) = &self.vault {
                        self.drop_input();
                        self.input_mode = InputMode::Normal;
                        self.previous_screen = self.current_screen;
                        self.current_screen = Screen::Dashboard;
                    }
                }
                Screen::Add => {
                    if let Some(vault) = &mut self.vault {
                        vault.entries.push(self.draft.clone());
                    }
                    self.draft = PasswordEntry {
                        service: String::new(),
                        login: String::new(),
                        password: String::new(),
                        description: None,
                    };
                    self.active_field = AddField::Service;
                    self.input_mode = InputMode::Normal;
                    self.previous_screen = self.current_screen;
                    self.current_screen = Screen::Dashboard;
                }
                Screen::ServerSettings => {
                    self.current_screen = Screen::Sync;
                    self.input_mode = InputMode::Normal;
                }
                Screen::ServerLogin => {
                    if let Some(tx) = &self.sync_cmd_tx {
                        let _ = tx.send(sync::SyncCommand::Login {
                            config: self.server_config.clone(),
                            login: self.server_input_login.clone(),
                            password: self.server_input_password.clone(),
                        });
                        self.server_status = "Logging in...".to_string();
                    }
                }
                Screen::ServerRegister => {
                    if let Some(tx) = &self.sync_cmd_tx {
                        let _ = tx.send(sync::SyncCommand::Register {
                            config: self.server_config.clone(),
                            login: self.server_input_login.clone(),
                            password: self.server_input_password.clone(),
                        });
                        self.server_status = "Registering...".to_string();
                    }
                }
                Screen::Dashboard | Screen::Handshake | Screen::Error | Screen::Generator | Screen::Profiles | Screen::Loading | Screen::Sync | Screen::ServerVersions | Screen::Esp32Setup | Screen::Esp32Auth => {}
            },
            _ => (),
        }
    }

    fn try_password(&mut self) -> Option<Vault> {
        if Path::new(&self.file_path).exists() {
            let bice = BiceFile::open(&self.file_path).ok()?;
            let file_profile = SecurityProfile::from_u8(bice.profile_id)?;
            self.current_profile = file_profile;
            self.salt = Some(bice.salt);
            let key = get_master_key(self.input.trim(), &bice.salt, file_profile).ok()?;

            if bice.requires_esp32() {
                self.esp32_pending_key = Some(key);
                self.esp32_pending_bice = Some(bice);
                self.esp32_operation = Esp32Operation::Decrypt;
                self.drop_input();
                self.input_mode = InputMode::Normal;
                self.start_esp32_auth();
                return None;
            }

            self.password_hash = Some(key);
            match bice.decrypt(key) {
                std::result::Result::Ok(decrypted_data) => {
                    let vault: Vault = postcard::from_bytes(&decrypted_data).ok()?;
                    Some(vault)
                }

                Err(_) => {
                    self.logs.push("[VAULT] | Wrong password".into());
                    None
                }
            }
        } else {
            self.salt = Some(generate_random_bytes(64).try_into().ok()?);
            if let Some(salt) = self.salt {
                let key = get_master_key(&self.input, &salt, self.current_profile).ok()?;

                if self.esp32_enabled {
                    self.esp32_pending_key = Some(key);
                    self.esp32_operation = Esp32Operation::NewDb;
                    self.drop_input();
                    self.input_mode = InputMode::Normal;
                    self.start_esp32_auth();
                    return None;
                }

                self.logs.push("[VAULT] | Created a new vault".to_owned());
                self.password_hash = Some(key);
                Some(Vault::new())
            } else {
                None
            }
        }
    }

    fn try_save(&mut self) -> bool {
        if let Some(ref vault) = self.vault {
            if let Some(ref password_hash) = self.password_hash {
                if let Some(ref salt) = self.salt {
                    let flags = if self.esp32_pubkey.is_some() { 1u8 } else { 0u8 };
                    let _ = models::Vault::save_to_disk(
                        vault,
                        &self.file_path,
                        password_hash,
                        self.current_profile,
                        *salt,
                        flags,
                        self.esp32_pubkey,
                    );
                    let _ = &self.logs.push("[SAVE] | Saving DB".to_owned());
                    return true;
                }
                false
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn new() -> Self {
        let file_path = "B1CE.bice".to_string();
        let current_profile = if Path::new(&file_path).exists() {
            if let Some(profile_id) = BiceFile::get_profile_id(&file_path) {
                SecurityProfile::from_u8(profile_id).unwrap_or(SecurityProfile::Standard)
            } else {
                SecurityProfile::Standard
            }
        } else {
            SecurityProfile::Standard
        };

        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (res_tx, res_rx) = std::sync::mpsc::channel();
        spawn_worker(cmd_rx, res_tx);

        let server_session = sync::load_session(&file_path);

        App {
            current_profile,
            input: ("").to_string(),
            cursor_position: (0),
            vault: (None),
            logs: (Vec::new()),
            list_state: (ListState::default()),
            table_state: (TableState::default().with_selected(Some(0))),
            current_screen: (Screen::Auth),
            should_quit: (false),
            input_mode: (InputMode::Normal),
            previous_screen: Screen::Auth,
            file_path,
            password_hash: None,
            salt: None,
            generator: PasswordGenerator {
                password: (None),
                params: [true, true, true, true],
                length: 12,
            },
            active_field: AddField::Login,
            draft: PasswordEntry { service: ("").to_string(), login: ("").to_string(), password: ("").to_string(), description: Some(("").to_string()) },
            server_config: ServerConfig::default(),
            server_session,
            server_input_login: String::new(),
            server_input_password: String::new(),
            server_status: "Ready".to_string(),
            server_active_field: ServerField::Login,
            sync_cmd_tx: Some(cmd_tx),
            sync_res_rx: Some(res_rx),
            server_versions: Vec::new(),
            versions_state: ratatui::widgets::ListState::default(),
            esp32_enabled: false,
            esp32_pubkey: None,
            esp32_status: String::new(),
            esp32_rx: None,
            esp32_pending_key: None,
            esp32_pending_bice: None,
            esp32_operation: Esp32Operation::None,
        }
    }

    fn start_esp32_auth(&mut self) {
        self.current_screen = Screen::Esp32Auth;
        self.esp32_status = "Searching for ESP32...".to_string();

        let salt = self.salt.unwrap_or([0u8; 64]);
        let challenge = esp32::derive_challenge(&salt);

        let (tx, rx) = std::sync::mpsc::channel();
        self.esp32_rx = Some(rx);

        std::thread::spawn(move || {
            let result = esp32::find_and_sign(&challenge);
            let _ = tx.send(result);
        });

        self.esp32_status = "Press button on ESP32...".to_string();
    }

    fn handle_esp32_response(&mut self, response: esp32::Esp32Response) {
        let factor = esp32::derive_factor(&response.signature);

        match self.esp32_operation {
            Esp32Operation::Decrypt => {
                if let Some(mut base_key) = self.esp32_pending_key.take() {
                    for i in 0..32 {
                        base_key[i] ^= factor[i];
                    }
                    let final_key = base_key;
                    self.password_hash = Some(final_key);
                    self.esp32_pubkey = Some(response.pubkey);

                    if let Some(bice) = self.esp32_pending_bice.take() {
                        self.salt = Some(bice.salt);
                        match bice.decrypt(final_key) {
                            std::result::Result::Ok(decrypted_data) => {
                                match postcard::from_bytes(&decrypted_data) {
                                    std::result::Result::Ok(vault) => {
                                        self.vault = Some(vault);
                                        self.current_screen = Screen::Dashboard;
                                    }
                                    Err(_) => {
                                        self.esp32_status = "Data corruption".to_string();
                                    }
                                }
                            }
                            Err(_) => {
                                self.esp32_status = "Wrong password or ESP32 mismatch".to_string();
                            }
                        }
                    }
                }
            }
            Esp32Operation::NewDb => {
                if let Some(mut base_key) = self.esp32_pending_key.take() {
                    for i in 0..32 {
                        base_key[i] ^= factor[i];
                    }
                    self.password_hash = Some(base_key);
                    self.esp32_pubkey = Some(response.pubkey);
                    self.esp32_enabled = true;
                    self.logs.push("[VAULT] | Created a new vault with ESP32".to_owned());
                    self.vault = Some(Vault::new());
                    self.current_screen = Screen::Dashboard;
                }
            }
            Esp32Operation::Attach => {
                if let Some(mut current_key) = self.password_hash {
                    for i in 0..32 {
                        current_key[i] ^= factor[i];
                    }
                    self.password_hash = Some(current_key);
                    self.esp32_pubkey = Some(response.pubkey);
                    self.esp32_enabled = true;
                    self.try_save();
                    self.esp32_status = "ESP32 attached successfully".to_string();
                    self.current_screen = Screen::Esp32Setup;
                }
            }
            Esp32Operation::Detach => {
                if let Some(mut current_key) = self.password_hash {
                    for i in 0..32 {
                        current_key[i] ^= factor[i];
                    }
                    self.password_hash = Some(current_key);
                    self.esp32_pubkey = None;
                    self.esp32_enabled = false;
                    self.try_save();
                    self.esp32_status = "ESP32 removed successfully".to_string();
                    self.current_screen = Screen::Esp32Setup;
                }
            }
            Esp32Operation::None => {}
        }
        self.esp32_operation = Esp32Operation::None;
    }
}

pub enum InputMode {
    Normal,
    Editing,
}

impl PartialEq for InputMode {
    fn eq(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

pub enum Screen {
    Auth,
    Dashboard,
    Handshake,
    Error,
    Generator,
    Add,
    Profiles,
    Loading,
    Sync,
    ServerLogin,
    ServerRegister,
    ServerSettings,
    ServerVersions,
    Esp32Setup,
    Esp32Auth,
}

impl Screen {
    fn footer_hints(&self) -> &str {
        match self {
            Screen::Auth => "[Enter] Login [p] Profiles [e] ESP32 [q] Quit",
            Screen::Dashboard => "[↑/↓] Select [Enter] Copy [g] Gen [n] New [s] Sync [e] ESP32 [q] Quit",
            Screen::Generator => "[Space] Regen [1-4] Params [+/-] Len [c] Copy [Backspace] Back",
            Screen::Add => "[Enter] Save [Esc] Cancel",
            Screen::Profiles => "[1-4] Select Profile [Backspace] Back",
            Screen::Sync => "[l] Login [r] Register [u] Push [d] Pull [c] Change Server [Backspace] Back",
            Screen::ServerLogin | Screen::ServerRegister => "[Enter] Submit [Tab] Next Field [Esc] Cancel",
            Screen::ServerSettings => "[Enter] Save [Esc] Cancel",
            Screen::Esp32Setup => "[a] Attach [r] Remove [Backspace] Back",
            Screen::Esp32Auth => "Waiting for ESP32...",
            _ => "[q] Quit [Backspace] Back",
        }
    }
}
