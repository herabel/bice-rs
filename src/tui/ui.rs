use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::*,
    widgets::*,
};

use crate::{
    generator::generate_password,
    tui::app::{AddField, App},
};

#[derive(Debug)]
/// A structure for password generator
pub struct PasswordGenerator {
    /// Contains password itself
    pub password: Option<String>,
    /// Contains params of password (uppercase, digits, specials, ascii)
    pub params: [bool; 4],
    /// Contains password length
    pub length: usize,
}

impl PasswordGenerator {
    /// Generates password using given parameters
    pub fn generate_password(&mut self) {
        self.password = Some(generate_password(
            self.length,
            self.params[0],
            self.params[1],
            self.params[2],
            self.params[3],
        ));
    }
}

/// Renders the auth page ([`Screen::Auth`][crate::tui::app::Screen::Auth]) inside the provided `Rect`.
pub fn render_auth(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let vault_status: bool = app.vault.is_some();
    let esp32_label = if app.esp32_enabled { "ON" } else { "OFF" };
    let info_text = format!(
        "Mode: {:?}\nInput: [   {}   ]\n\nVault: [{}]\nESP32 2FA: [{}]",
        app.input_mode,
        app.input.clone(),
        vault_status,
        esp32_label
    );
    let block = Block::default()
        .title(" Auth ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}

/// Renders the generator page ([`Screen::Generator`][crate::tui::app::Screen::Generator]) inside the provided `Rect`.
pub fn render_generator(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let generator = &app.generator;
    let info_text: String;
    if let Some(password) = &generator.password {
        info_text = format!(
            "Mode: {:?}\nPassword: [ {} ]\nLength: {}\nParams: [1] Uppercase: {}, [2] Digits: {}, [3] Specials: {}, [4] ASCII: {}",
            app.input_mode,
            password,
            generator.length,
            generator.params[0], // uppercase
            generator.params[1], // digits
            generator.params[2], // specials
            generator.params[3], // ascii (extended)
        );
    } else {
        info_text = format!(
            "Mode: {:?}\nPassword: [ {} ]\nLength: {}\nParams: [1] Uppercase: {}, [2] Digits: {}, [3] Specials: {}, [4] ASCII: {}",
            app.input_mode,
            "...",
            generator.length,
            generator.params[0], // uppercase
            generator.params[1], // digits
            generator.params[2], // specials
            generator.params[3], // ascii (extended)
        );
    }

    let block = Block::default()
        .title(" Generator ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}

/// Renders the dashboard page ([`Screen::Dashboard`][crate::tui::app::Screen::Dashboard]) inside the provided `Rect`.
pub fn render_dashboard(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Fill(1)])
        .split(rect);

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(40),
    ];

    if let Some(vault) = &app.vault {
        let table = Table::new(
            vault.entries.iter().map(|entry| {
                Row::new(vec![
                    Cell::from(entry.service.as_str()),
                    Cell::from(entry.login.as_str()),
                    Cell::from("******"),
                    Cell::from(entry.description.as_deref().unwrap_or("...")),
                ])
                .style(Style::default().fg(Color::Rgb(126, 162, 170))) 
            }),
            widths,
        )
        .header(
            Row::new(vec!["Service", "Login", "Password", "Note"])
                .style(
                    Style::default()
                        .fg(Color::Rgb(139, 232, 203)) 
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(" Vault Entries ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(126, 162, 170)))
                .bg(Color::Rgb(32, 40, 37)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(156, 122, 151)) 
                .fg(Color::Rgb(48, 54, 51))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

        let mut table_state = app.table_state;
        frame.render_stateful_widget(table, chunks[1], &mut table_state);
    }

    let info_text = format!("Mode: {:?}", app.input_mode);
    let block = Block::default()
        .title(" Dashboard ")
        .borders(Borders::TOP | Borders::RIGHT | Borders::LEFT)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));

    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, chunks[0]);
}

/// Renders the password add page ([`Screen::Add`][crate::tui::app::Screen::Add]) inside the provided `Rect`.
pub fn render_add(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let center_y = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(14),
            Constraint::Fill(1),
        ])
        .split(rect);

    let center_x = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(50),
            Constraint::Fill(1),
        ])
        .split(center_y[1]);

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(5),
        ])
        .split(center_x[1]);

    let active_style = Style::default()
        .fg(Color::Rgb(139, 232, 203))
        .add_modifier(Modifier::BOLD);

    let inactive_style = Style::default()
        .fg(Color::Rgb(126, 162, 170));

    let bg_color = Color::Rgb(48, 54, 51);

    let service_style = if app.active_field == AddField::Service { active_style } else { inactive_style };
    let service = Paragraph::new(app.draft.service.as_str())
        .style(service_style)
        .block(
            Block::default()
                .title(" Service ")
                .borders(Borders::ALL)
                .border_style(service_style)
                .bg(bg_color),
        );

    let login_style = if app.active_field == AddField::Login { active_style } else { inactive_style };
    let login = Paragraph::new(app.draft.login.as_str())
        .style(login_style)
        .block(
            Block::default()
                .title(" Login ")
                .borders(Borders::ALL)
                .border_style(login_style)
                .bg(bg_color),
        );

    let password_style = if app.active_field == AddField::Password { active_style } else { inactive_style };
    let password = Paragraph::new("*".repeat(app.draft.password.len()))
        .style(password_style)
        .block(
            Block::default()
                .title(" Password ")
                .borders(Borders::ALL)
                .border_style(password_style)
                .bg(bg_color),
        );

        let note_style = if app.active_field == AddField::Note { active_style } else { inactive_style };
    let note = Paragraph::new(app.draft.description.as_deref().unwrap_or(""))
        .style(note_style)
        .block(
            Block::default()
                .title(" Note ")
                .borders(Borders::ALL)
                .border_style(note_style)
                .bg(bg_color),
        );

    frame.render_widget(Block::default().bg(bg_color), rect);
    frame.render_widget(service, chunks[0]);
    frame.render_widget(login, chunks[1]);
    frame.render_widget(password, chunks[2]);
    frame.render_widget(note, chunks[3]);
}

/// Renders the encryption profiles page ([`Screen::Profiles`][crate::tui::app::Screen::Profiles]) inside the provided `Rect`.
pub fn render_profiles(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let info_text = format!(
        "Select Encryption Profile:\n\n\
        [1] Fast\n\
        [2] Standard\n\
        [3] Paranoid\n\
        [4] Extreme\n\n\
        Current: {:?}",
        app.current_profile
    );

    let block = Block::default()
        .title(" Security Profiles ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}

/// Renders the server sync page ([`Screen::Sync`][crate::tui::app::Screen::Sync]) inside the provided `Rect`.
pub fn render_sync(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let session_status = if let Some(session) = &app.server_session {
        format!("Logged in as: {}", session.user_id)
    } else {
        "Not logged in".to_string()
    };

    let info_text = format!(
        "Server Sync\n\nServer URL: {}\nSession: {}\n\nStatus: {}",
        app.server_config.url,
        session_status,
        app.server_status
    );

    let block = Block::default()
        .title(" Sync ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}

/// Renders the server auth page ([`Screen::ServerLogin`][crate::tui::app::Screen::ServerLogin]) inside the provided `Rect`.
pub fn render_server_auth(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let center_y = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Fill(1),
        ])
        .split(rect);

    let center_x = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(50),
            Constraint::Fill(1),
        ])
        .split(center_y[1]);

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(center_x[1]);

    let active_style = Style::default()
        .fg(Color::Rgb(139, 232, 203))
        .add_modifier(Modifier::BOLD);

    let inactive_style = Style::default()
        .fg(Color::Rgb(126, 162, 170));

    let bg_color = Color::Rgb(48, 54, 51);

    use crate::tui::app::ServerField;

    let login_style = if app.server_active_field == ServerField::Login { active_style } else { inactive_style };
    let login = Paragraph::new(app.server_input_login.as_str())
        .style(login_style)
        .block(
            Block::default()
                .title(" Login ")
                .borders(Borders::ALL)
                .border_style(login_style)
                .bg(bg_color),
        );

    let password_style = if app.server_active_field == ServerField::Password { active_style } else { inactive_style };
    let password = Paragraph::new("*".repeat(app.server_input_password.len()))
        .style(password_style)
        .block(
            Block::default()
                .title(" Password ")
                .borders(Borders::ALL)
                .border_style(password_style)
                .bg(bg_color),
        );

    let status_style = Style::default().fg(Color::Rgb(156, 122, 151));
    let status = Paragraph::new(app.server_status.as_str())
        .style(status_style)
        .centered();

    frame.render_widget(Block::default().bg(bg_color), rect);
    frame.render_widget(login, chunks[0]);
    frame.render_widget(password, chunks[1]);
    frame.render_widget(status, chunks[2]);
}
/// Renders the server settings page ([`Screen::ServerSettings`][crate::tui::app::Screen::ServerSettings]) inside the provided `Rect`.
pub fn render_server_settings(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let center_y = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Fill(1),
        ])
        .split(rect);

    let center_x = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(50),
            Constraint::Fill(1),
        ])
        .split(center_y[1]);

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(center_x[1]);

    let active_style = Style::default()
        .fg(Color::Rgb(139, 232, 203))
        .add_modifier(Modifier::BOLD);

    let bg_color = Color::Rgb(48, 54, 51);

    let url_block = Paragraph::new(app.server_config.url.as_str())
        .style(active_style)
        .block(
            Block::default()
                .title(" Server URL ")
                .borders(Borders::ALL)
                .border_style(active_style)
                .bg(bg_color),
        );

    let status_style = Style::default().fg(Color::Rgb(156, 122, 151));
    let status = Paragraph::new(app.server_status.as_str())
        .style(status_style)
        .centered();

    frame.render_widget(Block::default().bg(bg_color), rect);
    frame.render_widget(url_block, chunks[0]);
    frame.render_widget(status, chunks[1]);
}

/// Renders the version selection page ([`Screen::Esp32Auth`][crate::tui::app::Screen::Esp32Auth]) inside the provided `Rect`.
pub fn render_server_versions(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let center_y = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(60),
            Constraint::Percentage(20),
        ])
        .split(rect);

    let center_x = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Percentage(60),
            Constraint::Fill(1),
        ])
        .split(center_y[1]);

    let bg_color = Color::Rgb(48, 54, 51);
    let active_style = Style::default()
        .fg(Color::Rgb(139, 232, 203))
        .add_modifier(Modifier::BOLD);

    let block = Block::default()
        .title(" Select Version to Pull ")
        .borders(Borders::ALL)
        .border_style(active_style)
        .bg(bg_color);

    let items: Vec<ratatui::widgets::ListItem<'_>> = app
        .server_versions
        .iter()
        .map(|v| ratatui::widgets::ListItem::new(format!("Version: {}", v)))
        .collect();

    let list = ratatui::widgets::List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(139, 232, 203))
                .fg(bg_color)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    frame.render_widget(Block::default().bg(bg_color), rect);
    
    let mut state = app.versions_state;
    frame.render_stateful_widget(list, center_x[1], &mut state);
}

/// Renders the esp32 setup page ([`Screen::Esp32Setup`][crate::tui::app::Screen::Esp32Setup]) inside the provided `Rect`.
pub fn render_esp32_setup(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let pubkey_text = if let Some(ref pk) = app.esp32_pubkey {
        format!("Public Key: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
            pk[0], pk[1], pk[2], pk[3], pk[28], pk[29], pk[30], pk[31])
    } else {
        "No ESP32 attached".to_string()
    };

    let info_text = format!(
        "ESP32 Hardware 2FA\n\n{}\n\nStatus: {}",
        pubkey_text,
        app.esp32_status
    );

    let block = Block::default()
        .title(" ESP32 Setup ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(139, 232, 203)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(134, 168, 142))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}

/// Renders the esp32 auth page inside provided `Rect`.
pub fn render_esp32_auth(frame: &mut Frame<'_>, rect: Rect, app: &App) {
    let info_text = format!(
        "ESP32 Authentication\n\n{}\n\n[Backspace] Cancel",
        app.esp32_status
    );

    let block = Block::default()
        .title(" ESP32 2FA ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(156, 122, 151)))
        .bg(Color::Rgb(48, 54, 51));
    let placeholder = Paragraph::new(info_text)
        .fg(Color::Rgb(139, 232, 203))
        .block(block)
        .centered();

    frame.render_widget(placeholder, rect);
}