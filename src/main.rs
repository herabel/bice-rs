pub mod entropy;
mod encryption;
mod vault;
mod generator;
mod storage;
mod models;
pub mod cpu_entropy;
pub mod tui;
pub mod sync;
pub mod esp32;

fn main() {

    let mut app = tui::app::App::new();
    app.run(&mut ratatui::init()).unwrap();
    
}
