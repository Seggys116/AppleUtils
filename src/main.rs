use std::io::{self, stdout};
use std::time::Duration;

use apple_utils::app::App;
use apple_utils::preview;
use apple_utils::recovery_runtime::RecoveryRuntime;
use apple_utils::restore_service::AppleRecoveryService;
use apple_utils::ui;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event,
};
use ratatui::crossterm::execute;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--preview") {
        return preview::write_previews();
    }
    if args.get(1).map(String::as_str) == Some("asahi") {
        match apple_utils::asahi_cli::run(&args[2..]) {
            Ok(text) => {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
    if args.get(1).map(String::as_str) == Some("explorer") {
        match apple_utils::explorer_cli::run(&args[2..]) {
            Ok(text) => {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }
    if args.get(1).map(String::as_str) == Some("repair") {
        match apple_utils::repair_cli::run(&args[2..]) {
            Ok(text) => {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    let mut terminal = ratatui::init();
    execute!(stdout(), EnableBracketedPaste, EnableMouseCapture)?;
    let _guard = TerminalGuard;
    let result = run(&mut terminal);
    drop(_guard);
    result
}

fn run(terminal: &mut DefaultTerminal) -> io::Result<()> {
    let recovery = RecoveryRuntime::from_service(AppleRecoveryService::production());
    let mut app =
        App::with_banner_order_and_recovery(apple_utils::banner::BannerOrder::shuffled(), recovery);
    app.glyph_pack = apple_utils::ui::detect_pack();
    apple_utils::ui::set_pack(app.glyph_pack);
    loop {
        app.prepare();
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        if event::poll(Duration::from_millis(16))? {
            match event::read()? {
                Event::Resize(_, _) => {}
                other => {
                    if app.handle_event(other) {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), DisableBracketedPaste, DisableMouseCapture);
        ratatui::restore();
    }
}
