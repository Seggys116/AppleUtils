use std::io::{self, Read, stdout};
use std::sync::atomic::{AtomicI32, Ordering};
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
    if args.get(1).map(String::as_str) == Some("patch-restore") {
        match apple_utils::restore_patch_bundle::run(&args[2..]) {
            Ok(text) => {
                print!("{text}");
                return Ok(());
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
    if args.iter().any(|arg| arg == "--preview") {
        return preview::write_previews();
    }
    if args.get(1).map(String::as_str) == Some("preboot-ticket") {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        match apple_utils::preboot_ticket::sign_from_json(&input) {
            Ok(response) => {
                println!("{response}");
                return Ok(());
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
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

    let sign_recovery_os_local_policy = args
        .iter()
        .any(|arg| arg == apple_utils::restore::SIGNING_OPT_IN_FLAG);

    install_termination_handlers()?;
    let mut terminal = ratatui::init();
    execute!(stdout(), EnableBracketedPaste, EnableMouseCapture)?;
    let _guard = TerminalGuard;
    let result = run(&mut terminal, sign_recovery_os_local_policy);
    drop(_guard);
    // Die by the signal so the exit status is the conventional one.
    if let Some(signal) = termination_signal() {
        reraise_with_default(signal);
    }
    result
}

static TERMINATION: AtomicI32 = AtomicI32::new(0);

const TERMINATION_SIGNALS: [libc::c_int; 3] = [libc::SIGHUP, libc::SIGTERM, libc::SIGQUIT];

extern "C" fn on_termination(signal: libc::c_int) {
    // Only an atomic store: that is async-signal-safe.
    TERMINATION.store(signal, Ordering::SeqCst);
}

fn install_termination_handlers() -> io::Result<()> {
    for signal in TERMINATION_SIGNALS {
        // SAFETY: the sigaction struct is zero-initialised and then filled in; the handler is
        // an `extern "C"` function that only performs an atomic store.
        let status = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_termination as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn termination_signal() -> Option<libc::c_int> {
    match TERMINATION.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

fn reraise_with_default(signal: libc::c_int) {
    // SAFETY: restoring the default disposition and raising the signal have no preconditions.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

fn run(terminal: &mut DefaultTerminal, sign_recovery_os_local_policy: bool) -> io::Result<()> {
    let recovery = RecoveryRuntime::from_service(AppleRecoveryService::production());
    let mut app =
        App::with_banner_order_and_recovery(apple_utils::banner::BannerOrder::shuffled(), recovery);
    if sign_recovery_os_local_policy {
        app.recovery.set_local_policy_signing(true);
    }
    app.set_ipsw_cli(apple_utils::ipsw_tree::find_ipsw_cli());
    app.glyph_pack = apple_utils::ui::detect_pack();
    apple_utils::ui::set_pack(app.glyph_pack);
    loop {
        if termination_signal().is_some() {
            break;
        }
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
    // Dropping the app cancels a running IPSW export and waits for its ipsw child. SIGKILL and
    // hard crashes skip this; the next run's sweep reclaims the work folder.
    drop(app);
    Ok(())
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), DisableBracketedPaste, DisableMouseCapture);
        ratatui::restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_signals_set_the_flag_instead_of_killing_the_process() {
        install_termination_handlers().unwrap();
        assert_eq!(termination_signal(), None);
        for signal in TERMINATION_SIGNALS {
            // SAFETY: raise has no preconditions; the handler installed above only stores.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            assert_eq!(termination_signal(), Some(signal));
            TERMINATION.store(0, Ordering::SeqCst);
        }
    }
}
