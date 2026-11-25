//! `epicenter` — the state layer for Cargo builds (binary entry point).

mod cli;

use epicenter_cli::util;

fn main() {
    // Mitigate Broken pipe with number `head`/`less` piping of the binary:
    // print cleanly, exit code 141 (128+13, the SIGPIPE convention), never a
    // backtrace wall.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Broken pipe") {
            std::process::exit(141);
        }
        default_hook(info);
    }));

    if let Err(err) = cli::run() {
        eprintln!("{}", util::error_block(&err));
        std::process::exit(1);
    }
}
