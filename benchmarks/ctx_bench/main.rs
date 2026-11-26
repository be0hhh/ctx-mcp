//! Standalone benchmark binary for `ctx` (`ctx-bench`):
//!   - `ctx-bench waves [--ctx-bin PATH] [--agents 1,10,50,100,200] [--ops 25] [--extended] [--json]`
//!   - `ctx-bench micro [--iters 200] [--json]`

mod micro;
mod waves;

fn print_usage() {
    eprintln!(
        "Usage: ctx-bench <mode> [args]\n\
         Modes:\n\
         \x20 ctx-bench waves [--ctx-bin PATH] [--agents 1,10,50,100,200] [--ops 20] [--extended] [--json]\n\
         \x20 ctx-bench micro [--iters 200] [--json]"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("-h" | "--help" | "help") => {
            print_usage();
            0
        }
        Some("waves") => waves::run_waves_cli(&args[1..]),
        Some("micro") => micro::run_micro_cli(&args[1..]),
        Some(flag) if flag.starts_with('-') => waves::run_waves_cli(&args),
        None => waves::run_waves_cli(&[]),
        Some(other) => {
            eprintln!("ctx-bench: unknown mode `{other}`");
            print_usage();
            2
        }
    };
    std::process::exit(code);
}
