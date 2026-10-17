//! `cargo run -p xtask -- example-pki [DIR]`: writes the PKI files the
//! golden-path examples read (default `examples/pki`).

mod example_pki;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("example-pki") => example_pki::run(&args[1..]),
        _ => Err("usage: cargo run -p xtask -- example-pki [DIR]".to_string()),
    };
    if let Err(err) = result {
        eprintln!("xtask failed: {err}");
        std::process::exit(2);
    }
}
