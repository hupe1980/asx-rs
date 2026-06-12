// ASX build script.
//
// Exposes `cargo_release_profile` as a cfg flag when the active Cargo profile
// is `release`.  This allows `compile_error!` guards in `lib.rs` to reject
// dangerous feature combinations (e.g. `testing` in a release build) based on
// the actual profile name rather than the `debug_assertions` heuristic, which
// can be overridden by embedders via `[profile.release] debug-assertions = true`.
//
// Usage in lib.rs:
//   #[cfg(all(feature = "testing", cargo_release_profile))]
//   compile_error!("...");

fn main() {
    // Declare the custom cfg to silence `unexpected_cfgs` lint (Rust 1.80+).
    println!("cargo:rustc-check-cfg=cfg(cargo_release_profile)");

    // `PROFILE` is set by Cargo to the name of the active profile:
    // "debug", "release", or any custom profile name.
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    if profile == "release" {
        // Expose a stable cfg flag for release-profile detection.
        println!("cargo:rustc-cfg=cargo_release_profile");
    }
    // Re-run build.rs whenever the active profile changes.
    println!("cargo:rerun-if-env-changed=PROFILE");
}
