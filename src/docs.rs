//! Compiles every Rust block of the README and the site as a doctest
//! (part of `cargo test --all-features --doc`). Rustdoc compiles ```rust and ```rust,no_run blocks,
//! runs the former and skips ```text; a failure names the file and line.
//! `tests/docs_pages_listed.rs` fails when a page under `site/content/docs/`
//! is missing here.

#[doc = include_str!("../README.md")]
struct Readme;

macro_rules! page {
    ($name:ident, $path:literal) => {
        #[doc = include_str!(concat!("../site/content/docs/", $path))]
        struct $name;
    };
}

page!(Index, "_index.md");
page!(GettingStarted, "getting-started.md");
page!(Profiles, "profiles.md");
page!(As4, "as4.md");
page!(As2, "as2.md");
page!(Keys, "keys.md");
page!(Persistence, "persistence.md");
page!(Observability, "observability.md");
page!(Security, "security.md");
page!(Testing, "testing.md");
page!(Conformance, "conformance.md");
page!(Migration, "migration.md");
