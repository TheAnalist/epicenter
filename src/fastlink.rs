//! Zero-install fast linker.
//!
//! rustup ships LLVM's linkers inside every toolchain, next to the target's
//! std: `<sysroot>/lib/rustlib/<host>/bin/gcc-ld/` contains `ld.lld`
//! (ELF), `lld-link` (COFF/MSVC) and the Apple/WebAssembly variants. No
//! `mold`, no `lld` package, no `clang` needed.
//!
//! `epicenter setup --fast` wires that directory into Cargo:
//!
//! - GNU/ELF hosts keep the system C compiler as the linker *driver* and pass
//!   `-C link-arg=-fuse-ld=lld -C link-arg=-B<gcc-ld>` — a flag GCC and Clang
//!   both understand, with `-B` making the bundled `ld.lld` discoverable.
//! - MSVC hosts cannot use `-fuse-ld` (the driver is `link.exe`): rustc is
//!   pointed at the generic `rust-lld.exe` with `-C linker=…`. rustc detects
//!   that name and appends `-flavor link`; `gcc-ld/lld-link.exe` is already
//!   the COFF driver and rejects that flag.
//!
//! Apple's `ld64.lld` is not a drop-in for the system linker, so `--fast`
//! refuses macOS instead of producing fragile builds.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// How the bundled LLD is invoked on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// ELF/GNU-style: the C compiler drives `ld.lld` found via `-B`.
    Gnu,
    /// COFF/MSVC: rustc drives the generic `rust-lld.exe` with `-flavor link`.
    Msvc,
}

/// The bundled LLD for the active rustup toolchain.
#[derive(Debug, Clone)]
pub struct FastLinker {
    /// Host triple the flags apply to (`x86_64-unknown-linux-gnu`).
    pub host: String,
    /// `…/lib/rustlib/<host>/bin/gcc-ld`.
    pub lld_dir: PathBuf,
    /// `ld.lld` (ELF) or `rust-lld.exe` (COFF), the binary the flags point at.
    pub linker: PathBuf,
    pub flavor: Flavor,
}

impl FastLinker {
    /// rustc flags for `[target.<host>] rustflags`.
    pub fn rustflags(&self) -> Vec<String> {
        match self.flavor {
            Flavor::Gnu => vec![
                "-C".to_string(),
                "link-arg=-fuse-ld=lld".to_string(),
                "-C".to_string(),
                format!("link-arg=-B{}", forward(&self.lld_dir)),
            ],
            Flavor::Msvc => vec![
                "-C".to_string(),
                format!("linker={}", forward(&self.linker)),
            ],
        }
    }

    /// The `rustflags = [...]` value, ready for the config line.
    pub fn rustflags_toml(&self) -> String {
        toml_array(&self.rustflags())
    }

    /// TOML literals written by older epicenter versions for this host.
    ///
    /// 0.0.7 pointed MSVC at `gcc-ld/lld-link.exe`. rustc recognizes the
    /// `lld-link` name and switches to the generic LLD protocol
    /// (`-flavor link`), which the COFF driver rejects. `--fast` migrates
    /// these values to `rust-lld.exe`; `--without-fast` removes them.
    pub fn legacy_rustflags_toml(&self) -> Vec<String> {
        match self.flavor {
            Flavor::Msvc => {
                let old = self.lld_dir.join("lld-link.exe");
                vec![toml_array(&[
                    "-C".to_string(),
                    format!("linker={}", forward(&old)),
                ])]
            }
            Flavor::Gnu => Vec::new(),
        }
    }
}

/// TOML paths use forward slashes on every platform.
fn forward(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn toml_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('"');
        for ch in item.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// Detect the bundled LLD for the active toolchain's host.
pub fn detect() -> Result<FastLinker> {
    let mut rustc = crate::util::command_for("rustc")?;
    let output = rustc
        .arg("-vV")
        .output()
        .context("running `rustc -vV` to find the host triple")?;
    if !output.status.success() {
        bail!("`rustc -vV` failed — is a toolchain installed?");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let host = text
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow::anyhow!("`rustc -vV` did not report a host triple"))?
        .to_string();

    let mut rustc = crate::util::command_for("rustc")?;
    let output = rustc
        .args(["--print", "sysroot"])
        .output()
        .context("running `rustc --print sysroot`")?;
    if !output.status.success() {
        bail!("`rustc --print sysroot` failed — is a toolchain installed?");
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    locate(&sysroot, &host)
}

/// Pure detection against a known sysroot/host (unit-testable).
pub fn locate(sysroot: &Path, host: &str) -> Result<FastLinker> {
    if host.contains("apple-darwin") {
        bail!(
            "--fast supports ELF and COFF hosts; lld is not a drop-in for Apple's ld64 — \
             leave the default Apple linker in place"
        );
    }
    let bin_dir = sysroot.join("lib").join("rustlib").join(host).join("bin");
    let lld_dir = bin_dir.join("gcc-ld");
    let (flavor, search_dir, names): (Flavor, &Path, &[&str]) = if host.contains("windows-msvc") {
        // rustc matches these exact names and adds `-flavor link`; only the
        // generic multi-call driver understands it. `gcc-ld/lld-link.exe`
        // is already the COFF driver and rejects the flag.
        (Flavor::Msvc, &bin_dir, &["rust-lld.exe", "rust-lld"])
    } else if host.contains("windows-gnu")
        || host.contains("linux")
        || host.contains("freebsd")
        || host.contains("netbsd")
        || host.contains("openbsd")
        || host.contains("dragonfly")
        || host.contains("solaris")
        || host.contains("illumos")
    {
        (Flavor::Gnu, &lld_dir, &["ld.lld", "ld.lld.exe"])
    } else {
        bail!("--fast is not supported on host {host} (supported: Linux/BSD ELF and Windows)");
    };
    let linker = names
        .iter()
        .map(|name| search_dir.join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rustup's bundled LLD was not found in {} — is the `{host}` target installed?",
                search_dir.display()
            )
        })?;
    Ok(FastLinker {
        host: host.to_string(),
        lld_dir,
        linker,
        flavor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path, host: &str, names: &[&str]) -> PathBuf {
        let dir = root
            .join("lib")
            .join("rustlib")
            .join(host)
            .join("bin")
            .join("gcc-ld");
        std::fs::create_dir_all(&dir).expect("create fixture");
        for name in names {
            std::fs::write(dir.join(name), b"").expect("write fixture");
        }
        dir
    }

    /// Create files directly in `<sysroot>/lib/rustlib/<host>/bin`.
    fn fixture_bin(root: &Path, host: &str, names: &[&str]) {
        let dir = root.join("lib").join("rustlib").join(host).join("bin");
        std::fs::create_dir_all(&dir).expect("create fixture");
        for name in names {
            std::fs::write(dir.join(name), b"").expect("write fixture");
        }
    }

    #[test]
    fn gnu_hosts_use_fuse_ld_with_the_bundled_dir() {
        let root = tempfile::tempdir().unwrap();
        let dir = fixture(root.path(), "x86_64-unknown-linux-gnu", &["ld.lld"]);
        let lld = locate(root.path(), "x86_64-unknown-linux-gnu").unwrap();
        assert_eq!(lld.flavor, Flavor::Gnu);
        assert_eq!(lld.lld_dir, dir);
        let flags = lld.rustflags();
        assert_eq!(flags.len(), 4);
        assert_eq!(flags[0], "-C");
        assert_eq!(flags[1], "link-arg=-fuse-ld=lld");
        assert_eq!(flags[2], "-C");
        assert_eq!(flags[3], format!("link-arg=-B{}", dir.display()));
        assert!(lld.rustflags_toml().starts_with('['));
    }

    #[test]
    fn msvc_hosts_link_with_the_generic_rust_lld() {
        let root = tempfile::tempdir().unwrap();
        fixture_bin(root.path(), "x86_64-pc-windows-msvc", &["rust-lld.exe"]);
        let lld = locate(root.path(), "x86_64-pc-windows-msvc").unwrap();
        assert_eq!(lld.flavor, Flavor::Msvc);
        let flags = lld.rustflags();
        assert_eq!(flags[0], "-C");
        assert!(flags[1].starts_with("linker="));
        assert!(flags[1].ends_with("/bin/rust-lld.exe"), "{}", flags[1]);
        assert!(flags[1].contains("x86_64-pc-windows-msvc"));
        assert!(!flags[1].contains('\\'), "paths are forward-slash");

        // rustc passes `-flavor link` for the `lld-link` name; the COFF
        // driver rejects it. Prefer the generic driver even when both exist.
        fixture(root.path(), "x86_64-pc-windows-msvc", &["lld-link.exe"]);
        let lld = locate(root.path(), "x86_64-pc-windows-msvc").unwrap();
        assert!(lld.linker.ends_with("rust-lld.exe"));
    }

    #[test]
    fn msvc_exposes_the_old_lld_link_literal_for_migration() {
        let root = tempfile::tempdir().unwrap();
        fixture_bin(root.path(), "x86_64-pc-windows-msvc", &["rust-lld.exe"]);
        let lld = locate(root.path(), "x86_64-pc-windows-msvc").unwrap();
        let legacy = lld.legacy_rustflags_toml();
        assert_eq!(legacy.len(), 1);
        assert!(legacy[0].contains("gcc-ld/lld-link.exe"), "{}", legacy[0]);
        assert!(lld.rustflags_toml().contains("/bin/rust-lld.exe"));
    }

    #[test]
    fn windows_gnu_uses_the_gcc_driver() {
        let root = tempfile::tempdir().unwrap();
        fixture(root.path(), "x86_64-pc-windows-gnu", &["ld.lld.exe"]);
        let lld = locate(root.path(), "x86_64-pc-windows-gnu").unwrap();
        assert_eq!(lld.flavor, Flavor::Gnu);
        assert!(lld.rustflags()[1].contains("fuse-ld=lld"));
    }

    #[test]
    fn apple_and_missing_lld_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let err = locate(root.path(), "aarch64-apple-darwin").unwrap_err();
        assert!(err.to_string().contains("ld64"), "{err}");
        let err = locate(root.path(), "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(err.to_string().contains("bundled LLD"), "{err}");
    }
}
