//! Zero-install LLD linker setup.
//!
//! rustup ships LLVM's linkers inside every toolchain, next to the target's
//! std: `<sysroot>/lib/rustlib/<host>/bin/gcc-ld/` contains `ld.lld`
//! (ELF), `lld-link` (COFF/MSVC) and the Apple/WebAssembly variants. No
//! `mold`, no `lld` package, no `clang` needed.
//!
//! `epicenter setup --linker lld` wires that directory into Cargo:
//!
//! - GNU/ELF hosts keep the system C compiler as the linker *driver* and pass
//!   `-C link-arg=-fuse-ld=lld -C link-arg=-B<gcc-ld>` — a flag GCC and Clang
//!   both understand, with `-B` making the bundled `ld.lld` discoverable.
//! - MSVC hosts cannot use `-fuse-ld` (the driver is `link.exe`): rustc is
//!   pointed at the generic `rust-lld.exe` with `-C linker=…`. rustc detects
//!   that name and appends `-flavor link`; `gcc-ld/lld-link.exe` is already
//!   the COFF driver and rejects that flag.
//!
//! Apple's `ld64.lld` is not a drop-in for the system linker, so
//! `--linker lld` refuses macOS instead of producing fragile builds.

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

/// Which managed linker a plan describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkerKind {
    Lld,
    Wild,
    Mold,
    Gold,
}

/// One `[target.<triple>] rustflags` edit.
#[derive(Debug, Clone)]
pub struct TargetPlan {
    pub target: String,
    pub flags: Vec<String>,
    /// Exact `rustflags = [...]` literal written by this version.
    pub literal: String,
    /// Older literals that may be migrated/removed.
    pub legacy: Vec<String>,
}

/// A managed linker for the active rustup toolchain.
#[derive(Debug, Clone)]
pub struct FastLinker {
    pub kind: LinkerKind,
    /// Host triple the flags apply to (`x86_64-unknown-linux-gnu`).
    pub host: String,
    /// `…/lib/rustlib/<host>/bin/gcc-ld`.
    pub lld_dir: PathBuf,
    /// `ld.lld` / `rust-lld.exe` / `wild`, the binary the flags point at.
    pub linker: PathBuf,
    pub flavor: Flavor,
    /// Host target flags.
    pub flags: Vec<String>,
    /// Optional `wasm32-unknown-unknown` flags (Wild only, when installed).
    pub wasm: Option<Vec<String>>,
}

impl FastLinker {
    /// rustc flags for the host target.
    pub fn rustflags(&self) -> Vec<String> {
        self.flags.clone()
    }

    /// The host `rustflags = [...]` value, ready for the config line.
    pub fn rustflags_toml(&self) -> String {
        toml_array(&self.flags)
    }

    /// All target edits this plan owns: host, plus wasm for Wild.
    pub fn plans(&self) -> Vec<TargetPlan> {
        let mut plans = vec![TargetPlan {
            target: self.host.clone(),
            flags: self.flags.clone(),
            literal: toml_array(&self.flags),
            legacy: self.legacy_rustflags_toml(),
        }];
        if let Some(wasm) = &self.wasm {
            plans.push(TargetPlan {
                target: "wasm32-unknown-unknown".to_string(),
                flags: wasm.clone(),
                literal: toml_array(wasm),
                legacy: Vec::new(),
            });
        }
        plans
    }

    /// TOML literals written by older epicenter versions for this host.
    ///
    /// 0.0.7 pointed MSVC at `gcc-ld/lld-link.exe`. rustc recognizes the
    /// `lld-link` name and switches to the generic LLD protocol
    /// (`-flavor link`), which the COFF driver rejects. `--linker lld`
    /// migrates these values to `rust-lld.exe`; `--linker system` removes
    /// them.
    pub fn legacy_rustflags_toml(&self) -> Vec<String> {
        if self.kind != LinkerKind::Lld {
            return Vec::new();
        }
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
    let (host, sysroot) = rustc_host_and_sysroot()?;
    locate(&sysroot, &host)
}

/// Detect a standalone mold linker and a usable clang driver.
pub fn detect_mold() -> Result<FastLinker> {
    detect_external(LinkerKind::Mold, "mold", &["mold"])
}

/// Detect GNU gold and a usable clang driver.
pub fn detect_gold() -> Result<FastLinker> {
    detect_external(LinkerKind::Gold, "gold", &["ld.gold", "gold"])
}

fn detect_external(kind: LinkerKind, label: &str, names: &[&str]) -> Result<FastLinker> {
    let (host, sysroot) = rustc_host_and_sysroot()?;
    if !host.contains("linux") {
        bail!("--linker {label} supports Linux ELF only (host {host}); use lld or system");
    }
    let linker = names
        .iter()
        .find_map(|name| crate::util::which_path(name))
        .ok_or_else(|| {
            anyhow::anyhow!("`{label}` is not on PATH — install it or use --linker lld")
        })?;
    let clang = usable_clang().ok_or_else(|| {
        anyhow::anyhow!("{label} needs clang as the driver — install clang or use --linker lld")
    })?;
    let flags = vec![
        "-C".to_string(),
        "linker=clang".to_string(),
        "-C".to_string(),
        format!("link-arg=-fuse-ld={}", forward(&linker)),
    ];
    let lld_dir = sysroot
        .join("lib")
        .join("rustlib")
        .join(&host)
        .join("bin")
        .join("gcc-ld");
    let _ = clang;
    Ok(FastLinker {
        kind,
        host,
        lld_dir,
        linker,
        flavor: Flavor::Gnu,
        flags,
        wasm: None,
    })
}

/// Detect the standalone Wild linker and a usable C driver for it.
pub fn detect_wild() -> Result<FastLinker> {
    let (host, sysroot) = rustc_host_and_sysroot()?;
    detect_wild_at(&sysroot, &host)
}

fn rustc_host_and_sysroot() -> Result<(String, PathBuf)> {
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
    Ok((host, sysroot))
}

/// Wild needs a C driver that understands `wild`; no driver means a clear
/// refusal instead of a broken build.
fn detect_wild_at(sysroot: &Path, host: &str) -> Result<FastLinker> {
    if !host.contains("linux") {
        bail!("--linker wild supports Linux ELF and wasm32 only (host {host}); use lld or system");
    }
    let wild = crate::util::which_path("wild")
        .ok_or_else(|| anyhow::anyhow!("`wild` is not on PATH — install it or use --linker lld"))?;
    let cc = command_version("cc");
    let has_clang = usable_clang().is_some();
    let flags = if cc
        .as_deref()
        .is_some_and(|text| text.to_ascii_lowercase().contains("clang"))
    {
        // `cc` is already clang; keep it as the driver.
        vec!["-C".to_string(), "link-arg=--ld-path=wild".to_string()]
    } else if has_clang {
        // Wild's documented Rust integration: clang is the driver and
        // resolves wild through `--ld-path`.
        vec![
            "-C".to_string(),
            "linker=clang".to_string(),
            "-C".to_string(),
            "link-arg=--ld-path=wild".to_string(),
        ]
    } else if let Some((major, minor)) = cc.as_deref().and_then(parse_compiler_version) {
        if (major, minor) >= (16, 1) {
            vec!["-C".to_string(), "link-arg=-fuse-ld=wild".to_string()]
        } else {
            bail!(
                "wild found at {}, but no usable driver: cc is GCC {major}.{minor} (need >= 16.1) and clang is not usable",
                wild.display()
            );
        }
    } else {
        bail!(
            "wild found at {}, but no usable driver: install clang or GCC >= 16.1",
            wild.display()
        );
    };
    let wasm = sysroot
        .join("lib")
        .join("rustlib")
        .join("wasm32-unknown-unknown")
        .is_dir()
        .then(|| {
            vec![
                "-C".to_string(),
                format!("linker={}", forward(&wild)),
                "-C".to_string(),
                "linker-flavor=wasm-ld".to_string(),
            ]
        });
    let lld_dir = sysroot
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("gcc-ld");
    Ok(FastLinker {
        kind: LinkerKind::Wild,
        host: host.to_string(),
        lld_dir,
        linker: wild,
        flavor: Flavor::Gnu,
        flags,
        wasm,
    })
}

fn command_version(program: &str) -> Option<String> {
    let output = crate::util::command_for(program)
        .ok()?
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (!text.trim().is_empty()).then_some(text)
}

/// The kache `clang` shim exits non-zero when no real clang exists behind it.
fn usable_clang() -> Option<PathBuf> {
    let path = crate::util::tool_path("clang").ok()?;
    let output = std::process::Command::new(&path)
        .arg("--version")
        .output()
        .ok()?;
    // The kache shim prints an error and can still exit zero; a real clang
    // always announces itself on stdout.
    let version = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    // Real clang says "clang version ..." or "Apple clang version ..."; the
    // kache shim's error also contains the word clang, so be specific.
    (output.status.success() && version.contains("clang version")).then_some(path)
}

fn parse_compiler_version(text: &str) -> Option<(u32, u32)> {
    let first = text.lines().next()?;
    first.split_whitespace().rev().find_map(|token| {
        let token = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
        let mut parts = token.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
        Some((major, minor))
    })
}

/// Pure detection against a known sysroot/host (unit-testable).
pub fn locate(sysroot: &Path, host: &str) -> Result<FastLinker> {
    if host.contains("apple-darwin") {
        bail!(
            "--linker lld supports ELF and COFF hosts; lld is not a drop-in for Apple's ld64 — \
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
        bail!(
            "--linker lld is not supported on host {host} (supported: Linux/BSD ELF and Windows)"
        );
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
    let flags = match flavor {
        Flavor::Gnu => vec![
            "-C".to_string(),
            "link-arg=-fuse-ld=lld".to_string(),
            "-C".to_string(),
            format!("link-arg=-B{}", forward(&lld_dir)),
        ],
        Flavor::Msvc => vec!["-C".to_string(), format!("linker={}", forward(&linker))],
    };
    Ok(FastLinker {
        kind: LinkerKind::Lld,
        host: host.to_string(),
        lld_dir,
        linker,
        flavor,
        flags,
        wasm: None,
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
    #[test]
    fn parses_compiler_versions() {
        assert_eq!(
            parse_compiler_version("cc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0"),
            Some((11, 4))
        );
        assert_eq!(parse_compiler_version("gcc (GCC) 16.1.0"), Some((16, 1)));
        assert_eq!(parse_compiler_version("not a compiler"), None);
    }

    #[test]
    fn wild_plan_includes_the_wasm_target() {
        let linker = FastLinker {
            kind: LinkerKind::Wild,
            host: "x86_64-unknown-linux-gnu".to_string(),
            lld_dir: PathBuf::from("/sysroot/gcc-ld"),
            linker: PathBuf::from("/bin/wild"),
            flavor: Flavor::Gnu,
            flags: vec![
                "-C".to_string(),
                "linker=clang".to_string(),
                "-C".to_string(),
                "link-arg=--ld-path=wild".to_string(),
            ],
            wasm: Some(vec![
                "-C".to_string(),
                "linker=/bin/wild".to_string(),
                "-C".to_string(),
                "linker-flavor=wasm-ld".to_string(),
            ]),
        };
        let plans = linker.plans();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].target, "x86_64-unknown-linux-gnu");
        assert_eq!(plans[1].target, "wasm32-unknown-unknown");
        assert!(plans[1].literal.contains("wasm-ld"));
    }
}
