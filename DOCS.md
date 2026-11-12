<h1 align="center">
    <img width="99" alt="epicenter logo" src="epicenter-icon.svg">
    <br>
    <b>epicenter</b>
    <br>
    <sub>
        <sup>The state layer for cargo builds</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/epicenter-cli"><img src="https://img.shields.io/crates/v/epicenter-cli.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/epicenter-cli"><img alt="downloads" src="https://img.shields.io/crates/d/epicenter-cli?color=%230099ff"></a>
    <a href="https://docs.rs/epicenter-cli"><img src="https://docs.rs/epicenter-cli/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/TheAnalist/epicenter/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/crates/l/epicenter-cli.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.91%2B-blue"></a>
</p>

<p align="center">
    <b>Three-Tier Build State &amp; Shared Dependency Cache for Rust</b>
    <br>
    <i>Shared build cache + durable fingerprint vault + lock-free per-job work dirs + explicit linker choices + honest eviction + zero rustc shims.</i>
</p>

<br>

**Epicenter** is the state layer for Cargo builds. It solves Rust's two biggest headaches—slow compile times and bloated `target/` directories—by sharing compiled dependencies across all your projects without wrapping `rustc` or running a background daemon.

* **Requirement:** Rust **1.91+** (Cargo with `build.build-dir` support).
* **How it works:** Epicenter uses Cargo's native `[build] build-dir` configuration and fingerprint engine. When a unit is restored from Epicenter, Cargo sees it as `Fresh` in milliseconds and spawns **zero `rustc` processes**.

---

## 1. Core Concepts: Three Tiers, One Tool

Epicenter organizes build state into three simple tiers:

1. **`build` (Shared Warm Cache)** — `{cargo-cache-home}/epicenter/build/`
   Where your normal projects compile by default. Compile `serde` or `tokio` once in Project A, and Project B reuses it immediately.
2. **`store` (The Durable Vault)** — `{cargo-cache-home}/epicenter/store/`
   A read-only, content-addressed snapshot of compiled units keyed by toolchain and compiler flags. It survives `cargo clean`, branch switches, and feeds cold starts.
3. **`work` (Disposable Per-Job Directories)** — per-user OS cache, e.g. `$XDG_CACHE_HOME/epicenter/work/<id>/` (overridable with `--work-root`)
   Isolated build directories created by `epicenter exec` and seeded from the `store` vault in milliseconds. Allows 10+ AI agents or CI jobs to compile the same repo in parallel with **zero Cargo lock contention**.

---

## 2. Installation & 30-Second Quickstart

```bash
# 1. Install
cargo install epicenter-cli

# 2. Configure Cargo to use the shared build cache (backs up existing config automatically)
epicenter setup

# 3. Build any Rust project as usual
cargo build

# 4. Check cache status and health
epicenter status
epicenter doctor
```

> **Safety first:** Every time `epicenter setup` edits a file, it saves a backup (`config.toml.epicenter-bak[.N]`). Run `epicenter setup --revert` at any time to restore your previous configuration atomically.

---

## 3. Practical Recipes ("I want to...")

Straight-to-the-point commands for humans and AI agents:

### Local Compilation & Linker Choices
* **You want plug-and-play shared builds with the bundled LLVM linker (`lld`, no extra install needed):**
  ```bash
  epicenter setup --preset dev --linker lld
  ```
* **You want to compile fast and you have installed `wild` (plus `clang` or GCC 16.1+) for fast linking on Linux:**
  ```bash
  epicenter setup --preset dev --linker wild
  ```
* **You are on Linux and have `mold` or `gold` (plus `clang`) installed:**
  ```bash
  epicenter setup --preset dev --linker mold
  # or
  epicenter setup --preset dev --linker gold
  ```
* **You want to revert to your OS default linker:**
  ```bash
  epicenter setup --linker system
  ```

### Memory & Profile Tuning
* **You want to limit parallel Cargo jobs so `rustc` never exceeds 16 GiB of RAM (2 GiB per job cap):**
  ```bash
  epicenter setup --memory 16GiB
  ```
* **You want Epicenter to write recommended profile settings into your workspace `Cargo.toml` (with line-tables debug info):**
  ```bash
  epicenter setup --preset dev --write-profile --dev-debug line
  ```
* **You want to preview what `setup` will change without touching any files:**
  ```bash
  epicenter setup --preset dev --linker lld --memory 16GiB --dry-run
  ```
* **You want to apply setup and run one calibration build to record time and peak RSS for `epicenter doctor`:**
  ```bash
  epicenter setup --preset dev --measure
  ```

### Surviving `cargo clean` (The Vault)
* **You want to save your compiled dependencies before running `cargo clean` and get them back instantly:**
  ```bash
  epicenter store harvest   # Snapshot compiled units into the vault
  cargo clean               # Wipe the build view
  epicenter store restore   # Link/copy units back from the vault in milliseconds
  cargo build               # Instant "Fresh" build, zero rustc processes spawned
  ```

### Running AI Agents & Parallel Jobs (Zero Lock Waits)
* **You are running multiple AI coding agents on the same repository simultaneously:**
  ```bash
  # Agent 1 gets its own isolated build dir and target dir, seeded from the vault:
  epicenter exec --id agent-1 --target-dir -- cargo test

  # Agent 2 runs at the exact same time without waiting on Cargo's build-dir lock:
  epicenter exec --id agent-2 --target-dir -- cargo check
  ```
* **An agent wants to keep reusing its own warm workspace across multiple commands:**
  ```bash
  epicenter exec --id agent-1 --target-dir -- cargo build
  epicenter exec --id agent-1 --reuse --target-dir -- cargo test
  ```
* **You want a one-shot isolated test run that deletes its working directory when done:**
  ```bash
  epicenter exec --rm --id quick-check -- cargo test
  ```
* **You are running a CI job that should seed from the vault, build, and save any newly compiled dependencies back to the vault:**
  ```bash
  epicenter exec --harvest -- cargo test
  ```

### Custom Cache Location & External Wrappers
* **You want to put the shared build cache on a fast or larger secondary drive:**
  ```bash
  epicenter setup --cache-root /mnt/fast-nvme/rust-cache
  ```
* **You want to reset the cache path back to the default:**
  ```bash
  epicenter setup --use-default
  ```
* **You also use `kache` or `sccache` for cross-machine `rustc` wrapper caching:**
  ```bash
  epicenter setup --wrapper kache
  # or
  epicenter setup --wrapper sccache
  ```

---

## 4. Detailed Workflows

### Workflow 1: Daily Local Development (Set and Forget)

Run once on your machine:

```bash
epicenter setup --preset dev --linker lld
```

What happens under the hood:
1. Epicenter writes `[build] build-dir = '{cargo-cache-home}/epicenter/build'` to `~/.cargo/config.toml`.
2. It configures `incremental = true` (unless a `rustc-wrapper` is active) and sets `build.jobs` based on your RAM (`min(cores, floor(RAM / 2 GiB))`).
3. It configures Rust's bundled `lld` linker for your host target.
4. From now on, every `cargo build`, `cargo check`, or `cargo test` in any directory automatically shares compiled dependencies.

### Workflow 2: Using the Vault (`store harvest` & `store restore`)

The shared `build/` directory is fast while warm, but `cargo clean` wipes it. The **Vault** (`store/`) makes your compiled dependencies permanent.

```bash
# 1. After building your project(s), save the compiled units into the vault
epicenter store harvest

# 2. Inspect what generations (toolchain + flags) are stored in the vault
epicenter store vault

# 3. Verify vault integrity (file sizes, timestamps, hashes, dependency ordering)
epicenter store verify

# 4. Anytime after a cargo clean or on a fresh directory, restore units
epicenter store restore
```

* **Performance & Reflinks:** `harvest` and `restore` process independent unit groups in parallel (1 worker per core, capped at 8). On Unix, `harvest` copies or reflinks (`FICLONE` on btrfs/XFS/ZFS) artifacts into the vault so build outputs and `0444` store files never share a mutable inode.
* **CPU-starved hosts:** By default, copied artifacts in the vault use content-addressed gzip compression (while `.rlib`/`.a` library outputs stay raw). To skip compression during harvest, pass `--no-compress`:
  ```bash
  epicenter store harvest --no-compress
  ```
* **Nightly toolchains:** `harvest` stores units matching the layout of the active toolchain. To harvest nightly builds:
  ```bash
  epicenter exec --harvest -- cargo +nightly build
  # or
  RUSTUP_TOOLCHAIN=nightly epicenter store harvest
  ```

### Workflow 3: AI Agents & Parallel Local Builds (`exec`)

> **Important rule for agents:** Never point multiple concurrent agents or jobs at the same writable `build/` directory—Cargo's build-dir lock will force them to wait in line. Always use `epicenter exec`.

How `epicenter exec` works:
1. Reads the project's `Cargo.lock` and selects only the packages needed by this project from the read-only vault.
2. Creates a private work directory under the per-user OS cache (`$XDG_CACHE_HOME/epicenter/work/<id>/` by default, or `--work-root`) and seeds it in milliseconds (hard-linking immutable `.rlib`/`.a` archives from a local private vault, and copying mutable metadata/fingerprints).
3. Pins `CARGO_BUILD_BUILD_DIR` (and `CARGO_TARGET_DIR` when `--target-dir` is passed) in the child process environment.
4. Passes through the child command's `stdout`, `stderr`, and exit code unchanged.

Common `exec` flags:
* `--id <NAME>`: Name the job directory (`work/<NAME>/`). New job directories are created with `O_EXCL` and stamped with `.epicenter-job`.
* `--reuse`: Reuse an existing job directory with the same `--id` (refuses safely if another build is holding the lock or if the directory is unmarked/foreign-owned).
* `--target-dir [DIR]`: Give the job its own `CARGO_TARGET_DIR` (defaults to `<work-dir>/target` if no path is given) so final binaries don't collide either.
* `--work-root <PATH>`: Override the per-VM work directory root for this run.
* `--harvest`: After the command succeeds, harvest newly built units back into the vault.
* `--no-compress`: Skip gzip compression when used with `--harvest`.
* `--rm`: Delete the job directory as soon as the command finishes.
* `--cwd <DIR>`: Run the command in `<DIR>` and resolve `epicenter.toml` / `Cargo.lock` from there.

### Workflow 4: CI/CD & Multi-VM Fleets

In CI or multi-VM agent fleets, share the **read-only vault** (`store/`) across VMs, and give each VM its own fast local writable `work/` directory.

1. **Configure CI policy:**
   ```bash
   epicenter setup --preset ci --linker lld
   ```
   *(Or set `CI=true` in the environment—the default `auto` preset automatically switches to `ci` mode and sets `CARGO_INCREMENTAL=0`.)*
2. **Configure local writable work root (`--work-root`):**
   Keep disposable job directories on fast local VM disk (never on the read-only vault or slow `/mnt/c` mounts). The default is the per-user OS cache; `work` is global-only:
   ```bash
   epicenter setup --work-root /var/lib/epicenter/work
   epicenter setup --work-root default   # reset to OS cache default
   # Or override per job:
   epicenter exec --work-root /var/lib/epicenter/work -- cargo test
   ```
3. **Keep fleet parity & check for duplicate variants:**
   Every VM in a shared fleet must use the exact same Rust toolchain, host architecture, `RUSTFLAGS`, target, and Cargo profile settings.
   * **Tip:** Set `debug = "line-tables-only"` (for shared dev+CI fleets) or `debug = 0` (for CI-only fleets) in `Cargo.toml`. Different `debug` levels produce different unit hashes and prevent sharing. (`strip` only affects the final binary, not dependency units.)
   * **Audit profile/package duplication:** Run `epicenter store overlap` (or `--json`) to see if mismatched profiles are storing duplicate variants of the same package in the vault.
4. **Manifest authenticity across machines:**
   The vault manifest is Ed25519-signed. The writer keeps the private key in the per-user epicenter state directory (`${XDG_STATE_HOME:-$HOME/.local/state}/epicenter` on Linux, `~/Library/Application Support/epicenter` on macOS, `%LOCALAPPDATA%\epicenter` on Windows); readers need only the public key stored in the vault as `.epicenter-pubkey`. HMAC remains the legacy/local fallback for old manifests and single-trust-domain stores. Legacy keys under `$CARGO_HOME/epicenter` are still honored, and `doctor` reports them for migration.
5. **Builder / Uploader job (writable vault):**
   ```bash
   epicenter exec --harvest -- cargo build --locked
   ```
6. **Worker jobs (read-only vault mount):**
   ```bash
   epicenter exec --rm --target-dir -- cargo test --locked
   ```
   *(Note: Keep a checked-in `Cargo.lock` in the repo so `exec` seeds only the packages your project uses.)*
7. **Clean up old job directories periodically:**
   ```bash
   epicenter store evict --work-dirs --older-than 2d --yes
   ```
8. **Optional OverlayFS (Linux):**
   If you use `overlayfs` (or `fuse-overlayfs` rootless) for lazy copy-up, mount the `lowerdir` over a **materialized read-only build-dir view** (with `0644`/`0664` state files, not `0444`), not directly over the raw `store/` vault layout, and place Cargo's `upperdir` in the VM's local job directory.

---

## 5. Configuration Reference (`epicenter.toml` & Presets)

Cargo's `~/.cargo/config.toml` owns `[build] build-dir`. Epicenter's policy lives in `epicenter.toml`.

### Precedence Order
For every setting, Epicenter resolves values in this exact order:
1. **CLI flags** (highest priority)
2. **Project `epicenter.toml`** (nearest file walking up from current directory; read-only, never modified by Epicenter)
3. **Global `epicenter.toml`** in the per-user OS config directory (updated when you pass `--preset`, `--memory`, `--linker`, `--work-root`, or `--cargo-home` to `epicenter setup`):
   - Linux/BSD: `${XDG_CONFIG_HOME:-$HOME/.config}/epicenter/epicenter.toml`
   - macOS: `$HOME/Library/Application Support/epicenter/epicenter.toml`
   - Windows: `%APPDATA%\epicenter\epicenter.toml`
4. **`auto` defaults** (lowest priority)

The old `$CARGO_HOME/epicenter.toml` is no longer read or written. `doctor` reports it as legacy and prints the move command. Make relative `store` and `work` values absolute before moving the file; the new location is their base.

### The 7 Keys of `epicenter.toml`

All keys are top-level (no `[section]` headers).

```toml
# Example project or global epicenter.toml
preset = "dev"                   # "auto" | "dev" | "ci"
memory = "16GiB"                 # RAM budget for job calculation (e.g. "16GiB", "8192MiB", or 16384)
linker = "lld"                   # "auto" | "system" | "lld" | "wild"
store  = "~/.cargo/epicenter/store" # Path to the durable vault
work   = "~/.cache/epicenter/work"  # Global-only job-dir root
cargo_home = "/opt/epicenter/cargo" # Global-only, absolute, identical on every VM
link   = "auto"                  # "auto" | "copy" | "link"
```

| Key | Values | Default | What it does |
|---|---|---|---|
| `preset` | `"auto"`, `"dev"`, `"ci"` | `"auto"` | Controls `incremental` and `build.jobs`. See table below. |
| `memory` | `"16GiB"`, `"8192MiB"`, or integer MiB | Physical RAM | Sets `build.jobs = min(cores, floor(memory / 2 GiB))` (minimum 1). |
| `linker` | `"auto"`, `"system"`, `"lld"`, `"wild"` | `"auto"` | `auto` leaves flags untouched; `system` removes Epicenter linker flags; `lld`/`wild` select a linker explicitly. (CLI also accepts `mold` and `gold`). |
| `store` | File path string | `$CARGO_HOME/epicenter/store` | Location of the durable vault. |
| `work` | File path string | Per-user OS cache | Local job-dir root for `exec`, `evict --work-dirs`, `status` and `doctor`. Global-only; a project cannot set it. |
| `cargo_home` | Absolute path string | Shell `CARGO_HOME` or `~/.cargo` | Global-only `CARGO_HOME` for `exec`. Must be identical on every machine/VM that shares remote units; no `~`, relative path or `..`. A project cannot set it. |
| `link` | `"auto"`, `"copy"`, `"link"` | `"auto"` | How `restore`/`exec` materialize `.rlib`/`.a` files. `auto` hard-links from a private local store (owner-only ACL on Windows) and copies from network/shared mounts (`9p`, `drvfs`, `NFS`, `SMB`, etc.) or a Windows store with a permissive DACL. `copy` never hard-links. `link` forces hard links on a trusted store but still copies from a mutable store whose Windows DACL is not owner-only (only allowed in global `epicenter.toml`, projects can only tighten to `auto` or `copy`). |

`cargo_home` is opt-in and global-only. `epicenter setup --cargo-home PATH` creates a missing directory with private permissions (or validates an existing real directory), never copies the registry or Cargo credentials, and pins `exec`'s child `CARGO_HOME` to that absolute path. `epicenter setup --cargo-home default` clears it. The same absolute path must be used by the CI publisher and every reader; a different path changes Cargo's source `path` hash and the remote unit is a miss. Raw `cargo` outside `exec` still uses the shell's `CARGO_HOME`; `doctor` warns when the two differ.

### Presets Explained (`auto`, `dev`, `ci`)

| Preset | Best For | What `setup` writes to Cargo config | What `exec` sets |
|---|---|---|---|
| `auto` | General use | Sets `build.jobs` if missing (or if `--memory` is passed); leaves `incremental` untouched | Sets `CARGO_INCREMENTAL=0` if `CI` env var is truthy (`1`, `true`, `yes`); otherwise keeps Cargo config |
| `dev` | Local coding loop | `incremental = true` (or `false` if a wrapper is active) + `build.jobs` | `CARGO_INCREMENTAL=1` (unless a wrapper is active) |
| `ci` | CI & AI agents | `incremental = false` + `build.jobs` | `CARGO_INCREMENTAL=0` |

### Linker Support Matrix

| Linker Flag | OS / Target Support | Requirements |
|---|---|---|
| `--linker lld` | Linux, BSD, Windows MSVC | **None** — uses the `lld` already bundled inside your `rustup` toolchain. (Refused on macOS). |
| `--linker wild` | Linux ELF, `wasm32` | `wild` on `PATH` + `clang` (or GCC 16.1+). |
| `--linker mold` | Linux ELF | `mold` on `PATH` + `clang`. |
| `--linker gold` | Linux ELF | `gold` on `PATH` + `clang`. |

The old `--fast`/`--without-fast` aliases were removed; use `--linker lld` or
`--linker system` explicitly. LLD is not advertised as a speed win.
| `--linker system` | All | Removes any linker flags managed by Epicenter. |
| `--linker auto` | All | Leaves existing `rustflags` completely alone. |

*Note: Changing linkers alters `RUSTFLAGS`, which creates a new unit hash generation in Cargo and the vault. After switching linkers, run one `cargo build` and then `epicenter store harvest`.*

---

## 6. Observability & Diagnostics (`status` & `doctor`)

### Checking Cache Status & Unit Forensics
```bash
# High-level overview of build cache, vault, and work directories
epicenter status

# Machine-readable JSON output (ideal for AI agents and scripts)
epicenter status --json

# Inspect all cached units, grouped by package and toolchain generation
epicenter status --units

# Filter unit forensics by package name
epicenter status --units --filter serde

# Deep-dive into a single unit (hashes, features, dependencies, artifacts, FRESH/DIRTY verdict)
epicenter status --unit serde
```

### Auditing Health with `doctor`
Run `epicenter doctor` whenever something feels slow or misconfigured:
```bash
epicenter doctor
epicenter doctor --json
```
`doctor` checks and reports in plain language:
* Cargo config and `epicenter.toml` agreement
* Cargo profile audit (`jobs`, `codegen-units`, `lto`, `debug`, `split-debuginfo`, plus last calibrated build time/RSS)
* Wrapper (`kache`/`sccache`) health
* Filesystem performance warnings (e.g., warning if your WSL cache accidentally points to a slow `/mnt/c` Windows mount)
* Toolchain and mtime ordering integrity
* Vault health and legacy config reminders

---

## 7. Reclaiming Disk Space: `prune` vs `evict`

Both commands run in **dry-run mode by default** so you never delete files by accident. Add `--yes` to actually delete.

### Quick Rule of Thumb
* **Use `epicenter store prune`** for routine age-based housekeeping of the shared `build/` directory (never touches the vault).
* **Use `epicenter store evict`** to deliberately remove specific crates, stale toolchain generations, broken units, or finished agent `work/` directories across the vault and views.

### `prune` Examples (Housekeeping the Shared Build Dir)
```bash
# Preview removing build-dir units untouched for 30 days (default)
epicenter store prune

# Delete build-dir units untouched for 60 days
epicenter store prune --older-than 60d --yes

# Keep only the 2 newest unit groups per package/kind and delete older ones
epicenter store prune --keep-latest 2 --yes

# Prune only incremental compilation state, keeping only the latest 1
epicenter store prune --incremental --keep-latest 1 --yes
```

### `evict` Examples (Deliberate Removal Across Tiers)

 Epicenter separates **nominal size**, **bytes actually freed** (last hard link removed), and **links released** (another tier still holds a hard link to the file), so disk reports never lie.

```bash
# Remove a specific unit from both the vault and all build/work views
epicenter store evict --unit regex --tier all --yes

# Remove a unit from the vault ONLY (working build dirs keep functioning)
epicenter store evict --unit regex --tier store --yes

# Remove a unit from working views ONLY (vault stays untouched)
epicenter store evict --unit regex --tier view --yes

# Surgical cache-bust: unlink one crate from one specific job dir (or 'build')
epicenter store evict --work agent-1 --crate my-patched-dep --yes

# Delete an entire old toolchain/flag generation from the vault
epicenter store evict --generation <parity-key> --yes

# Bulk evict stale units, incomplete "husk" units, or units older than 90 days
epicenter store evict --stale --yes
epicenter store evict --husks --yes
epicenter store evict --older-than 90d --yes

# Clean up finished agent/CI job directories older than 7 days (default)
# (Live builds holding a lock are automatically skipped)
epicenter store evict --work-dirs --older-than 7d --yes

# Immediately delete one specific finished job directory right now
epicenter store evict --work-dir agent-1 --yes
```

---

## 8. Cross-OS & Toolchain Notes

* **One Config Everywhere:** Epicenter writes `build-dir = '{cargo-cache-home}/epicenter/build'` using forward slashes and Cargo's native `{cargo-cache-home}` template token. Cargo expands this at build time, so the exact same config works across Linux, WSL, macOS, and Windows.
* **Windows `%USERPROFILE%\.cargo` owner:** an elevated installer may leave `.cargo` owned by `Administrators` instead of the user. Epicenter accepts that when the DACL grants write access only to the current user, `SYSTEM`, `Administrators` or the object owner; it rejects a permissive DACL. If the directory is not writable by the user, either repair its ACL (`icacls`) or point `epicenter setup --cargo-home PATH` at a private directory.
* **WSL Best Practice:** Keep your source code wherever you like (even `/mnt/c/...`), but keep the Epicenter cache and `work/` directories on the native Linux filesystem (`~/.cargo/epicenter/...`). Linux ext4 I/O is 10–30× faster than `/mnt/c`. `epicenter doctor` will warn you if your cache drifts onto a Windows mount.
* **Never Hardcode Windows Backslash Paths:** Do not manually write `C:\...` into `~/.cargo/config.toml` if WSL shares that file. Always use `epicenter setup --cache-root ...` so paths stay portable.
* **Cargo Build-Dir Layouts (1.91+ vs 1.100+ / Nightly):**
  Cargo 1.91–1.99 uses the classic layout (`<profile>/.fingerprint/...`), while Cargo 1.99 nightly and 1.100+ use the new layout (`<profile>/build/<pkg>/<hash>/...`). Epicenter inspects and supports both layouts side-by-side automatically.

---

## 9. Complete Command Cheat Sheet

| Command | Description |
|---|---|
| `epicenter setup` | Configure shared build dir with `auto` preset; backs up touched config files |
| `epicenter setup --preset auto\|dev\|ci` | Set build jobs and incremental compilation policy |
| `epicenter setup --linker auto\|system\|lld\|wild\|mold\|gold` | Configure linker flags in global Cargo config |
| `epicenter setup --memory <SIZE>` | Set RAM budget (e.g. `16GiB`) for `2 GiB/job` concurrency calculation |
| `epicenter setup --cargo-home PATH\|default` | Set or clear the global absolute `CARGO_HOME` used by `exec` |
| `epicenter setup --write-profile [--dev-debug full\|line\|none]` | Write recommended profile settings to workspace `Cargo.toml` (with backup) |
| `epicenter setup --measure` | Run a calibration `cargo build` after setup to record wall time and peak RSS |
| `epicenter setup --wrapper kache\|sccache\|none` | Configure an external `rustc-wrapper` |
| `epicenter setup --cache-root <PATH>` / `--use-default` | Set a custom shared build dir path or reset to default |
| `epicenter setup --work-root <PATH\|default>` | Set or reset the local per-VM job-dir root (`work` in global `epicenter.toml`) |
| `epicenter setup --dry-run` | Print effective policy and config diffs without writing anything |
| `epicenter setup --revert` | Restore the newest backups of Cargo config and global `epicenter.toml` |
| `epicenter status [--json]` | Show cache sizes and tier summary |
| `epicenter status --units [--filter <Q>]` | Show per-package unit forensics and generations (alias: `who`) |
| `epicenter status --unit <NAME>` | Inspect one unit's hashes, deps, files, and freshness (alias: `why`) |
| `epicenter doctor [--json]` | Audit config, profile, wrapper, filesystem, toolchain, mtimes, and vault |
| `epicenter exec [FLAGS] -- <CMD>` | Run `<CMD>` in an isolated per-job build dir seeded from the vault |
| `epicenter store harvest [--unit <Q>] [--no-compress] [--dry-run]` | Save compiled units from the shared build dir into the durable vault |
| `epicenter store restore [--into <DIR>] [--unit <Q>] [--dry-run]` | Seed a build dir (default: shared build dir) from the vault |
| `epicenter store vault` | List vault generations, sizes, and active status |
| `epicenter store verify` | Verify vault file sizes, timestamps, hashes, and list active `work/` dirs |
| `epicenter store overlap [--json]` | Report duplicate package/profile variants and repeated bytes in the vault |
| `epicenter store prune [--older-than 30d] [--keep-latest N] [--incremental] [--yes]` | Age/count-based cleanup of the shared build dir (dry-run without `--yes`) |
| `epicenter store evict [SELECTOR] [--tier all\|store\|view] [--yes]` | Deliberately remove units, generations, or `work/` dirs (dry-run without `--yes`) |
