<h1 align="center">
    <img width="99" alt="epicenter logo" src="epicenter-icon.svg">
    <br>
    <b>epicenter</b>
    <br>
    <sub>
        <sup>The state layer for Cargo builds</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/epicenter-cli"><img src="https://img.shields.io/crates/v/epicenter-cli.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/epicenter-cli"><img alt="downloads" src="https://img.shields.io/crates/d/epicenter-cli?color=%230099ff"></a>
    <a href="https://docs.rs/epicenter-cli"><img src="https://docs.rs/epicenter-cli/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/TheAnalist/epicenter/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/crates/l/epicenter-cli.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.91%2B-blue"></a>
</p>
<br>

Rust has two main problems: slow compilation times and big target directories.
This usually means that every Cargo project compiles its dependencies into its own `target/` directory:
ten projects = ten copies of the same rlibs, consuming gigabytes of storage.
So *epicenter* tries to solve this problem with a simple idea:
why not keep one shared version of compiled dependencies?

It manages that state as **three tiers, one tool**:

- **store** - a durable vault of unit groups addressed by Cargo's own
  fingerprint hashes (`…/epicenter/store/…`); survives `cargo clean`, feeds
  cold starts and parallel jobs.
- **build** - the shared cache every project compiles into
  (`…/epicenter/build/…`): dependency rlibs, incremental state, build-script
  outputs - the heavy 95% - compiled once and reused everywhere.
- **work** - disposable per-job build dirs seeded from the vault, where CI jobs
  and agents run fully parallel: nothing shared but the read-only vault.

Around those tiers *epicenter* owns the lifecycle: **configure** (`setup`,
`doctor` - cross-OS config truth), **observe** (`status`, including
`--units`/`--unit`, and `store vault`/`store verify`), **reclaim**
(`store prune` for age-based housekeeping, tiered `store evict` for deliberate
removals with honest freed-vs-released accounting), **persist**
(`store harvest`/`store restore`) and **execute** (`exec`). Cargo stays Cargo -
no shim, no daemon - and a rustc-wrapper (kache or sccache) remains an optional
tier.

*epicenter isn't a Cargo wrapper* - it leans on Cargo's own fingerprint engine,
which decides freshness and therefore recompilation. A unit restored from the
vault is `Fresh` to Cargo in milliseconds, with **zero `rustc` processes
spawned**.

> **Full Guide & Workflow Integration:** See **[`DOCS.md`](DOCS.md)** for practical copy-paste recipes, workflow integration (daily dev, surviving `cargo clean`, parallel AI agents, multi-VM CI/CD), `epicenter.toml` configuration, linker setup (`lld`, `wild`, `mold`, `gold`), disk reclamation (`prune` vs `evict`), and the complete CLI reference.

## Benchmarks

These benchmarks are done against 5 projects with 37 identical dependencies each.

**Five cold builds: 83.1 s → 19.3 s (4.3× faster). Disk: 3.65 GiB → 0.91 GiB
(−75%). A cold per-job `work/` dir seeded from the vault: 0.66 s.**

All five projects declare the same platform stack. This is the monorepo / "one platform crate" case.
Every non-local Cargo unit is byte-for-byte identical across projects,
so epicenter can compile it once and the other projects reuse it.

### What is measured

| | baseline | epicenter |
|---|---|---|
| config | no `build-dir` key | `epicenter setup` → `[build] build-dir = '{cargo-cache-home}/epicenter/build'` |
| where dependencies compile | `<project>/target/` (one copy each) | one shared build dir |
| measurement | wall clock around `cargo build --locked --offline` | same |
| reset before every run | `rm -rf` every `target/` | `rm -rf` every `target/` + the whole `epicenter/` cache |

In addition it measures the vault tier (`epicenter store harvest` + `epicenter exec`),
where a cold per-job build dir is seeded from the durable store instead of recompiling.

![Cumulative build time](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-cumulative.svg)

![Disk usage](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-disk.svg)

![Epicenter shared projects save](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-variants.svg)

![Build time per project](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-per-project.svg)

![Cold start in a per-job work dir](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-vault.svg)

## Quickstart

```bash
cargo install epicenter-cli
epicenter setup                  # write the shared-cache config (backs up files it touches)
cargo build                      # any project of yours - intermediates now land in the shared cache
epicenter status                 # watch it fill up
epicenter doctor                 # verify everything is healthy
```

Every setup edit backs up the previous config (`epicenter setup --revert` restores it atomically).

## Documentation

Read **[`DOCS.md`](DOCS.md)** for the complete user and agent guide:

1. **[Core Concepts (`build`, `store`, `work`)](DOCS.md#1-core-concepts-three-tiers-one-tool)** — How the three tiers work together.
2. **[Installation & 30-Second Quickstart](DOCS.md#2-installation--30-second-quickstart)** — Getting started and safe rollback.
3. **[Practical Recipes ("I want to...")](DOCS.md#3-practical-recipes-i-want-to)** — Copy-paste setups for `lld`/`wild`/`mold`/`gold`, memory limits, profiles, `cargo clean` recovery, multiple git worktrees, and parallel agents.
4. **[Detailed Workflows](DOCS.md#4-detailed-workflows)** — Daily development, Vault persistence, lock-free git worktrees & AI agents (`exec`), and CI/CD multi-VM fleets.
5. **[Configuration Reference (`epicenter.toml` & Presets)](DOCS.md#5-configuration-reference-epicentertoml--presets)** — Precedence, the 7 policy keys, presets (`auto`, `dev`, `ci`), and linker support.
6. **[Observability & Diagnostics (`status` & `doctor`)](DOCS.md#6-observability--diagnostics-status--doctor)** — Unit forensics and health checks.
7. **[Reclaiming Disk Space (`prune` vs `evict`)](DOCS.md#7-reclaiming-disk-space-prune-vs-evict)** — Age-based housekeeping vs deliberate tiered eviction.
8. **[Cross-OS & Toolchain Notes](DOCS.md#8-cross-os--toolchain-notes)** — Linux, WSL, macOS, Windows, and Cargo 1.91+ vs 1.100+ layouts.
9. **[Complete Command Cheat Sheet](DOCS.md#9-complete-command-cheat-sheet)** — Every CLI command and flag at a glance.

## License

Licensed under the [GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html)
(`GPL-3.0-or-later`). See the `LICENSE` file in the repository.
