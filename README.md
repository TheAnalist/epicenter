# <img src="epicenter_logo_compact.svg" width="44" align="center" alt="epicenter logo" /> epicenter - the state layer for Cargo builds

*Requires Cargo with `build.build-dir` support — Rust 1.91+.*

Rust has two main problems: slow compilation times and big target directories.
This usually means that every Cargo project compiles its dependencies into its own `target/` directory:
ten projects = ten copies of the same rlibs, consuming gigabytes of storage.
So *epicenter* tries to solve this problem with a simple idea:
why not keep one shared version of compiled dependencies?

It manages that state as **three tiers, one tool**:

- **store** — a durable vault of unit groups addressed by Cargo's own
  fingerprint hashes (`…/epicenter/store/…`); survives `cargo clean`, feeds
  cold starts and parallel jobs.
- **build** — the shared cache every project compiles into
  (`…/epicenter/build/…`): dependency rlibs, incremental state, build-script
  outputs — the heavy 95% — compiled once and reused everywhere.
- **work** — disposable per-job build dirs seeded from the vault
  (`…/epicenter/work/<id>/`), where CI jobs and agents run fully parallel:
  nothing shared but the read-only vault.

Around those tiers *epicenter* owns the lifecycle: **configure** (`setup`,
`doctor` — cross-OS config truth), **observe** (`status`, `who`, `why`, `vault`,
`verify`), **reclaim** (`prune` for age-based housekeeping, tiered `evict` for
deliberate removals with honest freed-vs-released accounting), **persist**
(`harvest`, `restore`) and **execute** (`exec`). Cargo stays Cargo — no shim,
no daemon — and a rustc-wrapper (kache or sccache) remains an optional tier.

One configuration for Linux, WSL, macOS and native Windows: the platform code
is std-only and cfg-gated, and the canonical template line is identical
everywhere. (Linux/WSL and Windows are verified live; Apple and BSD targets are
compile-verified — see Cross-OS notes for the first-run checklist.)

*epicenter isn't a Cargo wrapper* — it leans on Cargo's own fingerprint engine,
which decides freshness and therefore recompilation. A unit restored from the
vault is `Fresh` to Cargo in milliseconds, with **zero `rustc` processes
spawned**.

## Benchmarks

These benchmarks are done against 5 projects with 37 identical dependencies each.

**Five cold builds: 123 s → 28.9 s (4.3× faster). Disk: 3.65 GiB → 0.91 GiB
(−75%). A cold per-job `work/` dir seeded from the vault: 1.50 s.**

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

In addition it measures the vault tier (`epicenter harvest` + `epicenter exec`),
where a cold per-job build dir is seeded from the durable store instead of recompiling.

![Cumulative build time](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-cumulative.svg)

![Disk usage](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-disk.svg)

![Epicenter shared projects save](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-variants.svg)

![Build time per project](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-per-project.svg)

![Cold start in a per-job work dir](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-vault.svg)

### rust-lld (`--fast`)

`epicenter setup --fast` wires rustup's bundled `ld.lld` into Cargo — no extra
install. On these Linux/GNU debug builds it is **neutral**: the five cold
builds go from 28.9 s to 29.1 s (+0.7%), and a paired relink after a one-line
change goes from 1039 ms to 1047 ms (+0.8%) — both inside run-to-run noise.
A cold build compiles 176 crates before it links, so the linker is a small
slice; `--fast` targets link-heavy workloads and platforms with a slower
system linker (large release binaries, MSVC). This benchmark covers the
debug/GNU case only.

![rust-lld summary](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-fast-summary.svg)

![rust-lld relink](https://raw.githubusercontent.com/TheAnalist/epicenter/main/chart-fast-relink.svg)

## Quickstart

```bash
cargo install epicenter-cli
epicenter setup                  # write the shared-cache config (backs up files it touches)
cargo build                      # any project of yours — intermediates now land in the shared cache
epicenter status                 # watch it fill up
epicenter doctor                 # verify everything is healthy
```

Every setup edit backs up the previous config as `config.toml.epicenter-bak[.N]` (monotonic suffixes).
`epicenter setup --revert-config` restores the newest one atomically and prints both the config and the backup path.

## Three workflows, one tool

1. **Daily development (zero extra steps)** — run `epicenter setup` once. Every
   project on the machine immediately shares compiled dependencies.
2. **Survive `cargo clean` and cold starts (the vault)** — `epicenter harvest`
   snapshots built units into the read-only vault; `epicenter restore` links
   them back so Cargo skips compilation completely.
3. **Parallel agents & CI jobs (zero lock waits)** —
   `epicenter exec --id agent-1 --target-dir -- cargo test` seeds a private
   per-job build dir from the vault in milliseconds — only the packages this
   project resolves to, not every unit in the cache. Ten agents can build the
   same repo at the same time without waiting on Cargo's build-dir lock or
   duplicating rlibs on disk.

## Commands

| command | what it does |
|---|---|
| `epicenter setup` | write the shared-cache config; **backups** any file it modifies (`*.epicenter-bak`) |
| `epicenter setup --cache-root <path>` | use a different cache directory instead of the default |
| `epicenter setup --use-default` | remove a custom root, back to the canonical default |
| `epicenter setup --fast` | wire rustup's bundled LLD (`ld.lld` / `rust-lld`) into `~/.cargo/config.toml` — zero installs; also sets `incremental = true` unless a wrapper is configured; `--without-fast` removes the flags |
| `epicenter setup --revert-config` | restore `~/.cargo/config.toml` from the newest setup backup (`config.toml.epicenter-bak[.N]`), then stop |
| `epicenter setup --with-wrapper kache` | also configure [kache](https://github.com/kunobi-ninja/kache) (or sccache) as `rustc-wrapper` |
| `epicenter setup --without-wrapper` | remove a previously configured wrapper |
| `epicenter status` | sizes, per-directory breakdown, largest build units |
| `epicenter who [--unit <q>]` | unit forensics: per-package blocks, toolchain generations, stale flags |
| `epicenter why <unit>` | one unit in depth: hashes, features, deps, artifact inventory, FRESH/DIRTY verdict |
| `epicenter evict --unit <q>` | remove units deliberately (store + views): dry run by default, `--yes` to delete — an explicit `--unit` is deliberate, so no `--force` even on the current generation |
| `epicenter evict --unit <q> --tier store` | trim the **vault only** — no `--force` needed, the vault is yours to trim |
| `epicenter evict --generation <key>` | delete a whole parity-key generation (units, manifest, lock) — dry run unless `--yes`; the active generation needs `--force`; `--tier store` keeps views |
| `epicenter evict --unit <q> --tier view` | unlink the working copies only (build dir + job dirs); vault untouched |
| `epicenter evict --work <job\|build> --crate <name>` | surgical cache-bust: unlink one crate from ONE view; the vault is never touched |
| `epicenter evict --stale` / `--husks` / `--older-than 90d` / `--rustc-key <h>` | bulk selectors, by default across the store and every known view — current-generation units need `--force` |
| `epicenter evict --work-dir <job>` | remove ONE job dir now — explicit choices bypass the GC window (dry run default; a live build's dir is refused) |
| `epicenter evict --work-dirs [--older-than 7d]` | collect stale per-job working dirs; a dir a live build has locked is never touched |
| `epicenter prune [--older-than 30d]` | age-based housekeeping of the shared build dir (policy GC, default 30d). **Dry run by default** — pass `--yes` to delete |
| `epicenter doctor` | health check with plain-language verdicts: config, wrapper, filesystem, toolchain, mtime ordering |
| `epicenter vault` | show the vault: generations (toolchain + flags), sizes, links into the build view |
| `epicenter harvest [--unit <q>] [--dry-run]` | store built unit groups from the shared build dir into the vault - only the layout of the toolchain it runs under (nightly units: `RUSTUP_TOOLCHAIN=nightly` or `exec --harvest`) |
| `epicenter restore [--into <dir>] [--unit <q>] [--dry-run]` | seed a working dir from the vault (default: the shared build dir) — `deps/`/`out/` rlibs and `.so` hard-linked; `.rmeta` + fingerprint state copied |
| `epicenter verify` | audit the vault: file sizes, canonical stamps, hash contents, dependency ordering — and name the job dirs under `work/` |
| `epicenter exec [--harvest] [--rm] [--reuse] [--target-dir [DIR]] [--id <id>] [--cwd <dir>] -- <cmd>` | run a command in a fresh per-job build dir seeded from the vault for the project's packages (CI/agents) |

### Zero-install fast linker (`setup --fast`)

rustup already ships LLVM's linker inside every toolchain — no `mold`, no `lld`
package, no `clang` needed:

```text
~/.rustup/toolchains/<toolchain>/lib/rustlib/<host>/bin/gcc-ld/
    ld.lld   lld-link   ld64.lld   wasm-ld
```

`epicenter setup --fast` detects that directory for the active host and writes
one `[target.<host>] rustflags` line into `~/.cargo/config.toml`:

- **Linux / BSD (ELF)** — `-C link-arg=-fuse-ld=lld -C link-arg=-B<gcc-ld>`.
  The system C compiler stays the driver; it does not have to be clang.
- **Windows MSVC** — `-C linker=<bin>/rust-lld.exe`. `-fuse-ld` is a
  GCC/Clang flag and `link.exe` does not understand it, so rustc is pointed at
  the bundled **generic** LLD driver. rustc recognizes the name and appends
  `-flavor link`; `gcc-ld/lld-link.exe` is already the COFF driver and rejects
  that flag.
- **macOS** is refused — `ld64.lld` is not a drop-in replacement for Apple's
  linker.

When no `rustc-wrapper` remains, `--fast` also sets `[build] incremental =
true`: wrapper caches (kache/sccache) and Cargo's incremental state work
against each other, so the key is skipped when a wrapper is present. Either
outcome is printed in the setup report.

`epicenter setup --without-fast` removes the flags again, but only when they
still match what `--fast` wrote: custom `rustflags` are never touched. The
change is backed up (`config.toml.epicenter-bak`) like every setup edit.
Enabling it changes RUSTFLAGS, so every unit re-keys once and the vault opens a
new generation — build once, then `epicenter harvest`.

## `prune` vs `evict` — housekeeping vs deliberate removal

Both delete things, both show a dry run first, and neither ever runs on its
own. The difference is *why* and *where* they act:

| | `epicenter prune` | `epicenter evict` |
|---|---|---|
| criterion | **age** — a policy (`--older-than`, default 30d) | **identity** — a selector (`--unit`, `--stale`, `--rustc-key`, `--husks`) or an explicit target (a job dir) |
| scope | the **shared build dir only** (one view) | the **vault and every known view** by default (`--tier all`); one tier on request |
| space | frees bytes no other link holds; vault copies keep theirs | with `--tier all`, removes every link it knows — the report separates *actually freed* from *links released* |
| typical use | scheduled housekeeping: "keep the cache bounded" | "get rid of **this**": a package, a stale toolchain generation, husk units, a finished job dir |
| never does | touch the vault or job dirs; take a selector | sweep purely by age (except `--work-dirs`, the job-dir GC); remove the shared build dir itself |

Rules of thumb:

- the cache grew over months and you just want it smaller → **`prune`**
- a specific crate misbehaves, a toolchain generation went stale, an agent's
  job dir is done → **`evict`**
- you want the *space* back, not just an unlink from the working view →
  **`evict --tier all`** (or `--tier store` to trim the vault alone)

Both report what they *would* do first; nothing is deleted without `--yes`.
(What "tiers" mean in practice — and how the numbers stay honest — is in
*Tiers, and honest numbers* below.)

## Configuration — one file owns the decision

The shared-cache decision lives in **`$CARGO_HOME/config.toml`**
(`~/.cargo/config.toml`) as the `[build] build-dir` key:

```toml
[build]
build-dir = '{cargo-cache-home}/epicenter/build'
```

`epicenter setup` writes/manages that key for you (and keeps a
`*.epicenter-bak` backup of the file before touching it). Custom roots go to
the same place: `epicenter setup --cache-root ~/bigdisk/rust-cache` replaces
the key's value with your path. There is **no separate epicenter state file** —
nothing can drift out of sync, and `epicenter doctor` verifies the whole
arrangement. (Older versions used `~/.epicenter/config.toml`; it is no longer
read and is safe to delete — `doctor` reminds you if it is still around.)

`{cargo-cache-home}` is expanded **by cargo at every build** — one line is
correct on Linux, WSL and native Windows; nothing is path-resolved-and-stored.

## Changing the build dir

```bash
epicenter setup --cache-root /mnt/big/cache        # literal path
epicenter setup --cache-root '~/rust-cache'        # home-relative
epicenter setup --cache-root '{cargo-cache-home}/n1' # template power-users
epicenter setup --use-default                      # back to default
```

Priority is explicit: CLI flag > the value already in `~/.cargo/config.toml` >
the canonical default template. After every change, `epicenter doctor`
re-verifies that the cargo config and the cache directory agree.

## How resolution works (and why it is safe)

- configs always contain the **template**, never an expanded path —
  cargo re-expands `{cargo-cache-home}` on the platform it builds for, so one
  file serves WSL and Windows;
- commands that touch the filesystem (`status`/`prune`) ask **cargo itself**
  (`cargo metadata` → `build_directory`) for the effective directory, then
  normalize separators locally; the expansion is never written back into any
  config;
- paths with backslash separators are the one known hazard in a
  shared-cross-OS setup — the canonical form therefore uses forward slashes,
  which are valid separators on Windows too.

## The vault — surviving `cargo clean` and cold starts

Cargo's own fingerprints make the shared build dir fast while it is warm — but a
wipe (`cargo clean`, a fresh checkout, a new container) throws that state away.
The vault makes the state durable:

```text
{cargo-cache-home}/epicenter/
  store/<parity-key>/          the vault: one generation per toolchain + flag set
    manifest.json              file list, sizes, canonical stamps
    units/<pkg>-<hash>/        one unit group: fingerprint files + artifacts
  build/…                      the shared build dir — a disposable view of the store
```

```bash
epicenter harvest              # after a build: store every unit group in the vault
epicenter vault                # what the store holds, per generation
epicenter verify               # audit: sizes, stamps, hash contents
cargo clean                    # the view is gone — the store is not
epicenter restore              # (or --into <dir>): seed the view from the vault
cargo build                    # Cargo sees fresh fingerprints: zero recompiles
```

Measured under WSL on ext4: wiping one unit and restoring it takes milliseconds,
after which `cargo build -v` reports `Fresh … in 0.01s` with **zero rustc
processes**. Restore hard-links link outputs (`deps/` classically, `out/`
in the new layout) — a thousand jobs share
one copy of every rlib — and copies `.rmeta` plus the fingerprint state and
build-script trees, because rustc and cargo rewrite those in place (a shared
inode would either break a rebuild or corrupt the store). Each unit group
carries one canonical timestamp: the moment its `.rmeta` landed, so nothing
is ever older than what it compiled against — `epicenter verify` audits that
order. Everything is fail-open: a partial vault just means Cargo recompiles
what is missing, never a broken build.

Generations are keyed by `<rustc-release>-<commit>-<host>-<flag-digest>`: a
toolchain upgrade opens a new generation instead of invalidating one, and
`epicenter vault` marks which generation is active. (Cross-arch sharing is not
supported — one vault per platform.)

`epicenter evict --generation <key>` removes a whole generation — units,
manifest and lock — in one step. An eviction that empties a generation removes
its parity-key directory and lock too, and a store sweep clears orphan locks
and empty manifest-less directories: nothing is left for you to delete by hand.

### Cargo's two build-dir layouts

Epicenter reads both unit layouts Cargo writes, side by side:

| Cargo | Layout | Unit shape |
|---|---|---|
| 1.91 – 1.99 stable | classic | `<profile>/.fingerprint/<pkg>-<hash>/` + `<profile>/deps/` |
| 1.99 nightly · 1.100+ | new | `<profile>/build/<pkg>/<hash>/{fingerprint,out}/` |

`who`, `why`, `status`, `prune`, `harvest` and `evict` discover units by shape,
so a cache shared by a stable and a nightly toolchain is fully visible. `exec`
resolves the child's `+toolchain` and `cargo --version`: nightly 1.99+ (and
stable 1.100+) seed the new layout; older nightlies only when
`-Zbuild-dir-new-layout` is passed; everything else stays classic.

`harvest` follows the toolchain it runs under: in a cache that mixes stable and
nightly units it stores only that toolchain's layout (the other units show up
as "skipped"). Harvest nightly units with
`epicenter exec --harvest -- cargo +nightly build`, or run
`RUSTUP_TOOLCHAIN=nightly epicenter harvest`.

### One line for CI jobs and agents

`exec` mints a fresh build dir per job, seeds it from the vault, and runs your
command in it — no shim, no daemon, no config change. The seed is scoped to the
packages in the project's `Cargo.lock` (workspace included), so a small project
does not inherit every other project's units — and it matches the build-dir
layout the child cargo will write (classic vs the new per-unit layout).
`restore` still seeds a whole generation by design:

```bash
epicenter exec -- cargo test                    # warm start, nothing kept
epicenter exec --harvest -- cargo build         # …and store the units this job produced
epicenter exec --rm --id nightly -- cargo test  # delete the job dir after the run
```

For long-lived agents, a job dir is a home:

```bash
epicenter exec --id agent-7 --target-dir -- cargo build           # per-job finals dir
epicenter exec --id agent-7 --reuse --target-dir -- cargo test    # continue in it
```

`--reuse` continues in an existing job dir instead of refusing (restore is
idempotent; a dir a live build holds is still refused). `--target-dir` pins the
child's `CARGO_TARGET_DIR` — bare it is `<work dir>/target`, so finals live and
die with the job; with a value it selects that path instead. With both pinned
per job, two builds of the same project share nothing but the read-only vault:
**no lock contention anywhere — the fully parallel case.**

The command's exit code becomes *epicenter*'s exit code; its stdout and stderr
pass through untouched (*epicenter*'s own frame lines go to stderr). Every job
owns its build dir, so parallel jobs never wait on Cargo's per-build-dir lock,
and job dirs are disposable — they live under
`{cargo-cache-home}/epicenter/work/<id>/`.

Job dirs accumulate by design (one per job). `epicenter evict --work-dirs`
collects the ones untouched for a week (customizable with `--older-than`,
dry-run by default, `--yes` to delete) and reports what was *actually* freed —
bytes still hard-linked from the vault or a wrapper's store are released, not
freed, and are reported separately. A dir a live build has locked is never
touched. And a dir you no longer need goes **right now**: `epicenter evict
--work-dir <job> --yes` — the age window is a GC policy for bulk collection,
not a gate on explicit choices.

### Tiers, and honest numbers

The vault is the user's storage: **trimming it never breaks a build** — the
only cost is the next compile. `evict` therefore treats the tiers explicitly:

- default `--tier all` — the store **and** every known view (build dir + job
  dirs). Use it to actually reclaim space; the dry run already tells you the
  truth: *nominal* bytes, *actually freed* (the last hard link goes with it),
  and *links released* (the vault or a wrapper store still holds those bytes).
- `--tier store` — the vault alone; no `--force` needed for the current
  generation, because views keep working from their own links.
- `--tier view` / `evict --work <job> --crate <name>` — cache-bust a chosen
  crate in one view (a patched dependency in an agent job, a flaky crate in
  CI). A freshness operation, never a space claim; the vault is untouched and
  a view a live build has locked refuses to be touched.

An explicit `--unit` is a deliberate choice, like `--tier store`: it bypasses
the current-generation guard. Bulk selectors (`--stale`, `--older-than`,
`--rustc-key`, `--husks`) keep it unless you pass `--force`.

Removing a job dir (`exec --rm`, `evict --work-dir`, `evict --work-dirs`) also
deletes its `.lock-<job>` marker and sweeps orphan `.lock-*` files left behind
by crashed or older removals.

## Cross-OS notes

- macOS / BSD: nothing platform-specific to configure — same template, same
  commands. First-run checks worth doing on real hardware: the Cargo lock guard
  (`exec --reuse` must refuse while a build runs in the job dir, and
  `evict --work-dirs` must skip it), hard links plus the copy+stamp fallback
  across APFS volumes, and `epicenter doctor`. Stamps are whole-second, so
  HFS+' 1-second mtime granularity is safe.
- WSL users: projects on `/mnt/c` are fine, but keep the *cache* on the Linux
  side (the default does) — 10–30× faster I/O. `doctor` warns if the cache ever
  drifts onto a Windows-mounted drive.
- Never put an expanded Windows path (`C:\…`) into `~/.cargo/config.toml`:
  WSL cargo reads that same file as an *ancestor* config and breaks.
  `doctor` catches this.

## With kache or sccache (optional)

One line: `epicenter setup --with-wrapper kache`. The wrapper tier adds
compile-result caching across machines (CI/remote) and languages beyond Rust.
*epicenter* stays the cache-state authority either way: config health, pruning,
ownership, diagnostics.

## License

Licensed under the [GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html)
(`GPL-3.0-or-later`). See the `LICENSE` file in the repository.
