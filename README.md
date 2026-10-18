# epicenter — the state layer for Cargo builds

*Requires Cargo with `build.build-dir` support — Rust 1.91+.*

Install: `cargo install epicenter-cli` — the crate ships the `epicenter` binary.

Every Cargo project compiles its dependencies into its own `target/` directory:
ten projects = ten copies of the same rlibs. epicenter manages that state as
**three tiers, one tool**:

- **store** — a durable vault of unit groups addressed by Cargo's own
  fingerprint hashes (`…/epicenter/store/…`); survives `cargo clean`, feeds
  cold starts and parallel jobs.
- **build** — the shared cache every project compiles into
  (`…/epicenter/build/…`): dependency rlibs, incremental state, build-script
  outputs — the heavy 95% — compiled once and reused everywhere.
- **work** — disposable per-job build dirs seeded from the vault
  (`…/epicenter/work/<id>/`), where CI jobs and agents run fully parallel:
  nothing shared but the read-only vault.

Around those tiers epicenter owns the lifecycle: **configure** (`setup`,
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

## Quickstart

```bash
cargo install epicenter-cli
epicenter setup                  # write the shared-cache config (backs up files it touches)
cargo build                      # any project of yours — intermediates now land in the shared cache
epicenter status                 # watch it fill up
epicenter doctor                 # verify everything is healthy
```

## Three workflows, one tool

1. **Daily development (zero extra steps)** — run `epicenter setup` once. Every
   project on the machine immediately shares compiled dependencies.
2. **Survive `cargo clean` and cold starts (the vault)** — `epicenter harvest`
   snapshots built units into the read-only vault; `epicenter restore` links
   them back so Cargo skips compilation completely.
3. **Parallel agents & CI jobs (zero lock waits)** —
   `epicenter exec --id agent-1 --target-dir -- cargo test` seeds a private
   per-job build dir from the vault in milliseconds. Ten agents can build the
   same repo at the same time without waiting on Cargo's build-dir lock or
   duplicating rlibs on disk.

## Commands

| command | what it does |
|---|---|
| `epicenter setup` | write the shared-cache config; **backups** any file it modifies (`*.epicenter-bak`) |
| `epicenter setup --cache-root <path>` | use a different cache directory instead of the default |
| `epicenter setup --use-default` | remove a custom root, back to the canonical default |
| `epicenter setup --with-wrapper kache` | also configure [kache](https://github.com/kunobi-ninja/kache) (or sccache) as `rustc-wrapper` |
| `epicenter setup --without-wrapper` | remove a previously configured wrapper |
| `epicenter status` | sizes, per-directory breakdown, largest build units |
| `epicenter who [--unit <q>]` | unit forensics: per-package blocks, toolchain generations, stale flags |
| `epicenter why <unit>` | one unit in depth: hashes, features, deps, artifact inventory, FRESH/DIRTY verdict |
| `epicenter evict --unit <q>` | remove units deliberately (store + views): dry run by default, `--yes` to delete |
| `epicenter evict --unit <q> --tier store` | trim the **vault only** — no `--force` needed, the vault is yours to trim |
| `epicenter evict --unit <q> --tier view` | unlink the working copies only (build dir + job dirs); vault untouched |
| `epicenter evict --work <job\|build> --crate <name>` | surgical cache-bust: unlink one crate from ONE view; the vault is never touched |
| `epicenter evict --stale` / `--husks` / `--older-than 90d` / `--rustc-key <h>` | bulk selectors, by default across the store and every known view |
| `epicenter evict --work-dir <job>` | remove ONE job dir now — explicit choices bypass the GC window (dry run default; a live build's dir is refused) |
| `epicenter evict --work-dirs [--older-than 7d]` | collect stale per-job working dirs; a dir a live build has locked is never touched |
| `epicenter prune [--older-than 30d]` | age-based housekeeping of the shared build dir (policy GC, default 30d). **Dry run by default** — pass `--yes` to delete |
| `epicenter doctor` | health check with plain-language verdicts: config, wrapper, filesystem, toolchain, mtime ordering |
| `epicenter vault` | show the vault: generations (toolchain + flags), sizes, links into the build view |
| `epicenter harvest [--unit <q>] [--dry-run]` | store built unit groups from the shared build dir into the vault |
| `epicenter restore [--into <dir>] [--unit <q>] [--dry-run]` | seed a working dir from the vault (default: the shared build dir) — artifacts hard-linked, fingerprint state copied |
| `epicenter verify` | audit the vault: file sizes, canonical stamps, hash contents, dependency ordering — and name the job dirs under `work/` |
| `epicenter exec [--harvest] [--rm] [--reuse] [--target-dir [DIR]] [--id <id>] [--cwd <dir>] -- <cmd>` | run a command in a fresh per-job build dir seeded from the vault (CI/agents) |

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

## Colors

Output uses one brand green (`#92D293`) for headings and accents, dim gray for
labels, amber strictly for warnings, red only for failures — calm unless
something needs attention. Status glyphs are geometric and emoji-free:
`✓` pass · `▲` warning · `✕` failure · `◆` info. Colors turn off automatically
when output is piped or when `NO_COLOR` is set; force them in scripts with
`CLICOLOR_FORCE=1`.

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
processes**. Restore hard-links `deps/` artifacts — a thousand jobs share one
copy of every rlib — and copies the fingerprint state and build-script trees,
because Cargo rewrites those in place (a shared inode would either hit the
read-only store file or corrupt the store). Files carry one canonical
timestamp per unit group; hard links share the store's stamp, private copies
are stamped after copying. Everything is fail-open: a partial vault just means
Cargo recompiles what is missing, never a broken build.

Generations are keyed by `<rustc-release>-<commit>-<host>-<flag-digest>`: a
toolchain upgrade opens a new generation instead of invalidating one, and
`epicenter vault` marks which generation is active. (Cross-arch sharing is not
supported — one vault per platform.)

### One line for CI jobs and agents

`exec` mints a fresh build dir per job, seeds it from the vault, and runs your
command in it — no shim, no daemon, no config change:

```bash
epicenter exec -- cargo test                    # warm start, nothing kept
epicenter exec --harvest -- cargo build         # …and store the units this job produced
epicenter exec --rm --id nightly -- cargo test  # delete the job dir on success
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

The command's exit code becomes epicenter's exit code; its stdout and stderr
pass through untouched (epicenter's own frame lines go to stderr). Every job
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
epicenter stays the cache-state authority either way: config health, pruning,
ownership, diagnostics.

## License

Licensed under the [GNU General Public License v3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html)
(`GPL-3.0-or-later`). See [`LICENSE`](LICENSE).
