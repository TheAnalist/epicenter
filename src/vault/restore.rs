//! Restore: link or copy stored unit groups into a working dir.

use std::fs;
#[cfg(not(unix))]
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::fingerprint;
use crate::settings::LinkPolicy;
use crate::util;

#[cfg(not(unix))]
use super::harvest::set_stamp;
use super::identity::parity_key_of;
#[cfg(windows)]
use super::layout::require_private_windows_acl;
use super::layout::{
    check_store_trust, prepare_view_root, store_access, store_is_private, store_is_shared_mount,
    unit_name_matches, unit_package, units_dir,
};
use super::manifest::{FileEntry, UnitEntry, load_manifest};

/// Extensionless build-tree files are build-script binaries and helper
/// executables. They are copied/decompressed (never linked), so setting 0700
/// on the private view copy cannot mutate the read-only store. Out archives
/// and proc-macro objects keep their normal extension and link policy.
#[cfg(unix)]
fn needs_exec(file: &FileEntry) -> bool {
    if file.role != "build-tree" {
        return false;
    }
    let name = file.path.rsplit('/').next().unwrap_or(&file.path);
    !name.contains('.')
}

// ── restore ─────────────────────────────────────────────────────────────────

/// What one restore did.
#[derive(Debug, Default)]
pub struct RestoreReport {
    pub parity: String,
    pub target: PathBuf,
    pub units_linked: usize,
    pub units_already: usize,
    pub files_linked: usize,
    pub files_copied: usize,
    pub files_existing: usize,
    pub files_missing: usize,
    pub bytes: u64,
    pub errors: usize,
    /// Integrity failures (hash/size/owner/symlink). These abort `exec` and
    /// make `restore` exit non-zero; a merely missing unit stays fail-open.
    pub fatal_errors: usize,
    pub note: Option<String>,
}

impl RestoreReport {
    /// Merge an overlay store's restore into the primary report. Files the
    /// primary store already installed are not counted as "existing" twice.
    pub fn merge_secondary(&mut self, other: RestoreReport) {
        self.units_linked += other.units_linked;
        self.files_linked += other.files_linked;
        self.files_copied += other.files_copied;
        self.files_missing += other.files_missing;
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.errors += other.errors;
        self.fatal_errors += other.fatal_errors;
        if self.note.is_none() {
            self.note = other.note;
        }
    }
}

pub(crate) enum RestoreOutcome {
    Existing,
    Missing,
    Linked,
    Copied,
}

/// fd-relative restore on Unix: destination parents are opened with
/// openat(O_NOFOLLOW), the source inode is opened once, and the final name is
/// installed with linkat. No path component can be swapped for a symlink
/// after the check.
#[cfg(unix)]
fn restore_compressed_at(
    view_root: &Path,
    dest_rel: &Path,
    blob: &Path,
    stamp: u64,
    file: &FileEntry,
) -> Result<RestoreOutcome> {
    use flate2::read::GzDecoder;
    let parent_rel = dest_rel.parent().unwrap_or_else(|| Path::new(""));
    let dst_name = dest_rel
        .file_name()
        .with_context(|| format!("destination {} has no file name", dest_rel.display()))?;
    let parent = util::open_dir_chain_at(view_root, parent_rel)?;
    if parent.exists(dst_name)? {
        return Ok(RestoreOutcome::Existing);
    }
    let input = match util::open_file_nofollow(blob) {
        Ok(file) => file,
        Err(err) if util::is_not_found(&err) => {
            return Ok(RestoreOutcome::Missing);
        }
        Err(err) => return Err(err),
    };
    let mut tmp = parent.create_excl(dst_name, 0o600)?;
    let result = (|| -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut decoder = GzDecoder::new(input);
        util::copy_verified(
            &mut decoder,
            &mut tmp,
            file.size,
            &file.sha256,
            Path::new(&file.path),
        )?;
        if needs_exec(file) {
            tmp.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        util::set_stamp_fd(&tmp, stamp)?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = parent.unlink(dst_name);
        return Err(err);
    }
    Ok(RestoreOutcome::Copied)
}

#[cfg(not(unix))]
pub(crate) fn install_compressed_copy(
    blob: &Path,
    dst: &Path,
    stamp: u64,
    file: &FileEntry,
) -> Result<RestoreOutcome> {
    // Decompress into a private temp in the destination directory. Only this
    // operation ever removes that temp; `dst` is installed with a no-overwrite
    // link/copy, so a racing restore cannot lose its file here.
    let parent = dst.parent().unwrap_or_else(|| Path::new(""));
    let nonce = util::temp_nonce();
    let mut temp = None;
    for attempt in 0..100u32 {
        let candidate = parent.join(format!(
            ".epicenter-tmp-{}-{nonce:016x}-{attempt}",
            std::process::id()
        ));
        match util::decompress_file_verified(blob, &candidate, file.size, &file.sha256) {
            Ok(()) => {
                temp = Some(candidate);
                break;
            }
            Err(err)
                if util::io_error(&err)
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(err) if util::is_not_found(&err) => {
                // A partial vault is fail-open: Cargo rebuilds the unit.
                return Ok(RestoreOutcome::Missing);
            }
            Err(err) => return Err(err),
        }
    }
    let Some(temp) = temp else {
        anyhow::bail!(
            "could not create a temporary file next to {}",
            dst.display()
        );
    };

    if let Err(err) = set_stamp(&temp, stamp) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }

    // A hard link is an atomic no-overwrite install on every platform that
    // supports it. Fall back to an exclusive copy where links are unavailable
    // (for example FAT/exFAT).
    match fs::hard_link(&temp, dst) {
        Ok(()) => {
            let _ = fs::remove_file(&temp);
            return Ok(RestoreOutcome::Copied);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            return existing_destination(dst);
        }
        Err(_) => {}
    }

    let mut output = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            return existing_destination(dst);
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("creating {}", dst.display()));
        }
    };
    let mut input = match fs::File::open(&temp) {
        Ok(file) => file,
        Err(err) => {
            drop(output);
            let _ = fs::remove_file(dst);
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("opening {}", temp.display()));
        }
    };
    let copied = std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copying verified temporary file to {}", dst.display()));
    let flushed = copied.and_then(|_| {
        output
            .flush()
            .with_context(|| format!("flushing {}", dst.display()))
    });
    drop(input);
    drop(output);
    let result = flushed.and_then(|_| set_stamp(dst, stamp));
    if let Err(err) = result {
        let _ = fs::remove_file(dst);
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    let _ = fs::remove_file(&temp);
    Ok(RestoreOutcome::Copied)
}

#[cfg(not(unix))]
fn existing_destination(dst: &Path) -> Result<RestoreOutcome> {
    let meta = match util::metadata_nofollow(dst) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("destination {} is not a regular file", dst.display());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("inspecting raced destination {}", dst.display()));
        }
    };
    if !meta.is_file() {
        anyhow::bail!("destination {} is not a regular file", dst.display());
    }
    Ok(RestoreOutcome::Existing)
}

#[cfg(unix)]
fn restore_file_at(
    view_root: &Path,
    dest_rel: &Path,
    src: &Path,
    stamp: u64,
    file: &FileEntry,
    linkable: bool,
    link: LinkPlan,
) -> Result<RestoreOutcome> {
    let parent_rel = dest_rel.parent().unwrap_or_else(|| Path::new(""));
    let dst_name = dest_rel
        .file_name()
        .with_context(|| format!("destination {} has no file name", dest_rel.display()))?;
    let parent = util::open_dir_chain_at(view_root, parent_rel)?;
    if parent.exists(dst_name)? {
        return Ok(RestoreOutcome::Existing);
    }
    let mut source = match util::open_file_nofollow(src) {
        Ok(file) => file,
        Err(err) if util::is_not_found(&err) => {
            return Ok(RestoreOutcome::Missing);
        }
        Err(err) => return Err(err),
    };
    let meta = source.metadata()?;
    if !meta.is_file() || (!util::owned_by_us(src, &meta) && !link.read_only) {
        anyhow::bail!(
            "stored file {} is not a regular file owned by this user",
            src.display()
        );
    }
    // A writable store file must not be writable by another principal, even
    // when the unit group is private (an inherited ACE can outlive the group
    // fix). A read-only foreign store is signature-verified instead.
    #[cfg(windows)]
    if !link.read_only && util::windows_acl_is_private(src) != Some(true) {
        anyhow::bail!(
            "stored file {} DACL grants write access to another principal",
            src.display()
        );
    }
    if meta.len() != file.size {
        anyhow::bail!(
            "stored file {} size drift (recorded {}, found {})",
            src.display(),
            file.size,
            meta.len()
        );
    }
    // A hard link is only safe when the view cannot mutate the store inode:
    // the store is on a read-only mount, or the source inode is foreign and
    // carries no write bits at all.
    #[cfg(unix)]
    let foreign_immutable = {
        use std::os::unix::fs::PermissionsExt;
        !util::owned_by_us(src, &meta) && meta.permissions().mode() & 0o222 == 0
    };
    #[cfg(not(unix))]
    let foreign_immutable = false;
    let may_link = linkable && !needs_exec(file) && link.may_link(foreign_immutable);
    if may_link {
        if file.sha256.is_empty() {
            anyhow::bail!("{} has no recorded SHA-256", src.display());
        }
        let found = util::sha256_file_fd(&mut source)?;
        if found != file.sha256 {
            anyhow::bail!("{} failed its SHA-256 check", src.display());
        }
        match parent.link_fd(&source, dst_name) {
            Ok(()) => return Ok(RestoreOutcome::Linked),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(RestoreOutcome::Existing);
            }
            Err(err)
                if util::link_fallback(&err) || err.kind() == std::io::ErrorKind::Unsupported =>
            {
                // Cross-device or a filesystem without hard links: fall
                // through to a verified private copy.
            }
            Err(err) => {
                return Err(err).with_context(|| format!("linking {:?}", dst_name));
            }
        }
    }
    // Write the private copy directly at the final name with O_EXCL. The
    // destination name is created once, at the held parent fd; on any
    // integrity/stamp failure the partial file is removed. No temp-path
    // lookup is needed, which keeps this portable on non-Linux Unix.
    let mut tmp = match parent.create_excl(dst_name, 0o600) {
        Ok(tmp) => tmp,
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .map_or(false, |io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            return Ok(RestoreOutcome::Existing);
        }
        Err(err) => return Err(err),
    };
    let result = (|| -> Result<()> {
        util::copy_fd_verified(&mut source, &mut tmp, file.size, &file.sha256)?;
        if needs_exec(file) {
            use std::os::unix::fs::PermissionsExt;
            tmp.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        util::set_stamp_fd(&tmp, stamp)?;
        Ok(())
    })();
    if let Err(err) = result {
        let _ = parent.unlink(dst_name);
        return Err(err);
    }
    Ok(RestoreOutcome::Copied)
}

/// Immutable rustc outputs that may be shared by inode. Build-script
/// executables, `.rmeta`, `.d`, `.o` and other deps files are mutable.
///
/// `auto` links the large archive outputs (`.rlib`, `.a`); proc-macro
/// `.so`/`.dylib` stay private writable copies because Cargo may rewrite
/// them in place during a rebuild. The explicit `link` policy links all four.
fn is_linkable_artifact(path: &str, policy: LinkPolicy) -> bool {
    if !(path.starts_with("deps/") || path.contains("/out/")) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    match policy {
        LinkPolicy::Copy => false,
        LinkPolicy::Link => matches!(extension, Some("rlib" | "a" | "so" | "dylib")),
        LinkPolicy::Auto => matches!(extension, Some("rlib" | "a")),
    }
}

#[derive(Clone, Copy)]
struct LinkPlan {
    policy: LinkPolicy,
    read_only: bool,
    mount_read_only: bool,
    shared_mount: bool,
    private_store: bool,
}

impl LinkPlan {
    #[cfg(unix)]
    fn may_link(self, foreign_immutable: bool) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            LinkPolicy::Link => true,
            LinkPolicy::Auto => {
                self.mount_read_only
                    || foreign_immutable
                    || (self.private_store && !self.shared_mount)
            }
        }
    }

    /// Dry-run prediction: a foreign immutable source cannot be known before
    /// opening it, so only the mount/store facts are used.
    fn predicts_link(self) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            LinkPolicy::Link => {
                #[cfg(windows)]
                {
                    self.read_only || self.private_store
                }
                #[cfg(not(windows))]
                {
                    true
                }
            }
            LinkPolicy::Auto => self.mount_read_only || (self.private_store && !self.shared_mount),
        }
    }

    #[cfg(windows)]
    fn windows_link(self) -> bool {
        match self.policy {
            LinkPolicy::Copy => false,
            // An immutable mount is safe to link even when it is foreign.
            LinkPolicy::Link => self.read_only || self.private_store,
            LinkPolicy::Auto => self.mount_read_only || (self.private_store && !self.shared_mount),
        }
    }
}

/// Link matching unit groups from the vault into a working dir.
///
/// `deps/` link outputs (`.rlib`, proc-macro `.so`) are hard-linked — rustc
/// only ever replaces those atomically. Fingerprint state, build-script
/// trees and `deps/*.rmeta` become private writable copies: rustc writes
/// `.rmeta` in place, so a read-only link turns any rebuild of that unit
/// into `output file … .rmeta is not writeable`. Hard links share the
/// store's canonical stamp; private copies are stamped after copying. Never
/// overwrites a file that already exists, never touches sources, and a
/// partial vault is fine: Cargo recompiles whatever is missing.
///
/// `unit_filter` narrows by substring (`restore --unit`); `packages` narrows
/// to the project's `Cargo.lock` (`exec` passes the index it already parsed,
/// so a job never inherits every other project's units and a unit only lands
/// where the lock resolves its exact package version). `profile` narrows to
/// one build-dir profile (`exec` passes the child's profile so a debug job
/// never seeds release units). Unit names that cannot be split into package +
/// hash are kept rather than dropped (fail-open).
pub fn restore(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    packages: Option<&crate::lockfile::LockIndex>,
    dry_run: bool,
) -> Result<RestoreReport> {
    restore_with(
        view_root,
        store_root,
        unit_filter,
        packages,
        None,
        None,
        None,
        dry_run,
        LinkPolicy::Auto,
    )
}

/// Restore with an explicit link policy (`epicenter.toml`).
pub fn restore_policy(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    dry_run: bool,
    link: LinkPolicy,
) -> Result<RestoreReport> {
    restore_with(
        view_root,
        store_root,
        unit_filter,
        None,
        None,
        None,
        None,
        dry_run,
        link,
    )
}

/// Restore for a specific toolchain/layout (`exec` with a `+toolchain` or a
/// new-layout child). `layout` skips units stored in the other build-dir
/// layout; `profile` skips units stored for another Cargo profile; the plain
/// [`restore`] accepts every stored unit.
pub fn restore_with(
    view_root: &Path,
    store_root: &Path,
    unit_filter: Option<&str>,
    packages: Option<&crate::lockfile::LockIndex>,
    layout: Option<fingerprint::UnitLayout>,
    profile: Option<&str>,
    selector: Option<&str>,
    dry_run: bool,
    link: LinkPolicy,
) -> Result<RestoreReport> {
    let parity = parity_key_of(selector)?;
    let mut report = RestoreReport {
        parity: parity.clone(),
        target: view_root.to_path_buf(),
        ..Default::default()
    };
    // Verify store ownership/mode before parsing its manifest. A fresh store
    // is allowed to be absent (cold start); a present-but-unsafe one is not.
    // Already checked its not a symlink in main (cmd_restore)
    let access = store_access(store_root);
    if store_root.exists() {
        check_store_trust(store_root)?;
    }
    let link_plan = LinkPlan {
        policy: link,
        mount_read_only: access.mount_read_only,
        read_only: access.read_only,
        shared_mount: store_is_shared_mount(store_root),
        private_store: store_is_private(store_root),
    };
    let Some(manifest) = load_manifest(store_root, &parity)? else {
        report.note = Some(
            "the vault holds no units for this generation yet — run `epicenter harvest` after a build"
                .into(),
        );
        return Ok(report);
    };
    if !dry_run {
        prepare_view_root(view_root)?;
    }

    let units = units_dir(store_root, &parity);
    let generation_root = store_root.join(&parity);

    // Select units once. `already` is a pure read of the view, so it is safe
    // to decide before any worker starts.
    let mut jobs: Vec<(usize, &UnitEntry)> = Vec::new();
    for (at, entry) in manifest.units.iter().enumerate() {
        if let Some(query) = unit_filter {
            if !unit_name_matches(&entry.name, query) {
                continue;
            }
        }
        if let Some(packages) = packages {
            if let Some(package) = unit_package(&entry.name) {
                // The lock must resolve this exact version from a registry or
                // git source. Path/workspace units are project-local and are
                // never seeded from the shared vault.
                if !packages.seedable(package, entry.version.as_deref()) {
                    continue;
                }
            }
        }
        if let Some(layout) = layout {
            if entry.layout() != layout {
                continue;
            }
        }
        if let Some(profile) = profile {
            if entry.profile != profile {
                continue;
            }
        }
        // The memo's destination in the manifest is layout-agnostic.
        let already = entry
            .files
            .iter()
            .find(|file| file.path == entry.memo)
            .and_then(|file| read_small_regular(&view_root.join(&entry.profile).join(&file.dest)))
            .map(|text| text.trim() == entry.hash)
            .unwrap_or(false);
        if already {
            report.units_already += 1;
            continue;
        }
        jobs.push((at, entry));
    }

    // Two units can share fingerprint files (and a manifest is not required
    // to prove uniqueness). Give every destination to the first selected unit
    // in manifest order, so concurrent restores never write the same path.
    let mut owners: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(
            jobs.iter().map(|(_, entry)| entry.files.len()).sum(),
        );
    if !dry_run {
        for (at, entry) in &jobs {
            for file in &entry.files {
                owners.entry(dest_key(entry, file)).or_insert(*at);
            }
        }
    }

    let workers = crate::settings::copy_workers();
    let outcomes: Vec<RestoreUnitResult> = if dry_run || jobs.len() <= 1 || workers <= 1 {
        jobs.iter()
            .map(|(at, entry)| {
                restore_unit(
                    view_root,
                    &units,
                    &generation_root,
                    *at,
                    entry,
                    None,
                    dry_run,
                    link_plan,
                )
            })
            .collect()
    } else {
        crate::settings::copy_pool().install(|| {
            jobs.par_iter()
                .map(|(at, entry)| {
                    restore_unit(
                        view_root,
                        &units,
                        &generation_root,
                        *at,
                        entry,
                        Some(&owners),
                        false,
                        link_plan,
                    )
                })
                .collect()
        })
    };

    for outcome in outcomes {
        report.files_existing += outcome.files_existing;
        report.files_missing += outcome.files_missing;
        report.files_linked += outcome.files_linked;
        report.files_copied += outcome.files_copied;
        report.bytes = report.bytes.saturating_add(outcome.bytes);
        report.errors += outcome.errors;
        report.fatal_errors += outcome.fatal_errors;
        if outcome.touched {
            report.units_linked += 1;
        }
        for message in outcome.messages {
            eprintln!("{message}");
        }
    }
    Ok(report)
}

fn dest_key(entry: &UnitEntry, file: &FileEntry) -> String {
    format!("{}/{}", entry.profile, file.dest)
}

#[derive(Default)]
struct RestoreUnitResult {
    files_existing: usize,
    files_missing: usize,
    files_linked: usize,
    files_copied: usize,
    bytes: u64,
    errors: usize,
    fatal_errors: usize,
    touched: bool,
    messages: Vec<String>,
}

/// Restore one unit group. Runs on a worker; every mutable report is local
/// and merged in manifest order by the caller.
fn restore_unit(
    view_root: &Path,
    units: &Path,
    generation_root: &Path,
    at: usize,
    entry: &UnitEntry,
    owners: Option<&std::collections::HashMap<String, usize>>,
    dry_run: bool,
    link: LinkPlan,
) -> RestoreUnitResult {
    let mut out = RestoreUnitResult::default();

    // A writable store's unit group must be owner-only too: a private root with
    // a permissive child would let another principal replace the artifacts the
    // manifest is about to install. A read-only foreign store is signature-
    // verified instead.
    #[cfg(windows)]
    if !link.read_only {
        if let Err(err) = require_private_windows_acl(&units.join(&entry.name), "unit group") {
            out.fatal_errors += 1;
            out.messages.push(format!("restore: {err:#}"));
            return out;
        }
    }

    for file in &entry.files {
        if let Some(owners) = owners {
            if owners
                .get(&dest_key(entry, file))
                .is_some_and(|owner| *owner != at)
            {
                // Another selected unit owns this destination; it will land
                // there exactly once, in manifest order, just as the serial
                // walk would have left it.
                out.files_existing += 1;
                continue;
            }
        }
        // Both components were validated by Manifest::validate; keep the
        // join explicit and reject any symlink in the destination chain.
        let dest_rel = Path::new(&entry.profile).join(&file.dest);
        let dst = view_root.join(&dest_rel);
        match util::metadata_nofollow(&dst) {
            Ok(_) => {
                out.files_existing += 1;
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                out.errors += 1;
                out.fatal_errors += 1;
                out.messages.push(format!(
                    "restore: refusing symlink/reparse destination {}",
                    dst.display()
                ));
                continue;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                out.errors += 1;
                out.messages
                    .push(format!("restore: inspecting {}: {err}", dst.display()));
                continue;
            }
        }
        // Only immutable rustc outputs may share the store inode. Everything
        // else (`.rmeta`, build-script executables, `.d`, object files) is a
        // private verified copy: rustc/cargo/build scripts write those in
        // place, and a read-only link would break the rebuild.
        let linkable = is_linkable_artifact(&file.path, link.policy);
        let shared = linkable;
        if dry_run {
            out.touched = true;
            if shared && link.predicts_link() && file.object.is_none() {
                out.files_linked += 1;
            } else {
                out.files_copied += 1;
            }
            out.bytes = out.bytes.saturating_add(file.size);
            continue;
        }
        // The Windows restore path is path-based, so create and hold every
        // destination parent before either the compressed or the uncompressed
        // installer opens the final name. The guard stays alive through the
        // whole loop iteration, including decompression.
        #[cfg(not(unix))]
        let _dir_guard = match dest_rel.parent() {
            Some(parent) => match util::create_dir_chain_nofollow(view_root, parent) {
                Ok(guard) => guard,
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: creating {}: {err}", parent.display()));
                    continue;
                }
            },
            None => util::DirChainGuard::default(),
        };
        if let Some(object) = &file.object {
            let blob = generation_root.join(object);
            #[cfg(unix)]
            let result = restore_compressed_at(view_root, &dest_rel, &blob, entry.stamp, file);
            #[cfg(not(unix))]
            let result = install_compressed_copy(&blob, &dst, entry.stamp, file);
            match result {
                Ok(RestoreOutcome::Existing) => out.files_existing += 1,
                Ok(RestoreOutcome::Missing) => out.files_missing += 1,
                Ok(RestoreOutcome::Copied) => {
                    out.files_copied += 1;
                    out.bytes = out.bytes.saturating_add(file.size);
                    out.touched = true;
                }
                Ok(RestoreOutcome::Linked) => {
                    out.files_linked += 1;
                    out.bytes = out.bytes.saturating_add(file.size);
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
            continue;
        }
        let src = units.join(&entry.name).join(&file.path);
        let rel = Path::new(&entry.name).join(&file.path);
        #[cfg(unix)]
        {
            if let Err(err) = util::check_regular_chain(&units, &rel) {
                out.errors += 1;
                out.fatal_errors += 1;
                out.messages
                    .push(format!("restore: writing {}: {err:#}", dst.display()));
                continue;
            }
            match restore_file_at(
                view_root,
                &dest_rel,
                &src,
                entry.stamp,
                file,
                linkable,
                link,
            ) {
                Ok(RestoreOutcome::Existing) => {
                    out.files_existing += 1;
                }
                Ok(RestoreOutcome::Missing) => {
                    out.files_missing += 1;
                }
                Ok(RestoreOutcome::Linked) => {
                    out.files_linked += 1;
                    out.bytes = out.bytes.saturating_add(file.size);
                    out.touched = true;
                }
                Ok(RestoreOutcome::Copied) => {
                    out.files_copied += 1;
                    out.bytes = out.bytes.saturating_add(file.size);
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
            continue;
        }
        #[cfg(not(unix))]
        {
            match util::metadata_nofollow(&src) {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Fail-open: a partial vault means Cargo rebuilds it.
                    out.files_missing += 1;
                    continue;
                }
                Err(err) => {
                    out.errors += 1;
                    out.messages
                        .push(format!("restore: inspecting {}: {err}", src.display()));
                    continue;
                }
            }
            let result = if shared && link.windows_link() {
                util::check_regular_chain(&units, &rel)
                    .and_then(|_| verify_store_file(&src, file, link.read_only))
                    .and_then(|_| match fs::hard_link(&src, &dst) {
                        Ok(()) => Ok(()),
                        // Cross-volume or a filesystem without links: a
                        // verified private copy is the fallback.
                        Err(_) => {
                            install_private_copy(&src, &dst, entry.stamp, file, link.read_only)
                        }
                    })
            } else {
                util::check_regular_chain(&units, &rel).and_then(|_| {
                    install_private_copy(&src, &dst, entry.stamp, file, link.read_only)
                })
            };
            match result {
                Ok(()) => {
                    if shared {
                        out.files_linked += 1;
                    } else {
                        out.files_copied += 1;
                    }
                    out.bytes = out.bytes.saturating_add(file.size);
                    out.touched = true;
                }
                Err(err) => {
                    out.errors += 1;
                    out.fatal_errors += 1;
                    out.messages
                        .push(format!("restore: writing {}: {err:#}", dst.display()));
                }
            }
        }
    }

    out
}

#[cfg(not(unix))]
fn verify_store_file(src: &Path, file: &FileEntry, allow_foreign: bool) -> Result<()> {
    let meta = match util::metadata_nofollow(src) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
            anyhow::bail!("{} is not a regular file", src.display());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting stored file {}", src.display()));
        }
    };
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", src.display());
    }
    if !util::owned_by_us(src, &meta) && !allow_foreign {
        anyhow::bail!("{} is owned by another user", src.display());
    }
    if meta.len() != file.size {
        anyhow::bail!(
            "{} size drift (recorded {}, found {})",
            src.display(),
            file.size,
            meta.len()
        );
    }
    if file.sha256.is_empty() {
        anyhow::bail!("{} has no recorded SHA-256", src.display());
    }
    let found = util::sha256_file(src)?;
    if found != file.sha256 {
        anyhow::bail!("{} failed its SHA-256 check", src.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_private_copy(
    src: &Path,
    dst: &Path,
    stamp: u64,
    file: &FileEntry,
    allow_foreign: bool,
) -> Result<()> {
    // Create the destination directly (O_EXCL semantics). A temp file plus
    // hard_link fails on volumes/filesystems without links, including
    // cross-device and read-only vaults.
    let copy = if allow_foreign {
        util::copy_file_verified_unowned
    } else {
        util::copy_file_verified
    };
    copy(src, dst, file.size, &file.sha256)?;
    set_stamp(dst, stamp)?;
    // Private copies stay writable: rustc/cargo rewrite .rmeta and
    // fingerprint state in place. Only shared `deps/` artifacts are 0444.
    Ok(())
}

/// Read a small regular file without following a symlink.
pub(crate) fn read_small_regular(path: &Path) -> Option<String> {
    util::read_small_text(path, 4 * 1024 * 1024).ok()
}
