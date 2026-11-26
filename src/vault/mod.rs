//! The vault: a durable store of Cargo unit groups, addressed by Cargo's
//! own fingerprint hashes.
//!
//! A *unit group* is exactly what Cargo needs to consider one built unit
//! fresh: the 16-hex fingerprint hash file, the serialized `Fingerprint`
//! JSON, the binary dep-info, and the unit's artifacts (`deps/…`, and the
//! `build/<anchor>/…` tree for build-script units). The vault keeps one
//! directory per generation, where a generation is one toolchain plus one
//! flag environment (the *parity key*):
//!
//! ```text
//! {cargo-cache-home}/epicenter/
//!   store/<parity-key>/
//!     manifest.json                file list, sizes, canonical stamps
//!     units/<pkg>-<unit-hash>/     one unit group
//!       <memo-file>                the authoritative 16-hex hash
//!       <memo-file>.json           the serialized Fingerprint
//!       dep-<memo-file>            EncodedDepInfo (mandatory for freshness)
//!       deps/…  build/…            artifacts, as the profile dir holds them
//!   build/…                        the shared working dir (a disposable view)
//! ```
//!
//! Timestamps are the only lever besides the hash in Cargo's freshness
//! check, so every file of a unit group carries ONE canonical second
//! (`stamp`): the ceiling of the group's metadata output (`.rmeta`) when it
//! has one — the moment dependents can compile against it — else of its
//! newest file, and always ≥ every dependency's stamp (harvest clamps the
//! store). Restore never stamps hard links: they share the store's inode,
//! and a `touch` on a restored file would rewrite the store itself.

mod compact;
mod generations;
mod harvest;
mod identity;
mod import;
mod keys;
mod layout;
mod manifest;
mod overlap;
mod restore;
mod verify;

#[cfg(test)]
mod tests;

pub use compact::{CompactReport, compact};
pub use generations::{
    GenerationInfo, StoredUnit, drop_units, generation_unit_names, generations, stored_unit_rustc,
    stored_units,
};
pub use harvest::{HarvestReport, HarvestTrust, harvest, harvest_with, harvest_with_trust};
pub use identity::{
    Toolchain, parity_key, parity_key_of, toolchain, toolchain_install_time,
    toolchain_install_time_of,
};
pub use import::{
    ImportFile, ImportReport, ImportSource, ImportUnit, import_units, missing_import_units,
};
pub use keys::PUBKEY_FILE;
pub use layout::{
    drop_generation, generation_names, store_accepts_imports, sweep_store_debris, units_dir,
};
pub use manifest::{FileEntry, Manifest, UnitEntry};
pub use overlap::{OverlapPackage, OverlapUnit, overlap};
pub use restore::{RestoreReport, restore, restore_policy, restore_with};
pub use verify::{VerifyReport, verify};

pub use crate::paths::{STORE_MARKER, set_store_override, store_root};

pub(crate) use generations::link_count;
#[cfg(test)]
pub(crate) use identity::flags_digest;
pub(crate) use identity::flags_digest_of;
pub(crate) use keys::{hex_decode, hex_encode};
pub(crate) use layout::{check_store_trust, store_is_shared_mount};

#[cfg(test)]
pub(crate) use harvest::{ceil_secs, set_stamp};
#[cfg(test)]
pub(crate) use keys::{load_or_migrate_signing_key, read_key_file, write_new_key_file};
#[cfg(test)]
pub(crate) use layout::{GENERATION_MARKER, manifest_path};
#[cfg(test)]
pub(crate) use manifest::{load_manifest, load_manifest_at, manifest_mac, save_manifest};
#[cfg(all(test, not(unix)))]
pub(crate) use restore::{RestoreOutcome, install_compressed_copy};
#[cfg(test)]
pub(crate) use verify::{AuditCtx, BlobCheck, unique_blobs};
