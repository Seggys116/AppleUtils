//! In-process APFS write primitives for offline repair.
//!
//! Checkpoint append handles real macOS descriptor/data rings, not the
//! synthetic two-entry maps in `apfs_update`. A node split is out of scope.

pub mod btree;
pub mod checkpoint;
pub mod disc;
pub mod object;
pub mod omap;
pub mod spaceman;
