//! Durability policy for clove1db writes.

/// How aggressively clove1db flushes data to durable storage.
///
/// Both modes always use atomic tmp→rename for sidecar files (migration JSON, blobs)
/// so a crash never leaves a final path half-written with NULs.
///
/// - [`Strict`](DurabilityMode::Strict) (default): `sync_all` on sidecar files and
///   `redb::Durability::Immediate` on database commits.
/// - [`Fast`](DurabilityMode::Fast): skip fsync / Immediate for throughput; still atomic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DurabilityMode {
    #[default]
    Strict,
    Fast,
}

impl DurabilityMode {
    #[inline]
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    #[inline]
    pub fn is_fast(self) -> bool {
        matches!(self, Self::Fast)
    }
}

/// Default max entries per redb commit batch (writes + deletes).
pub const DEFAULT_MAX_COMMIT_BATCH_ENTRIES: usize = 512;
