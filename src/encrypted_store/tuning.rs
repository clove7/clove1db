//! Speed settings of the whole-database encryption layer. They change how fast the layer works, never what is on disk: a file
//! written with any setting opens with any other.

/// How the encrypted file layer spends threads and memory. Use it with [`crate::storage::DatabaseConfig::encryption_tuning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionTuning {
    /// Keep the pages of a commit in memory and seal them together, on several threads, when the commit is synced (on by
    /// default). A commit smaller than 64 pages is sealed on the calling thread, and at most 4 MiB are held at a time: when
    /// that is reached the pages are sealed and written without waiting for the sync. A commit is never reported as done
    /// before all its pages are written and synced.
    pub parallel_seal: bool,
    /// The most threads, the calling thread included, one sealing step may use. `1` never starts a helper
    /// thread. The default is 4; it is never more than the processor offers.
    pub threads: usize,
}

impl EncryptionTuning {
    /// Parallel sealing on, 4 threads.
    pub const DEFAULT: EncryptionTuning = EncryptionTuning { parallel_seal: true, threads: 4 };

    /// The settings with parallel sealing off: every page is sealed and written at once, on one thread.
    pub const OFF: EncryptionTuning = EncryptionTuning { parallel_seal: false, threads: 1 };
}

impl Default for EncryptionTuning {
    fn default() -> Self {
        EncryptionTuning::DEFAULT
    }
}
