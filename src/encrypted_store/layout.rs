//! Where things are in an encrypted database file.
//!
//! ```text
//! [file header      2048 B]  lock slot A (512), lock slot B (512, reserved), random filler
//! [redb header area 2048 B]  four sealed 512 B pieces (see backend.rs)
//! [block 0][block 1] ...     each: nonce | 4096 B of redb pages, sealed | tag
//! ```
//! redb's first 4096 bytes are its header page, which is stored as the four pieces; every
//! later 4096-byte page of redb is one block.

/// redb's page size, fixed in the version this is built on.
pub const PAGE: usize = 4096;
pub const FILE_HEADER_LEN: u64 = 2048;
pub const SLOT_LEN: usize = 512;
pub const PIECE_LEN: usize = 512;
pub const PIECES_LEN: u64 = 4 * PIECE_LEN as u64;
/// Physical offset of block 0.
pub const DATA_BASE: u64 = FILE_HEADER_LEN + PIECES_LEN;
/// The part of redb's address space that is its header page.
pub const LOGICAL_HEADER: u64 = PAGE as u64;
/// The bytes redb really uses of its header page.
pub const REDB_HEADER_LEN: usize = 320;

/// Block geometry for one cipher: `overhead` is the nonce and tag it adds.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub overhead: usize,
}

impl Geometry {
    pub fn stride(&self) -> usize {
        PAGE + self.overhead
    }

    /// Physical offset of block `index`.
    pub fn block_offset(&self, index: u64) -> u64 {
        DATA_BASE + index * self.stride() as u64
    }

    /// redb's length for a file that is `physical` bytes long: 0 until the header area exists,
    /// then the header page plus whole blocks. A torn partial block at the end is ignored.
    pub fn logical_len(&self, physical: u64) -> u64 {
        if physical < DATA_BASE {
            return 0;
        }
        LOGICAL_HEADER + ((physical - DATA_BASE) / self.stride() as u64) * PAGE as u64
    }

    /// Physical length for a redb length (zero, or the header page plus whole pages).
    pub fn physical_len(&self, logical: u64) -> Option<u64> {
        if logical == 0 {
            return Some(FILE_HEADER_LEN);
        }
        if logical < LOGICAL_HEADER || logical % PAGE as u64 != 0 {
            return None;
        }
        Some(DATA_BASE + ((logical - LOGICAL_HEADER) / PAGE as u64) * self.stride() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip_and_partial_blocks_are_ignored() {
        for overhead in [28usize, 40] {
            let g = Geometry { overhead };
            assert_eq!(g.logical_len(0), 0);
            assert_eq!(g.logical_len(FILE_HEADER_LEN), 0);
            assert_eq!(g.logical_len(DATA_BASE - 1), 0);
            assert_eq!(g.logical_len(DATA_BASE), 4096);
            for pages in [0u64, 1, 2, 255, 256, 100_000] {
                let logical = LOGICAL_HEADER + pages * PAGE as u64;
                let physical = g.physical_len(logical).unwrap();
                assert_eq!(g.logical_len(physical), logical);
                assert_eq!(g.logical_len(physical + g.stride() as u64 - 1), logical, "torn tail");
                assert_eq!(g.logical_len(physical + g.stride() as u64), logical + PAGE as u64);
            }
            assert_eq!(g.physical_len(0), Some(FILE_HEADER_LEN));
            assert_eq!(g.physical_len(100), None);
            assert_eq!(g.physical_len(4097), None);
            assert_eq!(g.block_offset(0), DATA_BASE);
            assert_eq!(g.block_offset(3), DATA_BASE + 3 * (4096 + overhead as u64));
        }
    }

    #[test]
    fn the_header_pieces_and_slots_fit_their_areas() {
        assert_eq!(DATA_BASE % 4096, 0);
        assert!(2 * (32 + 40 + 32) <= SLOT_LEN, "both locks fit one slot for every cipher");
    }
}
