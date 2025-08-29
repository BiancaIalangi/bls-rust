use crate::bls_api::mclBnGT_isEqual;
use crate::constants::MCLBN_FP_UNIT_SIZE;
use crate::init::{init_library, INIT};

/// GT type
#[derive(Default, Debug, Clone, Copy, Eq)]
#[repr(C)]
pub struct GT {
    d0: [u64; MCLBN_FP_UNIT_SIZE * 4],
    d1: [u64; MCLBN_FP_UNIT_SIZE * 4],
    d2: [u64; MCLBN_FP_UNIT_SIZE * 4],
}

impl PartialEq for GT {
    /// return true if `self` is equal to `rhs`
    fn eq(&self, rhs: &Self) -> bool {
        INIT.call_once(init_library);
        unsafe { mclBnGT_isEqual(self, rhs) == 1 }
    }
}
