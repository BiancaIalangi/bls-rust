use std::sync::Once;

use crate::bls_api::blsInit;
use crate::constants::MCLBN_COMPILED_TIME_VAR;

enum CurveType {
    BLS12_381 = 5,
}

// Used to call blsInit only once.
pub static INIT: Once = Once::new();
pub fn init_library() {
    init(CurveType::BLS12_381);
}

fn init(curve_type: CurveType) -> bool {
    unsafe { blsInit(curve_type as usize, MCLBN_COMPILED_TIME_VAR) == 0 }
}
