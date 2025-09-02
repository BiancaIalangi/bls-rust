use std::collections::HashSet;

use crate::constants::{MCLBN_FP_UNIT_SIZE, MSG_SIZE};
use crate::g2::G2;
use crate::init::{init_library, INIT};
use crate::{bls_api::*, BlsError};

/// signature type
#[derive(Default, Debug, Clone, Copy, Eq)]
#[repr(C)]
pub struct G1 {
    pub x: [u64; MCLBN_FP_UNIT_SIZE],
    pub y: [u64; MCLBN_FP_UNIT_SIZE],
    pub z: [u64; MCLBN_FP_UNIT_SIZE],
}

impl PartialEq for G1 {
    /// return true if `self` is equal to `rhs`
    fn eq(&self, rhs: &Self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSignatureIsEqual(self, rhs) == 1 }
    }
}

impl G1 {
    /// return true if `self` is valid signature of `msg` for `public_key`
    pub fn verify(&self, public_key: G2, msg: &[u8]) -> bool {
        INIT.call_once(init_library);
        unsafe { blsVerify(self, &public_key, msg.as_ptr(), msg.len()) == 1 }
    }

    /// return true if `self` is a valid signature of `msg` for `public keys`
    /// * `public_keys` - array of public key
    /// * `msg` - message
    pub fn fast_aggregate_verify(&self, public_keys: &[G2], msg: &[u8]) -> bool {
        INIT.call_once(init_library);
        if public_keys.is_empty() {
            return false;
        }

        unsafe {
            blsFastAggregateVerify(
                self,
                public_keys.as_ptr(),
                public_keys.len(),
                msg.as_ptr(),
                msg.len(),
            ) == 1
        }
    }

    /// add a signature to `self`
    pub fn add_assign(&mut self, signature: G1) {
        INIT.call_once(init_library);
        unsafe {
            blsSignatureAdd(self, &signature);
        }
    }

    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSignatureIsValidOrder(self) == 1 }
    }

    /// set the aggregated signature of `sigs`
    /// * `sigs` - signatures to be aggregated
    pub fn aggregate(&mut self, sigs: &[G1]) {
        INIT.call_once(init_library);
        unsafe {
            blsAggregateSignature(self, sigs.as_ptr(), sigs.len());
        }
    }

    fn inner_aggregate_verify(&self, pubs: &[G2], msgs: &[u8], check_message: bool) -> bool {
        INIT.call_once(init_library);
        let n = pubs.len();
        if n == 0 || n * MSG_SIZE != msgs.len() {
            return false;
        }
        if check_message && !are_all_msg_different(msgs, MSG_SIZE) {
            return false;
        }
        unsafe { blsAggregateVerifyNoCheck(self, pubs.as_ptr(), msgs.as_ptr(), MSG_SIZE, n) == 1 }
    }

    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    /// * Note - this function does not call `are_all_msg_different`
    pub fn aggregate_verify_no_check(&self, pubs: &[G2], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, false)
    }

    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    pub fn aggregate_verify(&self, pubs: &[G2], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, true)
    }

    /// Checks if the `G1` element is the point at infinity (zero element).
    ///
    /// This function determines whether the `G1` element represented by `self`
    /// is the zero element, which is the identity element in the group.
    ///
    /// # Returns
    /// `true` if the `G1` element is the zero element, otherwise `false`.
    pub fn is_zero(&self) -> bool {
        unsafe { mclBnG1_isZero(self) == 1 }
    }

    /// Checks if the `G1` element is valid.
    ///
    /// This function determines whether the `G1` element represented by `self`
    /// is valid according to the cryptographic library's requirements.
    ///
    /// # Returns
    /// `true` if the `G1` element is valid, otherwise `false`.
    pub fn is_valid(&self) -> bool {
        unsafe { mclBnG1_isValid(self) == 1 }
    }

    /// verify the correctness whenever signature setter is used
    /// * `verify` - enable if true (default off)
    pub fn verify_signature_order(verify: bool) {
        unsafe { blsSignatureVerifyOrder(verify as i32) }
    }

    /// return true if `buf` is deserialized successfully
    /// * `buf` - serialized data by `serialize`
    pub fn deserialize(&mut self, buf: &[u8]) -> bool {
        INIT.call_once(init_library);
        let n = unsafe { blsSignatureDeserialize(self, buf.as_ptr(), buf.len()) };

        n > 0 && n == buf.len()
    }

    /// return deserialized `buf`
    pub fn from_serialized(buf: &[u8]) -> Result<Self, BlsError> {
        let mut v = Self::default();
        if v.deserialize(buf) {
            return Ok(v);
        }

        Err(crate::BlsError::InvalidData)
    }

    /// return serialized byte array
    pub fn serialize(&self) -> Result<Vec<u8>, BlsError> {
        INIT.call_once(init_library);

        let size = unsafe { mclBn_getFpByteSize() };
        let mut buf = vec![0u8; size];

        let n = unsafe { blsSignatureSerialize(buf.as_mut_ptr(), size, self) };
        if n == 0 {
            return Err(BlsError::SerializeError);
        }

        buf.truncate(n);

        Ok(buf)
    }
}

/// return true if `size`-byte splitted `msgs` are different each other
/// * `msgs` - an array that `size`-byte messages are concatenated
/// * `size` - length of one message
pub fn are_all_msg_different(msgs: &[u8], size: usize) -> bool {
    let n = msgs.len() / size;
    assert!(msgs.len() == n * size);

    let mut set = HashSet::new();
    for i in 0..n {
        let msg = &msgs[i * size..(i + 1) * size];
        if set.contains(msg) {
            return false;
        }
        set.insert(msg);
    }

    true
}
