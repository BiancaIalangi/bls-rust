use crate::constants::MCLBN_FP_UNIT_SIZE;
use crate::init::{init_library, INIT};
use crate::{bls_api::*, BlsError};

/// public key type
#[derive(Default, Debug, Clone, Copy, Eq)]
#[repr(C)]
pub struct G2 {
    pub x: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
    pub y: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
    pub z: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
}

impl PartialEq for G2 {
    /// return true if `self` is equal to `rhs`
    fn eq(&self, rhs: &Self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsPublicKeyIsEqual(self, rhs) == 1 }
    }
}

impl G2 {
    /// Adds the given `public_key` to `self`.
    ///
    /// This function performs an addition operation on the `G2` element represented by `self`
    /// and the provided `public_key`.
    ///
    /// # Arguments
    /// * `public_key` - A `G2` element to be added to `self`.
    pub fn add_assign(&mut self, public_key: G2) {
        INIT.call_once(init_library);
        unsafe {
            blsPublicKeyAdd(self, &public_key);
        }
    }

    /// Checks if the `G2` element has a valid order.
    ///
    /// This function verifies whether the `G2` element represented by `self`
    /// is of a valid order as per the cryptographic library's requirements.
    ///
    /// # Returns
    /// * `true` if the `G2` element has a valid order.
    /// * `false` otherwise.
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsPublicKeyIsValidOrder(self) == 1 }
    }

    /// Sets the `G2` element from a string representation.
    ///
    /// # Arguments
    /// * `s` - A string slice containing the `G2` element in base 10.
    ///
    /// # Panics
    /// May panic if initialization fails or the string is invalid.
    pub fn set_str(&mut self, s: &str) {
        INIT.call_once(init_library);
        unsafe { mclBnG2_setStr(self, s.as_ptr(), s.len(), 10) };
    }

    /// Deserializes a `G2` element from a byte slice.
    ///
    /// # Arguments
    /// * `buf` - A byte slice containing the serialized `G2` element.
    ///
    /// # Returns
    /// `true` if deserialization is successful and the buffer length matches, otherwise `false`.
    pub fn deserialize_g2(&mut self, buf: &[u8]) -> bool {
        INIT.call_once(init_library);
        let n = unsafe { mclBnG2_deserialize(self, buf.as_ptr(), buf.len()) };

        n > 0 && n == buf.len()
    }

    /// Checks if the `G2` element is the point at infinity (zero element).
    ///
    /// This function determines whether the `G2` element represented by `self`
    /// is the zero element, which is the identity element in the group.
    ///
    /// # Returns
    /// `true` if the `G2` element is the zero element, otherwise `false`.
    pub fn is_zero(&self) -> bool {
        unsafe { mclBnG2_isZero(self) == 1 }
    }

    /// Checks if the `G2` element is valid.
    ///
    /// This function determines whether the `G2` element represented by `self`
    /// is valid according to the cryptographic library's requirements.
    ///
    /// # Returns
    /// `true` if the `G2` element is valid, otherwise `false`.
    pub fn is_valid(&self) -> bool {
        unsafe { mclBnG2_isValid(self) == 1 }
    }

    /// verify the correctness whenever public key setter is used
    /// * `verify` - enable if true (default off)
    pub fn verify_public_key_order(verify: bool) {
        unsafe { blsPublicKeyVerifyOrder(verify as i32) }
    }

    /// return serialized byte array
    pub fn serialize(&self) -> Result<Vec<u8>, BlsError> {
        INIT.call_once(init_library);

        let size = unsafe { mclBn_getFpByteSize() * 2 };
        let mut buf = vec![0u8; size];

        let n = unsafe { blsPublicKeySerialize(buf.as_mut_ptr(), size, self) };
        if n == 0 {
            return Err(BlsError::SerializeError);
        }

        buf.truncate(n);

        Ok(buf)
    }

    pub fn deserialize(&mut self, buf: &[u8]) -> bool {
        INIT.call_once(init_library);
        let n = unsafe { blsPublicKeyDeserialize(self, buf.as_ptr(), buf.len()) };

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
}
