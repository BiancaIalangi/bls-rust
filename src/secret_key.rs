use crate::bls_api::*;
use crate::constants::MCLBN_FR_UNIT_SIZE;
use crate::g1::G1;
use crate::g2::G2;
use crate::init::{init_library, INIT};
use crate::BlsError;

/// secret key type
#[derive(Default, Debug, Clone, Copy, Eq)]
#[repr(C)]
pub struct SecretKey {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

impl PartialEq for SecretKey {
    /// return true if `self` is equal to `rhs`
    fn eq(&self, rhs: &Self) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSecretKeyIsEqual(self, rhs) == 1 }
    }
}

impl SecretKey {
    /// init secret key by CSPRNG
    pub fn set_by_csprng(&mut self) {
        INIT.call_once(init_library);
        unsafe { blsSecretKeySetByCSPRNG(self) }
        let ret = unsafe { mclBnFr_isZero(self) };
        if ret == 1 {
            panic!("zero secretkey")
        }
    }

    /// set hexadecimal string `s` to `self`
    pub fn set_hex_str(&mut self, s: &str) -> bool {
        INIT.call_once(init_library);
        unsafe { blsSecretKeySetHexStr(self, s.as_ptr(), s.len()) == 0 }
    }

    /// return the secret key set by hexadecimal string `s`
    pub fn from_hex_str(s: &str) -> Result<SecretKey, BlsError> {
        let mut v = SecretKey::default();
        if v.set_hex_str(s) {
            return Ok(v);
        }
        Err(BlsError::InvalidData)
    }

    /// return the public key corresponding to `self`
    pub fn get_public_key(&self) -> G2 {
        INIT.call_once(init_library);
        let mut v = G2::default();
        unsafe {
            blsGetPublicKey(&mut v, self);
        }
        v
    }

    /// return the signature of `msg`
    /// * `msg` - message
    pub fn sign(&self, msg: &[u8]) -> G1 {
        INIT.call_once(init_library);
        let mut v = G1::default();
        unsafe { blsSign(&mut v, self, msg.as_ptr(), msg.len()) }
        v
    }

    /// return true if `buf` is deserialized successfully
    /// * `buf` - serialized data by `serialize`
    pub fn deserialize(&mut self, buf: &[u8]) -> bool {
        INIT.call_once(init_library);

        let n = unsafe { blsSecretKeyDeserialize(self, buf.as_ptr(), buf.len()) };
        n > 0 && n == buf.len()
    }

    /// return deserialized `buf`
    pub fn from_serialized(buf: &[u8]) -> Result<Self, crate::BlsError> {
        let mut v = Self::default();
        if v.deserialize(buf) {
            return Ok(v);
        }

        Err(crate::BlsError::InvalidData)
    }

    /// return serialized byte array
    pub fn serialize(&self) -> Result<Vec<u8>, BlsError> {
        INIT.call_once(init_library);

        let size = unsafe { mclBn_getFrByteSize() };
        let mut buf = vec![0u8; size];

        let n = unsafe { blsSecretKeySerialize(buf.as_mut_ptr(), size, self) };
        if n == 0 {
            return Err(BlsError::SerializeError);
        }

        buf.truncate(n);

        Ok(buf)
    }
}
