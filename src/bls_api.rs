use crate::g1::G1;
use crate::g2::G2;
use crate::gt::GT;
use crate::secret_key::SecretKey;

unsafe extern "C" {
    pub fn blsInit(curve: usize, compiledTimeVar: usize) -> i32;

    pub fn mclBn_getFrByteSize() -> usize;
    pub fn mclBn_getFpByteSize() -> usize;
    pub fn mclBnG2_setStr(x: *mut G2, buf: *const u8, buf_size: usize, io_mode: i32) -> i32;
    pub fn mclBnG2_deserialize(x: *mut G2, buf: *const u8, buf_size: usize) -> usize;
    pub fn mclBnG2_isZero(x: *const G2) -> u8;
    pub fn mclBnG2_isValid(x: *const G2) -> u8;

    pub fn mclBnG1_isZero(x: *const G1) -> u8;
    pub fn mclBnG1_isValid(x: *const G1) -> u8;

    pub fn blsSecretKeySetByCSPRNG(x: *mut SecretKey);
    pub fn blsSecretKeySetHexStr(x: *mut SecretKey, buf: *const u8, buf_size: usize) -> i32;
    pub fn blsGetPublicKey(y: *mut G2, x: *const SecretKey);
    pub fn blsSignatureVerifyOrder(do_verify: i32);
    pub fn blsSignatureIsValidOrder(sig: *const G1) -> i32;
    pub fn blsPublicKeyVerifyOrder(do_verify: i32);
    pub fn blsPublicKeyIsValidOrder(public_key: *const G2) -> i32;

    pub fn blsSign(sig: *mut G1, secret_key: *const SecretKey, msg: *const u8, msg_len: usize);
    pub fn blsVerify(sig: *const G1, public_key: *const G2, msg: *const u8, msg_len: usize) -> i32;

    // pub fn blsMultiVerifyFinal(e: *const GT, sig: *const G2) -> i32;
    pub fn blsAggregateSignature(aggregate_sig: *mut G1, signature_vec: *const G1, n: usize);
    pub fn blsFastAggregateVerify(
        sig: *const G1,
        public_keys: *const G2,
        n: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> i32;
    pub fn blsAggregateVerifyNoCheck(
        sig: *const G1,
        public_keys: *const G2,
        messages: *const u8,
        messages_len: usize,
        n: usize,
    ) -> i32;

    pub fn blsSecretKeyIsEqual(lhs: *const SecretKey, rhs: *const SecretKey) -> i32;
    pub fn blsPublicKeyIsEqual(lhs: *const G2, rhs: *const G2) -> i32;
    pub fn blsSignatureIsEqual(lhs: *const G1, rhs: *const G1) -> i32;

    pub fn blsSecretKeySerialize(buf: *mut u8, max_buf_len: usize, x: *const SecretKey) -> usize;
    pub fn blsPublicKeySerialize(buf: *mut u8, max_buf_len: usize, x: *const G2) -> usize;
    pub fn blsSignatureSerialize(buf: *mut u8, max_buf_len: usize, x: *const G1) -> usize;

    pub fn blsSecretKeyDeserialize(x: *mut SecretKey, buf: *const u8, buf_len: usize) -> usize;
    pub fn blsPublicKeyDeserialize(x: *mut G2, buf: *const u8, buf_len: usize) -> usize;
    pub fn blsSignatureDeserialize(x: *mut G1, buf: *const u8, buf_len: usize) -> usize;

    pub fn blsPublicKeyAdd(public_key_1: *mut G2, public_key_2: *const G2);
    pub fn blsSignatureAdd(signature_1: *mut G1, signature_2: *const G1);
    pub fn mclBnFr_isZero(secret_key: *const SecretKey) -> i32;

    // pub fn mclBnGT_mul(z: *mut GT, x: *const GT, y: *const GT);
    pub fn mclBnGT_isEqual(lhs: *const GT, rhs: *const GT) -> i32;
}
