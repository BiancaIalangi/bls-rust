//! bls-eth-rust is a library to support BLS signature for Ethereum 2.0 Phase 0

use rand::prelude::*;
use std::collections::HashSet;
use std::os::raw::c_int;
use std::sync::Once;

#[repr(C)]
pub struct mclBnG2 {
    d: [u64; 12], // internal representation (Herumi uses 12*64 bits for G2)
}

#[allow(non_snake_case)]
extern "C" {
    // global functions
    pub fn blsInit(curve: c_int, compiledTimeVar: c_int) -> c_int;

    pub fn mclBn_getFrByteSize() -> u32;
    pub fn mclBn_getFpByteSize() -> u32;
    pub fn mclBnG2_setStr(x: *mut G2, buf: *const u8, bufSize: usize, ioMode: c_int) -> c_int;

    pub fn blsSecretKeySetByCSPRNG(x: *mut SecretKey);
    pub fn blsSecretKeySetHexStr(x: *mut SecretKey, buf: *const u8, bufSize: usize) -> c_int;
    pub fn blsGetPublicKey(y: *mut G1, x: *const SecretKey);
    pub fn blsSignatureVerifyOrder(doVerify: c_int);
    pub fn blsSignatureIsValidOrder(sig: *const G2) -> c_int;
    pub fn blsPublicKeyVerifyOrder(doVerify: c_int);
    pub fn blsPublicKeyIsValidOrder(pug: *const G1) -> c_int;

    // for new eth2.0 spec
    pub fn blsSign(sig: *mut G2, seckey: *const SecretKey, msg: *const u8, msgSize: usize);
    pub fn blsVerify(sig: *const G2, pubkey: *const G1, msg: *const u8, msgSize: usize) -> c_int;
    /*
      pub fn blsMultiVerify(
            sig: *const Signature,
            pubkey: *const PublicKey,
            msg: *const u8,
            msgSize: usize,
            randVec: *const u64,
            randSize: usize,
            n: usize,
            threadN: i32,
        ) -> c_int;
    */
    pub fn blsMultiVerifySub(
        e: *mut GT,
        sig: *mut G2,
        sig: *const G2,
        pubkey: *const G1,
        msg: *const u8,
        msgSize: usize,
        randVec: *const u64,
        randSize: usize,
        n: usize,
    );
    pub fn blsMultiVerifyFinal(e: *const GT, sig: *const G2) -> c_int;
    pub fn blsAggregateSignature(aggSig: *mut G2, sigVec: *const G2, n: usize);
    pub fn blsFastAggregateVerify(
        sig: *const G2,
        pubVec: *const G1,
        n: usize,
        msg: *const u8,
        msgSize: usize,
    ) -> c_int;
    pub fn blsAggregateVerifyNoCheck(
        sig: *const G2,
        pubVec: *const G1,
        msgVec: *const u8,
        msgSize: usize,
        n: usize,
    ) -> c_int;

    pub fn blsSecretKeyIsEqual(lhs: *const SecretKey, rhs: *const SecretKey) -> i32;
    pub fn blsPublicKeyIsEqual(lhs: *const G1, rhs: *const G1) -> i32;
    pub fn blsSignatureIsEqual(lhs: *const G2, rhs: *const G2) -> i32;

    pub fn blsSecretKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const SecretKey) -> usize;
    pub fn blsPublicKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const G1) -> usize;
    pub fn blsSignatureSerialize(buf: *mut u8, maxBufSize: usize, x: *const G2) -> usize;

    pub fn blsSecretKeyDeserialize(x: *mut SecretKey, buf: *const u8, bufSize: usize) -> usize;
    pub fn blsPublicKeyDeserialize(x: *mut G1, buf: *const u8, bufSize: usize) -> usize;
    pub fn blsSignatureDeserialize(x: *mut G2, buf: *const u8, bufSize: usize) -> usize;

    pub fn blsPublicKeyAdd(pubkey: *mut G1, x: *const G1);
    pub fn blsSignatureAdd(sig: *mut G2, x: *const G2);
    pub fn mclBnFr_isZero(x: *const SecretKey) -> i32;

    pub fn mclBnGT_mul(z: *mut GT, x: *const GT, y: *const GT);
    pub fn mclBnGT_isEqual(lhs: *const GT, rhs: *const GT) -> i32;
}

enum CurveType {
    BLS12_381 = 5,
}

#[derive(Debug, PartialEq, Clone)]
/// `BlsError` type for error
pub enum BlsError {
    /// invalid data
    InvalidData,
    /// bad parameter size
    BadSize,
    /// internal error (should not happen)
    InternalError,
}

const MCLBN_FP_UNIT_SIZE: usize = 6;
const MCLBN_FR_UNIT_SIZE: usize = 4;
const BLS_COMPILER_TIME_VAR_ADJ: usize = 200;
const MCLBN_COMPILED_TIME_VAR: c_int =
    (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ) as c_int;

/// message is 32 byte in eth2.0
pub const MSG_SIZE: usize = 32;

// Used to call blsInit only once.
static INIT: Once = Once::new();
fn init_library() {
    init(CurveType::BLS12_381);
}

/// return true if `size`-byte splitted `msgs` are different each other
/// * `msgs` - an array that `size`-byte messages are concatenated
/// * `size` - lenght of one message
pub fn are_all_msg_different(msgs: &[u8], size: usize) -> bool {
    let n = msgs.len() / size;
    assert!(msgs.len() == n * size);
    let mut set = HashSet::<&[u8]>::new();
    for i in 0..n {
        let msg = &msgs[i * size..(i + 1) * size];
        if set.contains(msg) {
            return false;
        }
        set.insert(msg);
    }
    return true;
}

macro_rules! common_impl {
    ($t:ty, $is_equal_fn:ident) => {
        impl PartialEq for $t {
            /// return true if `self` is equal to `rhs`
            fn eq(&self, rhs: &Self) -> bool {
                INIT.call_once(|| {
                    init_library();
                });
                unsafe { $is_equal_fn(self, rhs) == 1 }
            }
        }
        impl Eq for $t {}
        impl $t {
            /// return zero instance
            pub fn zero() -> $t {
                Default::default()
            }
            /// return uninitialized instance
            pub unsafe fn uninit() -> $t {
                std::mem::MaybeUninit::uninit().assume_init()
            }
        }
    };
}

macro_rules! serialize_impl {
    ($t:ty, $size:expr, $serialize_fn:ident, $deserialize_fn:ident) => {
        impl $t {
            /// return true if `buf` is deserialized successfully
            /// * `buf` - serialized data by `serialize`
            pub fn deserialize(&mut self, buf: &[u8]) -> bool {
                INIT.call_once(|| {
                    init_library();
                });
                let n = unsafe { $deserialize_fn(self, buf.as_ptr(), buf.len()) };
                return n > 0 && n == buf.len();
            }
            /// return deserialized `buf`
            pub fn from_serialized(buf: &[u8]) -> Result<$t, BlsError> {
                let mut v = unsafe { <$t>::uninit() };
                if v.deserialize(buf) {
                    return Ok(v);
                }
                Err(BlsError::InvalidData)
            }
            /// return serialized byte array
            pub fn serialize(&self) -> Vec<u8> {
                INIT.call_once(|| {
                    init_library();
                });

                let size = unsafe { $size } as usize;
                let mut buf: Vec<u8> = Vec::with_capacity(size);
                let n: usize;
                unsafe {
                    n = $serialize_fn(buf.as_mut_ptr(), size, self);
                }
                if n == 0 {
                    panic!("BLS serialization error");
                }
                unsafe {
                    buf.set_len(n);
                }
                buf
            }
            /// alias of serialize
            pub fn as_bytes(&self) -> Vec<u8> {
                self.serialize()
            }
        }
    };
}

fn init(curve_type: CurveType) -> bool {
    unsafe { blsInit(curve_type as c_int, MCLBN_COMPILED_TIME_VAR) == 0 }
}

/// verify the correctness whenever signature setter is used
/// * `verify` - enable if true (default off)
pub fn verify_signature_order(verify: bool) {
    unsafe { blsSignatureVerifyOrder(verify as c_int) }
}

/// verify the correctness whenever signature setter is used
/// * `verify` - enable if true (default off)
pub fn verify_publickey_order(verify: bool) {
    unsafe { blsPublicKeyVerifyOrder(verify as c_int) }
}

/// secret key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SecretKey {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

/// public key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct G1 {
    pub x: [u64; MCLBN_FP_UNIT_SIZE],
    pub y: [u64; MCLBN_FP_UNIT_SIZE],
    pub z: [u64; MCLBN_FP_UNIT_SIZE],
}

/// signature type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct G2 {
    pub x: [u64; MCLBN_FP_UNIT_SIZE * 2],
    pub y: [u64; MCLBN_FP_UNIT_SIZE * 2],
    pub z: [u64; MCLBN_FP_UNIT_SIZE * 2],
}

/// GT type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GT {
    d0: [u64; MCLBN_FP_UNIT_SIZE * 4],
    d1: [u64; MCLBN_FP_UNIT_SIZE * 4],
    d2: [u64; MCLBN_FP_UNIT_SIZE * 4],
}
common_impl![GT, mclBnGT_isEqual];

common_impl![SecretKey, blsSecretKeyIsEqual];
serialize_impl![
    SecretKey,
    mclBn_getFrByteSize(),
    blsSecretKeySerialize,
    blsSecretKeyDeserialize
];

common_impl![G1, blsPublicKeyIsEqual];
serialize_impl![
    G1,
    mclBn_getFpByteSize(),
    blsPublicKeySerialize,
    blsPublicKeyDeserialize
];

common_impl![G2, blsSignatureIsEqual];
serialize_impl![
    G2,
    mclBn_getFpByteSize() * 2,
    blsSignatureSerialize,
    blsSignatureDeserialize
];

impl SecretKey {
    /// init secret key by CSPRNG
    pub fn set_by_csprng(&mut self) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSecretKeySetByCSPRNG(self) }
        let ret = unsafe { mclBnFr_isZero(self) };
        if ret == 1 {
            panic!("zero secretkey")
        }
    }
    /// set hexadecimal string `s` to `self`
    pub fn set_hex_str(&mut self, s: &str) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSecretKeySetHexStr(self, s.as_ptr(), s.len()) == 0 }
    }
    /// return the secret key set by hexadecimal string `s`
    pub fn from_hex_str(s: &str) -> Result<SecretKey, BlsError> {
        let mut v = unsafe { SecretKey::uninit() };
        if v.set_hex_str(&s) {
            return Ok(v);
        }
        Err(BlsError::InvalidData)
    }
    /// return the public key corresponding to `self`
    pub fn get_publickey(&self) -> G1 {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = unsafe { G1::uninit() };
        unsafe {
            blsGetPublicKey(&mut v, self);
        }
        v
    }
    /// return the signature of `msg`
    /// * `msg` - message
    pub fn sign(&self, msg: &[u8]) -> G2 {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = unsafe { G2::uninit() };
        unsafe { blsSign(&mut v, self, msg.as_ptr(), msg.len()) }
        v
    }
}

impl G1 {
    /// add `x` to `self`
    /// * `x` - signature to be added
    pub fn add_assign(&mut self, x: *const G1) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsPublicKeyAdd(self, x);
        }
    }
    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsPublicKeyIsValidOrder(self) == 1 }
    }
}

impl G2 {
    /// return true if `self` is valid signature of `msg` for `pubkey`
    /// `pubkey` - public key
    /// `msg` - message
    pub fn verify(&self, pubkey: *const G1, msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsVerify(self, pubkey, msg.as_ptr(), msg.len()) == 1 }
    }
    /// add `x` to `self`
    /// * `x` - signature to be added
    pub fn add_assign(&mut self, x: *const G2) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsSignatureAdd(self, x);
        }
    }
    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSignatureIsValidOrder(self) == 1 }
    }
    /// set the aggregated signature of `sigs`
    /// * `sigs` - signatures to be aggregated
    pub fn aggregate(&mut self, sigs: &[G2]) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsAggregateSignature(self, sigs.as_ptr(), sigs.len());
        }
    }
    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msg` - message
    pub fn fast_aggregate_verify(&self, pubs: &[G1], msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        if pubs.len() == 0 {
            return false;
        }
        unsafe {
            blsFastAggregateVerify(self, pubs.as_ptr(), pubs.len(), msg.as_ptr(), msg.len()) == 1
        }
    }
    fn inner_aggregate_verify(&self, pubs: &[G1], msgs: &[u8], check_message: bool) -> bool {
        INIT.call_once(|| {
            init_library();
        });
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
    pub fn aggregate_verify_no_check(&self, pubs: &[G1], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, false)
    }
    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    pub fn aggregate_verify(&self, pubs: &[G1], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, true)
    }

    pub fn set_str(&mut self, s: &str) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { mclBnG2_setStr(self, s.as_ptr(), s.len(), 10) };
    }
}

/// return true if all sigs are valid
/// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
pub fn multi_verify(sigs: &[G2], pubs: &[G1], msgs: &[u8]) -> bool {
    INIT.call_once(|| {
        init_library();
    });
    let n = sigs.len();
    if n == 0 || pubs.len() != n || msgs.len() != n * MSG_SIZE {
        return false;
    }
    let mut rng = rand::thread_rng();
    let mut rands: Vec<u64> = Vec::new();
    let mut thread_n = num_cpus::get();
    rands.resize_with(n, Default::default);
    for i in 0..n {
        rands[i] = rng.gen::<u64>();
    }
    let mut e = unsafe { GT::uninit() };
    let mut agg_sig = unsafe { G2::uninit() };
    const MAX_THREAD_N: usize = 32;
    if thread_n > MAX_THREAD_N {
        thread_n = MAX_THREAD_N;
    }
    const MIN_N: usize = 3;
    if thread_n > 1 && n >= MIN_N {
        let mut et: [GT; MAX_THREAD_N] = unsafe { [GT::uninit(); MAX_THREAD_N] };
        let mut agg_sigt: [G2; MAX_THREAD_N] = unsafe { [G2::uninit(); MAX_THREAD_N] };
        let block_n = n / MIN_N;
        let q = block_n / thread_n;
        let mut r = block_n % thread_n;
        let mut pos = 0;
        for i in 0..thread_n {
            let mut m = q;
            if r > 0 {
                m = m + 1;
                r = r - 1;
            }
            if m == 0 {
                thread_n = i;
                break;
            }
            m *= MIN_N;
            if i == thread_n - 1 {
                m = n - pos;
            }
            unsafe {
                blsMultiVerifySub(
                    &mut et[i],
                    &mut agg_sigt[i],
                    sigs[pos..].as_ptr(),
                    pubs[pos..].as_ptr(),
                    msgs[pos * MSG_SIZE..].as_ptr(),
                    MSG_SIZE,
                    rands[pos..].as_ptr(),
                    8,
                    m,
                );
            }
            pos = pos + m;
        }
        e = et[0];
        agg_sig = agg_sigt[0];
        for i in 1..thread_n {
            unsafe {
                mclBnGT_mul(&mut e, &e, &et[i]);
            }
            agg_sig.add_assign(&agg_sigt[i]);
        }
    } else {
        unsafe {
            blsMultiVerifySub(
                &mut e,
                &mut agg_sig,
                sigs.as_ptr(),
                pubs.as_ptr(),
                msgs.as_ptr(),
                MSG_SIZE,
                rands.as_ptr(),
                8, /* sizeof(uint64_t) */
                n,
            );
        }
    }
    unsafe { blsMultiVerifyFinal(&e, &agg_sig) == 1 }
    /*
        unsafe {
            blsMultiVerify(
                sigs.as_ptr(),
                pubs.as_ptr(),
                msgs.as_ptr(),
                MSG_SIZE,
                rands.as_ptr(),
                8, /* sizeof(uint64_t) */
                n,
                thread_n as i32,
            ) == 1
        }
    */
}
