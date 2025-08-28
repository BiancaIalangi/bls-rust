use std::collections::HashSet;
use std::os::raw::c_int;
use std::sync::Once;

// global functions
extern "C" {
    pub fn blsInit(curve: usize, compiledTimeVar: usize) -> c_int;

    pub fn mclBn_getFrByteSize() -> u32;
    pub fn mclBn_getFpByteSize() -> u32;
    pub fn mclBnG2_setStr(x: *mut G2, buf: *const u8, buf_size: usize, io_mode: c_int) -> c_int;
    pub fn mclBnG2_deserialize(x: *mut G2, buf: *const u8, buf_size: usize) -> usize;

    pub fn blsSecretKeySetByCSPRNG(x: *mut SecretKey);
    pub fn blsSecretKeySetHexStr(x: *mut SecretKey, buf: *const u8, buf_size: usize) -> c_int;
    pub fn blsGetPublicKey(y: *mut G2, x: *const SecretKey);
    pub fn blsSignatureVerifyOrder(do_verify: c_int);
    pub fn blsSignatureIsValidOrder(sig: *const G1) -> c_int;
    pub fn blsPublicKeyVerifyOrder(do_verify: c_int);
    pub fn blsPublicKeyIsValidOrder(public_key: *const G2) -> c_int;

    pub fn blsSign(sig: *mut G1, secret_key: *const SecretKey, msg: *const u8, msg_len: usize);
    pub fn blsVerify(
        sig: *const G1,
        public_key: *const G2,
        msg: *const u8,
        msg_len: usize,
    ) -> c_int;

    // pub fn blsMultiVerifySub(
    //     e: *mut GT,
    //     sig: *mut G2,
    //     sig: *const G2,
    //     pubkey: *const G1,
    //     msg: *const u8,
    //     msgSize: usize,
    //     randVec: *const u64,
    //     randSize: usize,
    //     n: usize,
    // );
    pub fn blsMultiVerifyFinal(e: *const GT, sig: *const G2) -> c_int;
    pub fn blsAggregateSignature(aggregate_sig: *mut G1, signature_vec: *const G1, n: usize);
    pub fn blsFastAggregateVerify(
        sig: *const G1,
        public_keys: *const G2,
        n: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> c_int;
    pub fn blsAggregateVerifyNoCheck(
        sig: *const G1,
        public_keys: *const G2,
        messages: *const u8,
        messages_len: usize,
        n: usize,
    ) -> c_int;

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
const MCLBN_COMPILED_TIME_VAR: usize = MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE;

/// message is 32 byte in eth2.0
pub const MSG_SIZE: usize = 32;

// Used to call blsInit only once.
static INIT: Once = Once::new();
fn init_library() {
    init(CurveType::BLS12_381);
}

/// return true if `size`-byte splitted `msgs` are different each other
/// * `msgs` - an array that `size`-byte messages are concatenated
/// * `size` - length of one message
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

    true
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
            pub fn uninit() -> $t {
                Default::default()
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
                let mut v = <$t>::uninit();
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
    unsafe { blsInit(curve_type as usize, MCLBN_COMPILED_TIME_VAR) == 0 }
}

/// verify the correctness whenever signature setter is used
/// * `verify` - enable if true (default off)
pub fn verify_signature_order(verify: bool) {
    unsafe { blsSignatureVerifyOrder(verify as c_int) }
}

/// verify the correctness whenever public key setter is used
/// * `verify` - enable if true (default off)
pub fn verify_public_key_order(verify: bool) {
    unsafe { blsPublicKeyVerifyOrder(verify as c_int) }
}

/// secret key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SecretKey {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

/// signature type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct G1 {
    pub x: [u64; MCLBN_FP_UNIT_SIZE],
    pub y: [u64; MCLBN_FP_UNIT_SIZE],
    pub z: [u64; MCLBN_FP_UNIT_SIZE],
}

/// public key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct G2 {
    pub x: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
    pub y: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
    pub z: [[u64; MCLBN_FP_UNIT_SIZE]; 2],
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

common_impl![G1, blsSignatureIsEqual];
serialize_impl![
    G1,
    mclBn_getFpByteSize(),
    blsSignatureSerialize,
    blsSignatureDeserialize
];

common_impl![G2, blsPublicKeyIsEqual];
serialize_impl![
    G2,
    mclBn_getFpByteSize() * 2,
    blsPublicKeySerialize,
    blsPublicKeyDeserialize
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
        let mut v = SecretKey::uninit();
        if v.set_hex_str(s) {
            return Ok(v);
        }
        Err(BlsError::InvalidData)
    }

    /// return the public key corresponding to `self`
    pub fn get_public_key(&self) -> G2 {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = G2::uninit();
        unsafe {
            blsGetPublicKey(&mut v, self);
        }
        v
    }

    /// return the signature of `msg`
    /// * `msg` - message
    pub fn sign(&self, msg: &[u8]) -> G1 {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = G1::uninit();
        unsafe { blsSign(&mut v, self, msg.as_ptr(), msg.len()) }
        v
    }
}

impl G1 {
    /// return true if `self` is valid signature of `msg` for `pubkey`
    /// `pubkey` - public key
    /// `msg` - message
    pub fn verify(&self, pubkey: G2, msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsVerify(self, &pubkey, msg.as_ptr(), msg.len()) == 1 }
    }

    /// add `x` to `self`
    /// * `x` - signature to be added
    pub fn add_assign(&mut self, x: G1) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsSignatureAdd(self, &x);
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
    pub fn aggregate(&mut self, sigs: &[G1]) {
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
    pub fn fast_aggregate_verify(&self, pubs: &[G2], msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        if pubs.is_empty() {
            return false;
        }
        unsafe {
            blsFastAggregateVerify(self, pubs.as_ptr(), pubs.len(), msg.as_ptr(), msg.len()) == 1
        }
    }

    fn inner_aggregate_verify(&self, pubs: &[G2], msgs: &[u8], check_message: bool) -> bool {
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
    pub fn aggregate_verify_no_check(&self, pubs: &[G2], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, false)
    }

    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    pub fn aggregate_verify(&self, pubs: &[G2], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, true)
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
        INIT.call_once(|| {
            init_library();
        });
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
        INIT.call_once(|| {
            init_library();
        });
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
        INIT.call_once(|| {
            init_library();
        });
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
        INIT.call_once(|| {
            init_library();
        });
        let n = unsafe { mclBnG2_deserialize(self, buf.as_ptr(), buf.len()) };

        n > 0 && n == buf.len()
    }
}

// return true if all sigs are valid
// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
// pub fn multi_verify(sigs: &[G2], pubs: &[G1], msgs: &[u8]) -> bool {
//     INIT.call_once(|| {
//         init_library();
//     });
//     let n = sigs.len();
//     if n == 0 || pubs.len() != n || msgs.len() != n * MSG_SIZE {
//         return false;
//     }
//     let mut rng = rand::thread_rng();
//     let mut rands: Vec<u64> = Vec::new();
//     let mut thread_n = num_cpus::get();
//     rands.resize_with(n, Default::default);
//     for i in 0..n {
//         rands[i] = rng.gen::<u64>();
//     }
//     let mut e = unsafe { GT::uninit() };
//     let mut agg_sig = unsafe { G2::uninit() };
//     const MAX_THREAD_N: usize = 32;
//     if thread_n > MAX_THREAD_N {
//         thread_n = MAX_THREAD_N;
//     }
//     const MIN_N: usize = 3;
//     if thread_n > 1 && n >= MIN_N {
//         let mut et: [GT; MAX_THREAD_N] = unsafe { [GT::uninit(); MAX_THREAD_N] };
//         let mut agg_sigt: [G2; MAX_THREAD_N] = unsafe { [G2::uninit(); MAX_THREAD_N] };
//         let block_n = n / MIN_N;
//         let q = block_n / thread_n;
//         let mut r = block_n % thread_n;
//         let mut pos = 0;
//         for i in 0..thread_n {
//             let mut m = q;
//             if r > 0 {
//                 m = m + 1;
//                 r = r - 1;
//             }
//             if m == 0 {
//                 thread_n = i;
//                 break;
//             }
//             m *= MIN_N;
//             if i == thread_n - 1 {
//                 m = n - pos;
//             }
//             unsafe {
//                 blsMultiVerifySub(
//                     &mut et[i],
//                     &mut agg_sigt[i],
//                     sigs[pos..].as_ptr(),
//                     pubs[pos..].as_ptr(),
//                     msgs[pos * MSG_SIZE..].as_ptr(),
//                     MSG_SIZE,
//                     rands[pos..].as_ptr(),
//                     8,
//                     m,
//                 );
//             }
//             pos = pos + m;
//         }
//         e = et[0];
//         agg_sig = agg_sigt[0];
//         for i in 1..thread_n {
//             unsafe {
//                 mclBnGT_mul(&mut e, &e, &et[i]);
//             }
//             agg_sig.add_assign(&agg_sigt[i]);
//         }
//     } else {
//         unsafe {
//             blsMultiVerifySub(
//                 &mut e,
//                 &mut agg_sig,
//                 sigs.as_ptr(),
//                 pubs.as_ptr(),
//                 msgs.as_ptr(),
//                 MSG_SIZE,
//                 rands.as_ptr(),
//                 8, /* sizeof(uint64_t) */
//                 n,
//             );
//         }
//     }
//     unsafe { blsMultiVerifyFinal(&e, &agg_sig) == 1 }
//     /*
//         unsafe {
//             blsMultiVerify(
//                 sigs.as_ptr(),
//                 pubs.as_ptr(),
//                 msgs.as_ptr(),
//                 MSG_SIZE,
//                 rands.as_ptr(),
//                 8, /* sizeof(uint64_t) */
//                 n,
//                 thread_n as i32,
//             ) == 1
//         }
//     */
// }
