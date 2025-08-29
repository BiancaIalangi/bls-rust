mod bls_api;
mod constants;
mod error;
mod g1;
mod g2;
mod gt;
mod init;
mod secret_key;

pub use error::BlsError;
pub use g1::{are_all_msg_different, G1};
pub use g2::G2;
pub use gt::GT;
pub use secret_key::SecretKey;

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
