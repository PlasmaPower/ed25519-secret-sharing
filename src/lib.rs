#![allow(clippy::missing_safety_doc)]

#[cfg(test)]
mod tests;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::collections::HashSet;
use std::convert::TryInto;
use std::slice;

pub const INTERNAL_ERROR: u8 = 1;
pub const PARAMS_ERROR: u8 = 2;
pub const VALIDATE_ERROR: u8 = 3;

#[cfg(not(test))]
macro_rules! catch_panic {
    ($code:block) => {{
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || $code));
        match res {
            Ok(x) => x,
            Err(e) => {
                match e.downcast_ref::<&'static str>() {
                    Some(s) => eprintln!("INTERNAL ED25519-SECRET-SHARING ERROR: {}", s),
                    None => eprintln!("UNKNOWN INTERNAL ED25519-SECRET-SHARING ERROR!"),
                }
                INTERNAL_ERROR
            }
        }
    }};
}

#[cfg(test)]
macro_rules! catch_panic {
    ($code:block) => {{
        $code
    }};
}

#[cfg(feature = "wasm")]
#[no_mangle]
pub unsafe extern "C" fn secret_sharing_malloc(size: usize) -> *mut u8 {
    let mut vec: Vec<u8> = Vec::with_capacity(size + mem::size_of::<usize>());
    let true_size = vec.capacity();
    let ptr = vec.as_mut_ptr();
    *(ptr as *mut usize) = true_size;
    mem::forget(vec);
    ptr.offset(mem::size_of::<usize>() as isize)
}

#[cfg(feature = "wasm")]
#[no_mangle]
pub unsafe extern "C" fn secret_sharing_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let ptr = ptr.offset(-(mem::size_of::<usize>() as isize));
    let size = *(ptr as *mut usize);
    let _: Vec<u8> = Vec::from_raw_parts(ptr, 0, size);
}

#[no_mangle]
pub unsafe extern "C" fn secret_sharing_generate(
    key: *const u8,
    needed: u8,
    shares: u8,
    verification_out: *mut u8,
    shares_out: *const *mut [u8; 32],
) -> u8 {
    catch_panic!({
        if needed == 0 || shares == 0 || needed > shares {
            return PARAMS_ERROR;
        }
        let mut rng = OsRng;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&slice::from_raw_parts(key, 32));
        let key = Scalar::from_bytes_mod_order(key_bytes);
        let mut coeffs = Vec::with_capacity(needed.into());
        coeffs.push(key);
        for _ in 1..needed {
            coeffs.push(Scalar::random(&mut rng));
        }
        if !verification_out.is_null() {
            let verification_out =
                slice::from_raw_parts_mut(verification_out as *mut [u8; 32], needed.into());
            for (coeff, out) in coeffs.iter().zip(verification_out) {
                let coeff_pub = coeff * &ED25519_BASEPOINT_TABLE;
                *out = coeff_pub.compress().to_bytes();
            }
        }
        let shares_out = slice::from_raw_parts(shares_out, shares.into());
        for (i, &out) in (1..=shares).zip(shares_out) {
            let x_scalar = Scalar::from(u64::from(i));
            let mut curr_x_pow = Scalar::one();
            let mut total = Scalar::zero();
            for coeff in &coeffs {
                total += curr_x_pow * coeff;
                curr_x_pow *= &x_scalar;
            }
            *out = total.to_bytes();
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn secret_sharing_validate(
    verification: *const u8,
    verification_len: usize,
    share: *const u8,
    share_num: u8,
    pubkey_out: *mut [u8; 32],
    needed_shares_out: *mut u8,
) -> u8 {
    catch_panic!({
        if verification_len == 0
            || verification_len % 32 != 0
            || verification_len / 32 > u8::max_value().into()
        {
            return VALIDATE_ERROR;
        }
        if share_num == 0 {
            // this would mean we just have the private key
            return VALIDATE_ERROR;
        }
        let verification =
            slice::from_raw_parts(verification as *const [u8; 32], verification_len / 32);
        let x_scalar = Scalar::from(u64::from(share_num));
        let mut curr_x_pow = Scalar::one();
        let mut total = EdwardsPoint::default();
        for &chunk in verification {
            let coeff = match CompressedEdwardsY(chunk).decompress() {
                Some(c) => c,
                None => return VALIDATE_ERROR,
            };
            total += curr_x_pow * coeff;
            curr_x_pow *= &x_scalar;
        }
        let share = slice::from_raw_parts(share, 32);
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(share);
        let share = Scalar::from_bytes_mod_order(share_bytes);
        if &share * &ED25519_BASEPOINT_TABLE != total {
            return VALIDATE_ERROR;
        }
        if !pubkey_out.is_null() {
            *pubkey_out = verification[0];
        }
        if !needed_shares_out.is_null() {
            *needed_shares_out = verification
                .len()
                .try_into()
                .expect("verification.len() didn't fit into a u8 despite earlier check");
        }
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn secret_sharing_solve(
    shares: *const *const [u8; 32],
    share_numbers: *const u8,
    num_shares: usize,
    secret_key_out: *mut [u8; 32],
) -> u8 {
    catch_panic!({
        if num_shares == 0 {
            return PARAMS_ERROR;
        }
        let shares = slice::from_raw_parts(shares, num_shares);
        let share_numbers = slice::from_raw_parts(share_numbers, num_shares);
        let share_numbers_set: HashSet<u8> = share_numbers.iter().cloned().collect();
        if share_numbers_set.len() != num_shares || share_numbers_set.contains(&0) {
            return PARAMS_ERROR;
        }
        let mut total = Scalar::zero();
        for (&share, &share_num_int) in shares.iter().zip(share_numbers.iter()) {
            let share_num = Scalar::from(u64::from(share_num_int));
            let mut processed_part = Scalar::from_bytes_mod_order(*share);
            // based on Lagrange basis polynomials, but optimized for x=0
            for &other_share_num_int in share_numbers {
                if share_num_int == other_share_num_int {
                    continue;
                }
                let other_share_num = Scalar::from(u64::from(other_share_num_int));
                let denom = other_share_num - share_num;
                processed_part *= other_share_num * denom.invert();
            }
            total += processed_part;
        }
        *secret_key_out = total.to_bytes();
        0
    })
}
