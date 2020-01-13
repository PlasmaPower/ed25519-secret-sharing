use super::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::ptr;

#[test]
fn basic_test() {
    const NEEDED: usize = 2;
    const SHARES: usize = 5;
    let mut rng = OsRng;
    let skey = Scalar::random(&mut rng);
    let skey_bytes = *skey.as_bytes();
    let pubkey = &skey * &ED25519_BASEPOINT_TABLE;
    let pubkey_compressed = pubkey.compress();
    let mut validation = [0u8; NEEDED * 32];
    let mut shares = [[0u8; 32]; SHARES];
    let shares_ptrs: Vec<_> = shares.iter_mut().map(|s| s as *mut _).collect();
    // test with validation argument as a nullptr (should be ignored)
    unsafe {
        assert_eq!(
            secret_sharing_generate(
                skey_bytes.as_ptr(),
                NEEDED.try_into().unwrap(),
                SHARES.try_into().unwrap(),
                ptr::null_mut(),
                shares_ptrs.as_ptr(),
            ),
            0,
        );
    }
    assert!(shares.iter().all(|s| s.iter().any(|&b| b != 0)));
    let shares_orig = shares.clone();
    unsafe {
        assert_eq!(
            secret_sharing_generate(
                skey_bytes.as_ptr(),
                NEEDED.try_into().unwrap(),
                SHARES.try_into().unwrap(),
                validation.as_mut_ptr(),
                shares_ptrs.as_ptr(),
            ),
            0,
        );
    }
    assert!(validation.iter().any(|&b| b != 0));
    assert!(shares.iter().all(|s| s.iter().any(|&b| b != 0)));
    assert!(shares != shares_orig);
    unsafe {
        for (i, share) in shares.iter().enumerate() {
            let mut pubkey_bytes = [0u8; 32];
            let mut needed = 0u8;
            assert_eq!(
                secret_sharing_validate(
                    validation.as_ptr(),
                    validation.len(),
                    share.as_ptr(),
                    (i + 1).try_into().unwrap(),
                    &mut pubkey_bytes as *mut _,
                    &mut needed as *mut _,
                ),
                0,
            );
            // test with pubkey_out and needed_out as nullptrs (should be ignored)
            assert_eq!(
                secret_sharing_validate(
                    validation.as_ptr(),
                    validation.len(),
                    share.as_ptr(),
                    (i + 1).try_into().unwrap(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                0,
            );
            assert_eq!(&pubkey_bytes, pubkey_compressed.as_bytes());
            assert_eq!(usize::from(needed), NEEDED);
        }
    }
    assert_eq!(NEEDED, 2); // change loop depth if `NEEDED` changes
    for (share1_i, share1) in shares.iter().enumerate() {
        for (share2_i, share2) in shares.iter().enumerate() {
            if share1_i == share2_i {
                continue;
            }
            let needed_share_ptrs = [share1 as *const _, share2 as *const _];
            let needed_share_nums = [
                (share1_i + 1).try_into().unwrap(),
                (share2_i + 1).try_into().unwrap(),
            ];
            let mut private_key_bytes = [0u8; 32];
            unsafe {
                assert_eq!(
                    secret_sharing_solve(
                        needed_share_ptrs.as_ptr(),
                        needed_share_nums.as_ptr(),
                        NEEDED,
                        &mut private_key_bytes as _,
                    ),
                    0,
                );
            }
            assert_eq!(&private_key_bytes, skey.as_bytes());
        }
    }
    let all_shares_nums: Vec<_> = (1..=(shares.len() as u8)).collect();
    let mut private_key_bytes = [0u8; 32];
    unsafe {
        assert_eq!(
            secret_sharing_solve(
                shares_ptrs.as_ptr() as *const *const _,
                all_shares_nums.as_ptr(),
                NEEDED,
                &mut private_key_bytes as _,
            ),
            0,
        );
    }
    assert_eq!(&private_key_bytes, skey.as_bytes());
}
