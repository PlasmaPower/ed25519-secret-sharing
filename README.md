# ed25519-secret-sharing

This is a Rust project that exports a C FFI which is documented in `interface.h`. It allows for splitting a key into "shares", and given a specified number of shares, the original key can be recovered. It also produces a verification value which can be used to verify that the shares recover a given key.

This can be combined with MuSig to allow the key not to be exposed during normal signing, but the key to be recovered via this secret sharing in case it's no longer accessible.

This library uses Feldman's scheme, which is based on Shamir's secret sharing.
