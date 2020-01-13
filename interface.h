#include <stdint.h>
#include <stddef.h>

#ifndef ED25519_SECRET_SHARING_INTERFACE_H
#define ED25519_SECRET_SHARING_INTERFACE_H

/** This indicates a problem within this library, e.g. it failed to initialize a secure random number generator. */
#define ED25519_SECRET_SHARING_INTERNAL_ERROR 1
/** This indicates a problem with a function's parameters, e.g. more shares would be needed than would be produced. */
#define ED25519_SECRET_SHARING_PARAMS_ERROR 2
/** This indicates a problem with either the verification value or the share, i.e. verification failed. */
#define ED25519_SECRET_SHARING_VALIDATION_ERROR 3

/**
 * Generates shares of an ed25519 scalar secret (private keys first need to be expanded).
 * \param key The 32 byte scalar secret.
 * \param needed The number of shares needed to recover the secret.
 * \param shares The number of shares to generate.
 * \param verification_out A pointer to a `needed*32` byte long array that will be populated with information needed to verify shares. If this argument is null, the verification information won't be generated.
 * \param shares_out A pointer to an array of `shares` pointers to memory that will be populated with each 32 byte share. Each share has a necessary consecutive number, starting at 1.
 */
uint8_t secret_sharing_generate(uint8_t * key, uint8_t needed, uint8_t shares, uint8_t * verification_out, uint8_t ** shares_out);

/**
 * Validates that a share can be used in combination with others to recover a key. Care should be taken to ensure that shares are unique but have the same verification information, otherwise, they may not be usable together.
 * \param verification A pointer to the verification information.
 * \param verification_len The length of the verification information.
 * \param share A pointer to the 32 byte share to validate.
 * \param share_number Which share this is. Share numbers start at 1.
 * \param pubkey_out A pointer to 32 bytes of memory that will be filled with the public key this share is for. If null, this will be ignored.
 * \param needed_shares_out A pointer to 1 byte of memory that will be filled with the number of shares needed to recover this key. If null, this will be ignored.
 */
uint8_t secret_sharing_validate(uint8_t * verification, size_t verification_len, uint8_t * share, uint8_t share_num, uint8_t * pubkey_out, uint8_t * needed_shares_out);

/**
 * Combine a list of shares into the secret. If not enough shares are specified, this will produce the wrong key, but specifying too many shares is fine and will produce the correct key.
 * \param shares A pointer to a list of pointers to 32 byte shares. These must all be from the same secret sharing generation (meaning they must have the same verification information).
 * \param share_numbers A pointer to a list of 1 byte share numbers. Share numbers have a minimum of 1, and this library generates them consecutively, though that's not necessary.
 * \param num_shares The number of shares, which must also be the length of share_numbers.
 * \param secret_key_out On success, this will be populated with the key these shares were generated for. Note that this may return "no error" but produce the wrong key if there are not enough shares or at least one share is incorrect.
 */
uint8_t secret_sharing_solve(uint8_t ** shares, uint8_t * share_numbers, size_t num_shares, uint8_t * secret_key_out);

#endif // ED25519_SECRET_SHARING_INTERFACE_H
