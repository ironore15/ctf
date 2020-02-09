#ifndef MessageAuth_H
#define MessageAuth_H

#include <stddef.h>
#include <stdint.h>
#include <gmp.h>

#define SHA256_BLOCK_SIZE 32

typedef struct {
	mpz_t module;
    mpz_t exp;
} RSA_key;

void SHA256_get_hash_message(unsigned char *message, unsigned char *hash, uint16_t length);
void SHA256_copy_hash_in_mpz(mpz_t hash_out, unsigned char *hash);
RSA_key *RSA_key_init(unsigned char *exp, unsigned char *module);
void RSA_encrypt_decrypt_hash(RSA_key *key, mpz_t input);

#endif 