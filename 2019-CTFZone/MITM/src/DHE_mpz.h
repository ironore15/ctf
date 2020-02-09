#ifndef DHE_mpz_H
#define DHE_mpz_H

#include <stddef.h>
#include <stdint.h>
#include <gmp.h>


void DHE_generate_symmetric_key(mpz_t key, mpz_t pub_key, mpz_t priv_key, mpz_t p);
int8_t DHE_generate_parameters(mpz_t p, mpz_t g, uint16_t bits_length);
void DHE_generate_private_and_public_key(mpz_t private_key, mpz_t public_key, mpz_t p, mpz_t g);

#endif