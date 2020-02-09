// gcc solve.c -o solve -lgmp
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


void generate_private_key(mpz_t priv_key) {
    gmp_randstate_t state;
    uint32_t seed;
    seed = time(NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
    mpz_urandomb(priv_key, state, 349);
    mpz_setbit(priv_key, 349);
    gmp_randclear(state);
}


unsigned char *get_bignum_to_str(mpz_t number) {
    unsigned char *buffer;
    buffer = malloc(mpz_sizeinbase(number, 16) + 1);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, mpz_sizeinbase(number, 16) + 1);
    mpz_get_str(buffer, 16, number);
    return buffer;
}


int main(int argc, char **argv, char **envp)
{
    mpz_t private_key;
    mpz_init(private_key);
    generate_private_key(private_key);
    unsigned char *buffer = get_bignum_to_str(private_key);
    puts(buffer);
    free(buffer);
    return 0;
}
