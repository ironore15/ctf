#ifndef AESCTR_H
#define AESCTR_H

#include <stdlib.h>
#include <stdint.h>

void AES_init_nonce_and_crypt(uint8_t *key, uint8_t *nonce, uint8_t *data, uint32_t length);

#endif