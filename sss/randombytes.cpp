#include "randombytes.h"
#include <string.h>

#define RANDOM_POOL_SIZE 128

/* Basic iterative prng relying on the SGX SDK primitives.
 * Initial implementation relies on /dev/urandom, but it cannot be accessed
 * from the enclave. Moreover, external sources of randomness are not considered
 * as trusted. */
static uint8_t random_pool[RANDOM_POOL_SIZE];

void randominit(void *entropy, size_t size) {
  /*
    sgx_sha256_hash_t digest;
    
    uint8_t *p = random_pool;
    sgx_sha256_msg((uint8_t *) entropy, (uint32_t) size, &digest);

    for (int i = 0; i < 4; i++) {
        memcpy(p, digest, SGX_SHA256_HASH_SIZE);
        sgx_sha256_msg(p, SGX_SHA256_HASH_SIZE, &digest);
        p += SGX_SHA256_HASH_SIZE;
    }
    */
  for (size_t i = 0; i < RANDOM_POOL_SIZE; ++i) {
    random_pool[i] = 0xA0+i;
  }
}

int randombytes(void *buf, size_t n) {
    if (n == 0) {
        return 0;
    }

    uint8_t *data = (uint8_t *)buf;
    while (n > RANDOM_POOL_SIZE) {
        memcpy(data, random_pool, RANDOM_POOL_SIZE);
        data += RANDOM_POOL_SIZE;
        n -= RANDOM_POOL_SIZE;
    }
    memcpy(data, random_pool, n);
    return 0;
}
