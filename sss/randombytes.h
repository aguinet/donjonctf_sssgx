#pragma once

#include <stdint.h>
#include <stddef.h>

void randominit(void *entropy, size_t size);

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
int randombytes(void *buf, size_t n);
