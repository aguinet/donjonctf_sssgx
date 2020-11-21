#include "hazmat.h"
#include "sss.h"
#include "randombytes.h"
#include <cstring>
#include <cstdio>

int main()
{
  uint8_t data[sss_MLEN], restored[sss_MLEN];
  sss_Share shares[3];

  randominit(NULL, 0);
  strncpy((char*)data, "Tyler Durden isn't real.", sizeof(data));
  sss_create_shares(shares, data, 3, 3);

  for (auto const& S: shares) {
    for (size_t i = 0; i < sss_KEYSHARE_LEN; ++i) {
      printf("%02X", S[i]);
    }
    printf("\n");
  }

  sss_combine_shares(restored, shares, 3);
  puts((const char*) restored);

  return 0;
}
