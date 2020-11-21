import pydffi
import sys
import os
import sage
import random

if len(sys.argv) <= 1:
    print("Usage: %s path/to/libsss.so" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

pydffi.dlopen(sys.argv[1])

FFI=pydffi.FFI()
CU=FFI.cdef('''
#include <stdint.h>
void sss_create_keyshares_impl(uint8_t *out,
                      const uint8_t* key,
                      const uint8_t* poly, // was uint32_t*
                      uint8_t n,
                      uint8_t k);
int sss_decrypt(uint8_t *out, uint8_t const* in, uint8_t const* key);
''')

LEN_KEY=32
LEN_POLY=32
LEN_KEYSHARE=32+1
NSHARES=3
NPOLYS = NSHARES-1
LEN_POLYS=LEN_POLY*NPOLYS
LEN_KEYSHARES=LEN_KEYSHARE*NSHARES

def polys_to_keyshares(polys):
    assert(len(polys) == LEN_POLYS)
    # This is due to the random generator reusing the same data (this is the vuln we are exploiting).
    key = polys[:LEN_KEY]
    out = bytearray([0]*LEN_KEYSHARES)
    CU.funcs.sss_create_keyshares_impl(out, key, polys, NSHARES, NSHARES)
    ret = (out[:LEN_KEYSHARE], out[LEN_KEYSHARE:2*LEN_KEYSHARE], out[2*LEN_KEYSHARE:])
    return ret

def kss_to_F_output(kss):
    return kss[1][1:] + kss[2][1:]

# This is our function F. It takes 64 bytes as input (two sets of 32 GF(2**8)
# polynoms each), and returns the last two shares (2*32 bytes).
def F(in_):
    kss = polys_to_keyshares(in_)
    return kss_to_F_output(kss)

# Make sure F is a linear function in GF(2)**N (N==512)
def xor(A,B):
    return bytes(a^b for a,b in zip(A,B))

polysZ = b"\x00"*LEN_POLYS
assert(F(polysZ) == polysZ)
for i in range(100):
    polys0 = bytes(random.getrandbits(8) for _ in range(LEN_POLYS))
    polys1 = bytes(random.getrandbits(8) for _ in range(LEN_POLYS))
    A = F(xor(polys0, polys1))
    B = xor(F(polys0),F(polys1))
    assert(A == B)

# Compute the linear matrix

# We work with vector of bits, so we choose a way to transform a list of bytes
# into a list of bits and vice versa. Any representation would work, as long as
# bytes2bits is the inverse of bits2bytes.
def bits2bytes(v):
    assert(len(v) % 8 == 0)
    def tobyte(bits):
        v = 0
        for i,b in enumerate(bits):
            v |= b<<i
        return v
    return bytes(tobyte(v[i*8:(i+1)*8]) for i in range(len(v)//8))

def bytes2bits(v):
    ret = []
    for byteidx,v in enumerate(v):
        for bitidx in range(8):
            ret.append((v >> bitidx) & 1)
    return ret

from sage.all import Integers, Matrix, vector
GF2=Integers(2)
def computeFMatrix(F, input_nbits):
    ret_cols = []
    for bin_ in range(input_nbits):
        in_ = [0]*NBITS
        in_[bin_] = 1
        in_ = bits2bytes(in_)
        out = F(in_)
        out = bytes2bits(out)
        ret_cols.append(out)
    return Matrix(GF2, ret_cols).transpose()
NBITS=64*8
M=computeFMatrix(F, NBITS)

print("[+] Matrix kernel")
print(M.kernel())

# Get all possible values of X in M*X = C thanks to Sage
def allsols(M, C):
    S0 = M.solve_right(vector(GF2,bytes2bits(C)))
    for S in M.right_kernel():
        yield S + S0

# Solve the challenge. First, gather and parse the shares
import base64
shares=open("shares.txt","r")
shares=[base64.b64decode(s.strip()) for s in shares]

# Each share has the encrypted secret at its end
msg = shares[0][LEN_KEYSHARE:]
# First byte is the share index, next 32 bytes are the actual share value
shares={s[0]:s[1:33] for s in shares}

# Then, get all the possible keys.
Fout = shares[2]+shares[3]
keys = []
for S in allsols(M, Fout):
    S = [int(v) for v in S]
    # One solution gives us the encryption K and the set of polynoms P2. We only
    # care about K here.
    key = bits2bytes(S)[:32]
    print("[x] Possible key: %s" % key.hex())
    keys.append(key)

# Now check all possible keys to see which one is able to decrypt and verify
# the authenticity of the original secret.
# The encrypted secret is at the end of every share.
print("[x] Bruteforcing the possible keys...")
for k in keys:
    out = bytearray([0]*64)
    # sss_decrypt is basically a wrapper around crypto_secretbox_open added to
    # the sss lib. 
    if int(CU.funcs.sss_decrypt(out, msg, k)) == 0:
        print("[+] Original secret found: %s" % out.hex())
        sys.exit(0)
print("[-] No valid keys found...")
sys.exit(1)
