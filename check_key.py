import base64
import sys

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point

WALLET_PUBLIC_KEY = "VUQGNoUfdWDxlGWhX87mFyD95A/rz8mediMJviVk5RtkxOy/tXP0+3pX51twnPznXvIOKBDPk796icm4zQ1QXQ=="


def main():
    if len(sys.argv) != 2:
        print("Usage: {} <hex key>".format(sys.argv[0]))

    # Public key extracted from the local storage
    raw_public_key = base64.b64decode(WALLET_PUBLIC_KEY)
    p = Point(NIST256p.curve, int.from_bytes(raw_public_key[:32], "little"),
              int.from_bytes(raw_public_key[32:], "little"))

    private_key = sys.argv[1]

    d = int.from_bytes(bytes.fromhex(private_key), "little")
    q = d * NIST256p.generator
    if p == q:
        print("Flag: CTF{{{}}}".format(private_key.lower()))
    else:
        print("Wrong private key")



if __name__ == "__main__":
    main()
