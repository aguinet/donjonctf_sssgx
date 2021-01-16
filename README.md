# A solution to Ledger Donjon's CTF SSSGX Wallet stage

This repository contains a solution to the SSSGX stage of the 2020 Ledger Donjon CTF.

A blog post explaining this solution is available [here](https://aguinet.github.io/blog/2020/11/22/donjon-ctf-sssgx.html).

## Run

To run it, you first need to compile the provided and modified
[sss](https://github.com/dsprenkels/sss) library:

~~~
$ mkdir sss/build
$ cd sss/build && cmake -DCMAKE_BUILD_TYPE=Release .. && make
~~~

You will need the [DragonFFI](https://github.com/aguinet/dragonffi) python bindings:

~~~
$ pip install pydffi
~~~

You also need the [Sage](https://www.sagemath.org/) software. Under Debian-based system:

~~~
$ sudo apt install sagemath
~~~

Then, you can run the Python 3 script ``attack.py``, specifying the path to the compiled `sss` library:

~~~
$ python3 ./attack.py ./sss/build/libsss.so
~~~
