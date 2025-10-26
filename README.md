# esp-sha3

SHA3 implementation.

My main motivation for implementing SHA3 was to compare the performance of a microcontroller with that of a computer on pure arithmetic operations.

As expected, it is quite slow compared to a decent PC. Of course, it depends on the chips and frequencies of the ESP and the PC, but the difference is generally at least two orders of magnitude.

I tried some tweaks about memory access (by transposing the Keccak state) to see if GCC could do better optimization, or if it could be more hardware friendly, without any sensible gain. The results are about the same when hashing actual small data (less than Keccak block size), since most time is spent in the Keccak function applied when done and when the data size hits the Keccak block size (that is, every 144, 136, and 72 bytes for sha3-224, sha3-256, and sha3-512 respectively).

Since it is not intended to hash large data, the progressive hash method is not exposed, in order to keep the interface as simple as possible.
