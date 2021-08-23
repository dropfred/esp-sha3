# esp-sha3

ESP microcontrollers SHA3 implementation.

My main motivation into implementing SHA3 for ESP was to compare performances with a computer on simple operations.

As expected, it is quite slow, about 690 µs on the ESP8266, and about 560 µs on the ESP32-WROOM and ESP32-CAM - all running at 160 MHz -, for a no data (the empty string) sha3-256 hash. For comparison, it takes less than 2 µs on my computer. The 64 bits nature of SHA3 is probably penalizing on 32 bits ESP chips.

I tried some tweaks about memory access (by transposing the Keccak state) to see if GCC could do better optimization, or if it could be more hardware friendly, without any sensible gain. The results are about the same when hashing actual small data (less than Keccak block size), since most time is spent in the Keccak function applied when done and when the data size hits the Keccak block size (that is, every 144, 136, and 72 bytes for sha3-224, sha3-256, and sha3-512 respectively).

Since it is not intended to hash large data, the progressive hash method is not exposed, in order to keep the interface as simple as possible.

Most of the code (in particular the Keccak constants and round function) is adapted from different sources, I can't remember which ones.
