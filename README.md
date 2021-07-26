# esp-sha3

ESP microcontrollers SHA3 implementation.

It is veryyyy slow, about 690 µs on the ESP8266, and about 380 µs on the ESP32-WROOM and ESP32-CAM, for a no data (the empty string) sha3-256 hash. I tried some tweaks about memory access (by transposing the Keccak state) without any sensible gain. Next step (when I'll have some time) is to test if emulating 64 bits bitwise operations with 32 bits ones can help, but I have doubts.
