# esp-sha3

ESP microcontrollers SHA3 implementation.

It is veryyyy slow, about 690 µs on the ESP8266, and about 380 µs on the ESP32-WROOM and ESP32-CAM, for a no data (the empty string) sha3-256 hash. I tried some tweaks about memory access (by transposing the Keccak state) without any sensible gain.
