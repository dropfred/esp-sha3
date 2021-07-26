#ifndef SHA3_H
#define SHA3_H

#include <cstddef>

#define SHA3_224_DIGEST_SIZE 28
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_512_DIGEST_SIZE 64

extern void sha3_224(void const * data, std::size_t size, void * digest);
extern void sha3_256(void const * data, std::size_t size, void * digest);
extern void sha3_512(void const * data, std::size_t size, void * digest);

#endif
