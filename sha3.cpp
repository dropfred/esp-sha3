#include "sha3.h"

#include <cstdlib>
#include <cstring>
#include <cstdint>

#define SHA3_TRANSPOSE_NONE 0
#define SHA3_TRANSPOSE_STATE 1
#define SHA3_TRANSPOSE_INPUT 2
#define SHA3_TRANSPOSE SHA3_TRANSPOSE_NONE

namespace
{
    std::uint64_t const keccak_rc[24] =
    {
        0x0000000000000001ULL,
        0x0000000000008082ULL,
        0x800000000000808AULL,
        0x8000000080008000ULL,
        0x000000000000808BULL,
        0x0000000080000001ULL,
        0x8000000080008081ULL,
        0x8000000000008009ULL,
        0x000000000000008AULL,
        0x0000000000000088ULL,
        0x0000000080008009ULL,
        0x000000008000000AULL,
        0x000000008000808BULL,
        0x800000000000008BULL,
        0x8000000000008089ULL,
        0x8000000000008003ULL,
        0x8000000000008002ULL,
        0x8000000000000080ULL,
        0x000000000000800AULL,
        0x800000008000000AULL,
        0x8000000080008081ULL,
        0x8000000000008080ULL,
        0x0000000080000001ULL,
        0x8000000080008008ULL
    };

    std::uint8_t const keccak_rot[5][5] =
    {
        {0, 36, 3, 41, 18},
        {1, 44, 10, 45, 2},
        {62, 6, 43, 15, 61},
        {28, 55, 25, 21, 56},
        {27, 20, 39, 8, 14}
    };

#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_STATE)
    void transpose(std::uint64_t const s[5][5], std::uint64_t d[5][5])
    {
        for (std::size_t x = 0; x < 5; ++x)
        {
            for (std::size_t y = 0; y < 5; ++y)
            {
                d[x][y] = s[y][x];
            }
        }
    }
#elif (SHA3_TRANSPOSE == SHA3_TRANSPOSE_INPUT)
    std::size_t transpose(std::size_t i)
    {
        // it appears that gcc doesn't optimize div(x, 8), manually use and/shift instead
        auto qr = std::div(int(i >> 3), 5);
        return (((qr.rem * 5) + qr.quot) * 8 + (i & 7));
    }
#endif

    std::uint64_t keccak_rotl(std::uint64_t x, std::uint64_t y)
    {
        return ((x << y) | (x >> (64 - y)));
    }

#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_NONE)
    void keccak_round(std::uint64_t state[5][5], std::uint64_t RC)
    {
        std::uint64_t BCD[5][5];
        /* theta */
        for (std::size_t x = 0; x < 5; ++x)
        {
            BCD[0][x] = state[0][x] ^ state[1][x] ^ state[2][x] ^ state[3][x] ^ state[4][x];
        }
        for (std::size_t x = 0; x < 5; ++x)
        {
            std::uint64_t v = BCD[0][(x + 4) % 5] ^ keccak_rotl(BCD[0][(x + 1) % 5], 1);
            for (std::size_t y = 0; y < 5; ++y)
            {
                state[y][x] ^= v;
            }
        }
        /* rho pi */
        for (std::size_t x = 0; x < 5; ++x)
        {
            for (std::size_t y = 0; y < 5; ++y)
            {
                BCD[((2 * x) + (3 * y)) % 5][y] = keccak_rotl(state[y][x], keccak_rot[x][y]);
            }
        }
        /* chi */
        for (std::size_t x = 0; x < 5; ++x)
        {
            for (std::size_t y = 0; y < 5; ++y)
            {
                state[y][x] = BCD[y][x] ^ ((~BCD[y][(x + 1) % 5] & BCD[y][(x + 2) % 5]));
            }
        }
        /* iota */
        state[0][0] ^= RC;
    }
#else
    void keccak_round(std::uint64_t state[5][5], std::uint64_t RC)
    {
        std::uint64_t BCD[5][5];
        /* theta */
        for (std::size_t x = 0; x < 5; ++x)
        {
            BCD[x][0] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }
        for (std::size_t x = 0; x < 5; ++x)
        {
            std::uint64_t v = BCD[(x + 4) % 5][0] ^ keccak_rotl(BCD[(x + 1) % 5][0], 1);
            for (std::size_t y = 0; y < 5; ++y)
            {
                state[x][y] ^= v;
            }
        }
        /* rho pi */
        for (std::size_t x = 0; x < 5; ++x)
        {
            for (std::size_t y = 0; y < 5; ++y)
            {
                BCD[y][((2 * x) + (3 * y)) % 5] = keccak_rotl(state[x][y], keccak_rot[x][y]);
            }
        }
        /* chi */
        for (std::size_t x = 0; x < 5; ++x)
        {
            for (std::size_t y = 0; y < 5; ++y)
            {
                state[x][y] = BCD[x][y] ^ ((~BCD[(x + 1) % 5][y] & BCD[(x + 2) % 5][y]));
            }
        }
        /* iota */
        state[0][0] ^= RC;
    }
#endif

    void keccak_f(std::uint64_t state[5][5])
    {
#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_STATE)
        std::uint64_t ST[5][5];
        auto s = ST;
        transpose(state, s);
#else
        auto s = state;
#endif
        for (std::size_t r = 0; r < 24; ++r)
        {
            keccak_round(s, keccak_rc[r]);
        }
#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_STATE)
        transpose(s, state);
#endif
    }

    struct sha3
    {
        std::uint8_t digest;
        std::uint8_t block;
        std::uint64_t index;
        std::uint64_t state[5][5];
    };

    void init(sha3 &sha, std::uint8_t digest_size)
    {
        std::memset(sha.state, 0, 5 * 5 * 8);
        sha.index = 0;
        sha.digest = digest_size;
        sha.block = (5 * 5 * 8) - (2 * digest_size);
    }

    void update(sha3 &sha, const std::uint8_t *input, std::size_t size)
    {
        auto * state = reinterpret_cast<std::uint8_t *>(sha.state);

        for (std::uint32_t i = 0; i < size; i++)
        {
#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_INPUT)
            state[transpose(sha.index++)] ^= input[i];
#else
            state[sha.index++] ^= input[i];
#endif
            if (sha.index == sha.block)
            {
                keccak_f(sha.state);
                sha.index = 0;
            }
        }
    }

    void finalize(sha3 &sha, std::uint8_t *output)
    {
        std::uint8_t * state = reinterpret_cast<std::uint8_t *>(sha.state);
#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_INPUT)
        state[transpose(sha.index)] ^= 0x06;
        state[transpose(sha.block - 1)] ^= 0x80;
#else
        state[sha.index] ^= 0x06;
        state[sha.block - 1] ^= 0x80;
#endif
        keccak_f(sha.state);
#if (SHA3_TRANSPOSE == SHA3_TRANSPOSE_INPUT)
        for (std::size_t i = 0; i < 4; ++i)
        {
            std::memcpy(output + (i * 8), sha.state[i], 8);
        }
#else
        std::memcpy(output, state, sha.digest);
#endif
    }

    void sha3_x(void const *data, std::size_t data_size, void *digest, std::size_t digest_size)
    {
        sha3 sha;
        init(sha, digest_size);
        update(sha, reinterpret_cast<std::uint8_t const *>(data), data_size);
        finalize(sha, reinterpret_cast<std::uint8_t *>(digest));
    }
}

void sha3_224(void const *data, std::size_t size, void *digest)
{
    sha3_x(data, size, digest, 28);
}

void sha3_256(void const *data, std::size_t size, void *digest)
{
    sha3_x(data, size, digest, 32);
}

void sha3_512(void const *data, std::size_t size, void *digest)
{
    sha3_x(data, size, digest, 64);
}
