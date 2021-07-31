#include "sha3.h"

#include <cstdlib>
#include <cstring>
#include <cstdint>

namespace
{
    std::uint64_t const keccak_rc[24] =
    {
        0x0000000000000001ULL,
        0x0000000000008082ULL,
        0x800000000000808aULL,
        0x8000000080008000ULL,
        0x000000000000808bULL,
        0x0000000080000001ULL,
        0x8000000080008081ULL,
        0x8000000000008009ULL,
        0x000000000000008aULL,
        0x0000000000000088ULL,
        0x0000000080008009ULL,
        0x000000008000000aULL,
        0x000000008000808bULL,
        0x800000000000008bULL,
        0x8000000000008089ULL,
        0x8000000000008003ULL,
        0x8000000000008002ULL,
        0x8000000000000080ULL,
        0x000000000000800aULL,
        0x800000008000000aULL,
        0x8000000080008081ULL,
        0x8000000000008080ULL,
        0x0000000080000001ULL,
        0x8000000080008008ULL
    };

    std::uint8_t const keccak_rot[5][5] =
    {
        { 0, 36,  3, 41, 18},
        { 1, 44, 10, 45,  2},
        {62,  6, 43, 15, 61},
        {28, 55, 25, 21, 56},
        {27, 20, 39,  8, 14}
    };

    std::uint64_t rotl(std::uint64_t x, std::uint64_t y)
    {
        return ((x << y) | (x >> (64 - y)));
    }

    class sha3
    {
        using State = std::uint64_t[5][5];

        std::size_t digest;
        std::size_t block;
        std::uint64_t index;
        State state;

        void keccak_round(std::uint64_t r)
        {
            State bcd;
            /* theta */
            for (std::size_t x = 0; x < 5; ++x)
            {
                bcd[0][x] = state[0][x] ^ state[1][x] ^ state[2][x] ^ state[3][x] ^ state[4][x];
            }
            for (std::size_t x = 0; x < 5; ++x)
            {
                std::uint64_t v = bcd[0][(x + 4) % 5] ^ rotl(bcd[0][(x + 1) % 5], 1);
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
                    bcd[((2 * x) + (3 * y)) % 5][y] = rotl(state[y][x], keccak_rot[x][y]);
                }
            }
            /* chi */
            for (std::size_t x = 0; x < 5; ++x)
            {
                for (std::size_t y = 0; y < 5; ++y)
                {
                    state[y][x] = bcd[y][x] ^ ((~bcd[y][(x + 1) % 5] & bcd[y][(x + 2) % 5]));
                }
            }
            /* iota */
            state[0][0] ^= r;
        }

        void keccak_f()
        {
            for (std::size_t r = 0; r < 24; ++r)
            {
                keccak_round(keccak_rc[r]);
            }
        }

    public:
        void begin(std::size_t size)
        {
            std::memset(state, 0, sizeof (State));
            index = 0;
            digest = size;
            block = (5 * 5 * 8) - (2 * size);
        }

        void append(std::uint8_t const * input, std::size_t size)
        {
            auto * s = reinterpret_cast<std::uint8_t *>(state);

            for (std::uint32_t i = 0; i < size; i++)
            {
                s[index++] ^= input[i];
                if (index == block)
                {
                    keccak_f();
                    index = 0;
                }
            }
        }

        void end(std::uint8_t * output)
        {
            auto * s = reinterpret_cast<std::uint8_t *>(state);
            s[index] ^= 0x06;
            s[block - 1] ^= 0x80;
            keccak_f();
            std::memcpy(output, state, digest);
        }
    };

    void sha3_x(void const * data, std::size_t data_size, void * digest, std::size_t digest_size)
    {
        sha3 sha;
        sha.begin(digest_size);
        sha.append(reinterpret_cast<std::uint8_t const *>(data), data_size);
        sha.end(reinterpret_cast<std::uint8_t *>(digest));
    }
}

void sha3_224(void const * data, std::size_t size, void * digest)
{
    sha3_x(data, size, digest, SHA3_224_DIGEST_SIZE);
}

void sha3_256(void const * data, std::size_t size, void * digest)
{
    sha3_x(data, size, digest, SHA3_256_DIGEST_SIZE);
}

void sha3_512(void const * data, std::size_t size, void * digest)
{
    sha3_x(data, size, digest, SHA3_512_DIGEST_SIZE);
}
