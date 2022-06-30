#include "sha3.h"

// #include <cstddef>
#include <cstdint>
// #include <cstring>

#ifdef TIS_INTERPRETER
#include <cstdlib>
#include <cstring>
#else
#include <tis_builtin.h>
#endif

namespace
{
    // void test_0()
    // {
    //     std::uint8_t digest[SHA3_256_DIGEST_SIZE];
    //     sha3_256(nullptr, 0, digest);
    // }

#ifdef TIS_INTERPRETER
	void hex(void const * src, char * dst, std::size_t size)
	{
		static char const H[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		auto * s = static_cast<std::uint8_t const *>(src);
		auto * d = dst;
		for (auto i = size; i != 0; --i, ++s)
		{
			auto v = *s;
			*(d++) = H[v >> 4];
			*(d++) = H[v & 0x0f];
		}
		*d = 0;
	}

    void make_rand(void * data, std::size_t size)
    {
        std::uint8_t * p = static_cast<std::uint8_t *>(data);
        while (size > 0)
        {
            *p++ = std::uint8_t(std::rand());
            --size;
        }
    }
#endif
}

int main()
{
#ifdef TIS_INTERPRETER
    std::uint8_t digest_224[SHA3_224_DIGEST_SIZE];
    std::uint8_t digest_256[SHA3_256_DIGEST_SIZE];
    std::uint8_t digest_512[SHA3_512_DIGEST_SIZE];
    {
        struct Test
        {
            char const * txt;
            char const * hash;
        };
        Test const test[] =
        {
            {"fred"      , "901e5b95a7c6f4c25f1dbb31931585a1aac6cac21eb1f09a39411f5ba4e710d6"},
            {"azerty"    , "f47f0b8a0050d885d55380c08edc99d5d6cffdb04e8f45a7bf8a360857bc5ccb"},
            {"qwerty"    , "f171cbb35dd1166a20f99b5ad226553e122f3c0f2fe981915fb9e4517aac9038"},
            {"0123456789", "8f8eaad16cbf8722a2165b660d47fcfd8496a41c611da758f3bb70f809f01ee3"}
        };
        for (auto const & t : test)
        {
            char hd[SHA3_256_DIGEST_SIZE * 2 + 1];
            sha3_256(t.txt, std::strlen(t.txt), digest_256);
            hex(digest_256, hd, SHA3_256_DIGEST_SIZE);
            bool ok = std::strcmp(hd, t.hash) == 0;
            //@ assert ok;
        }
    }
    {
        char data[TEST_SIZE];
        make_rand(data, sizeof (data));
        sha3_224(data, sizeof (data), digest_224);
        sha3_256(data, sizeof (data), digest_256);
        sha3_512(data, sizeof (data), digest_512);
    }
#else
    {
        char data[TEST_SIZE];
        tis_make_unknown(data, sizeof (data));
        {
            std::uint8_t digest[SHA3_224_DIGEST_SIZE];
            sha3_224(data, sizeof (data), digest);
        }
        {
            std::uint8_t digest[SHA3_256_DIGEST_SIZE];
            sha3_256(data, sizeof (data), digest);
        }
        {
            std::uint8_t digest[SHA3_512_DIGEST_SIZE];
            sha3_512(data, sizeof (data), digest);
        }
    }
#endif

    return 0;
}
