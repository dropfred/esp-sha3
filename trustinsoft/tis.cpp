#include <sha3.h>

#include <cstdint>

#ifdef TIS_INTERPRETER
#include <cstdlib>
#include <cstring>
#else
#include <tis_builtin.h>
#endif

#ifndef TEST_SIZE
#define TEST_SIZE 1000
#endif

namespace
{
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

        static Test const test_224[] =
        {
            {""          , "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
            {"fred"      , "47ff7f7707e40de7e531bbf75fd5f6dfa1b1ae9a3033fae0b4c1bece"},
            {"azerty"    , "531d2cd029cff83dac224c43910ac8ca229738bed3e17711d5d3e34a"},
            {"qwerty"    , "13783bdfa4a63b202d9aa1992eccdd68a9fa5e44539273d8c2b797cd"},
            {"0123456789", "06aa5c957a256ce91b3db10862fb3b5bbc77f2b621a57dba88ad0167"}
        };
        static Test const test_256[] =
        {
            {""          , "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
            {"fred"      , "901e5b95a7c6f4c25f1dbb31931585a1aac6cac21eb1f09a39411f5ba4e710d6"},
            {"azerty"    , "f47f0b8a0050d885d55380c08edc99d5d6cffdb04e8f45a7bf8a360857bc5ccb"},
            {"qwerty"    , "f171cbb35dd1166a20f99b5ad226553e122f3c0f2fe981915fb9e4517aac9038"},
            {"0123456789", "8f8eaad16cbf8722a2165b660d47fcfd8496a41c611da758f3bb70f809f01ee3"}
        };
        static Test const test_512[] =
        {
            {""          , "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
            {"fred"      , "9d15efc1b71e0143a4daad34d5bb2e97d4968d80269e49c633aac69cc13d990b25295685eacb5b29eb584a1f6dd92a8e91e257c0c493a869310bee0b8a2ef440"},
            {"azerty"    , "577af03daf806da0b879ec38178966f4c2f597f842b1ac1dfa36e5cda8084dfc95f5fc35082b8ee72701e7ec8455a0b416359ea19cb9d640ce796cf443e4f497"},
            {"qwerty"    , "f6d1015e17df348f2d84b3b603648ae4bd14011f4e5b82f885e45587bcad48947d37d64501dc965c0f201171c44b656ee28ed9a5060aea1f2a336025320683d6"},
            {"0123456789", "62610b14fcd9f4abeab6ed1cb4ec99e7441be250e62b805e3a92811d31f2a170d1a801e0e0fc15cf5f28f0c508c3f3d9295c6ddddad9b7250140f6b27c641346"}
        };

        for (auto const & t : test_224)
        {
            char hd[SHA3_224_DIGEST_SIZE * 2 + 1];
            sha3_224(t.txt, std::strlen(t.txt), digest_224);
            hex(digest_224, hd, SHA3_224_DIGEST_SIZE);
            bool ok = std::strcmp(hd, t.hash) == 0;
            //@ assert ok;
            ok = true;
        }

        for (auto const & t : test_256)
        {
            char hd[SHA3_256_DIGEST_SIZE * 2 + 1];
            sha3_256(t.txt, std::strlen(t.txt), digest_256);
            hex(digest_256, hd, SHA3_256_DIGEST_SIZE);
            bool ok = std::strcmp(hd, t.hash) == 0;
            //@ assert ok;
        }

        for (auto const & t : test_512)
        {
            char hd[SHA3_512_DIGEST_SIZE * 2 + 1];
            sha3_512(t.txt, std::strlen(t.txt), digest_512);
            hex(digest_512, hd, SHA3_512_DIGEST_SIZE);
            bool ok = std::strcmp(hd, t.hash) == 0;
            //@ assert ok;
        }
    }
    {
        char data[TEST_SIZE];
        make_rand(data, sizeof data);
        sha3_224(data, sizeof data, digest_224);
        sha3_256(data, sizeof data, digest_256);
        sha3_512(data, sizeof data, digest_512);
    }
#else
    {
        char data[TEST_SIZE];
        tis_make_unknown(data, sizeof data);

        {
            std::uint8_t digest[SHA3_224_DIGEST_SIZE];
            sha3_224(data, sizeof data, digest);
        }
        {
            std::uint8_t digest[SHA3_256_DIGEST_SIZE];
            sha3_256(data, sizeof data, digest);
        }
        {
            std::uint8_t digest[SHA3_512_DIGEST_SIZE];
            sha3_512(data, sizeof data, digest);
        }
    }
#endif

    return 0;
}
