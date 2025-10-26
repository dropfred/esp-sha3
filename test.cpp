#include <cstdint>
#include <cstring>
#include <cstdio>

#include "sha3.h"

namespace
{
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

    struct
    {
        char const * txt;
        struct
        {
            char const * sha3_224;
            char const * sha3_256;
            char const * sha3_512;
        } hash;
    } const TEST[] =
    {
        {
            .txt = "",
            .hash =
            {
                .sha3_224 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                .sha3_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                .sha3_512 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            }
        },
        {
            .txt = "fred",
            .hash =
            {
                .sha3_224 = "47ff7f7707e40de7e531bbf75fd5f6dfa1b1ae9a3033fae0b4c1bece",
                .sha3_256 = "901e5b95a7c6f4c25f1dbb31931585a1aac6cac21eb1f09a39411f5ba4e710d6",
                .sha3_512 = "9d15efc1b71e0143a4daad34d5bb2e97d4968d80269e49c633aac69cc13d990b25295685eacb5b29eb584a1f6dd92a8e91e257c0c493a869310bee0b8a2ef440"
            }
        },
        {
            .txt = "qwerty",
            .hash =
            {
                .sha3_224 = "13783bdfa4a63b202d9aa1992eccdd68a9fa5e44539273d8c2b797cd",
                .sha3_256 = "f171cbb35dd1166a20f99b5ad226553e122f3c0f2fe981915fb9e4517aac9038",
                .sha3_512 = "f6d1015e17df348f2d84b3b603648ae4bd14011f4e5b82f885e45587bcad48947d37d64501dc965c0f201171c44b656ee28ed9a5060aea1f2a336025320683d6"
            }
        },
        {
            .txt = "0123456789",
            .hash =
            {
                .sha3_224 = "06aa5c957a256ce91b3db10862fb3b5bbc77f2b621a57dba88ad0167",
                .sha3_256 = "8f8eaad16cbf8722a2165b660d47fcfd8496a41c611da758f3bb70f809f01ee3",
                .sha3_512 = "62610b14fcd9f4abeab6ed1cb4ec99e7441be250e62b805e3a92811d31f2a170d1a801e0e0fc15cf5f28f0c508c3f3d9295c6ddddad9b7250140f6b27c641346"
            }
        }
    };
}

#define SHA3_CHECK(t, s)                                           \
do {                                                               \
    std::uint8_t d[SHA3_ ## s ##_DIGEST_SIZE];                     \
    char hd[sizeof d * 2 + 1];                                     \
    sha3_## s(t.txt, std::strlen(t.txt), d);                       \
    hex(d, hd, sizeof d);                                          \
    bool ok = std::strcmp(hd, t.hash.sha3_ ## s) == 0;             \
    std::printf("sha3_" #s "(%s): %s\n", t.txt, ok ? "OK" : "KO"); \
} while (false)

extern "C" void app_main()
{
    for (auto const & t : TEST)
    {
        SHA3_CHECK(t, 224);
        SHA3_CHECK(t, 256);
        SHA3_CHECK(t, 512);
    }
}
