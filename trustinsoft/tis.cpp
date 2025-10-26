#include <sha3.h>

#include <cstdint>

#include <trustinsoft/tis_helper.h>

#ifndef TEST_SIZE
#define TEST_SIZE 100
#endif

int main()
{
    {
        char data[TEST_SIZE];
        tis_make_unknown(data, sizeof data);

        #define TEST __LINE__
        #define SHA3(S) do { \
            std::uint8_t digest[SHA3_##S##_DIGEST_SIZE]; \
            sha3_##S(data, tis_unsigned_int_interval(0,  sizeof data), digest); \
        } while (false)

        while (tis_unknown_b())
        {
            switch (tis_unknown_si())
            {
            case TEST: SHA3(224); break;
            case TEST: SHA3(256); break;
            case TEST: SHA3(512); break;
            }
        }
    }

    return 0;
}

