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
}

void setup()
{
	Serial.begin(115200); while (!Serial);
}

void loop()
{
	std::uint8_t digest[SHA3_256_DIGEST_SIZE];
	char hash[SHA3_256_DIGEST_SIZE * 2 + 1];
	String data;

	while (true)
	{
		if (Serial.available() > 0)
		{
			char c = Serial.read();
			if (c == '\n') break;
			data += c;
		}
		else
		{
			delay(10);
		}
	}	

	auto dt = micros();
	sha3_256(data.c_str(), data.length(), digest);
	dt = micros() - dt;
	
	hex(digest, hash, SHA3_256_DIGEST_SIZE);
	Serial.print("sha3-256("); Serial.print(data); Serial.print(") : "); Serial.print(hash); Serial.print(" ("); Serial.print(dt); Serial.println(" us)");
}
