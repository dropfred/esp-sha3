#include "sha3.h"

namespace
{
	void hex(void const * src, char * dst, std::size_t size)
	{
		static char const H[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		auto * s = static_cast<std::uint8_t const *>(src);
		auto * d = dst;
		for (auto i = size; i > 0; --i, ++s)
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
  Serial.begin(115200);
  Serial.println("SHA3");
}

void loop() {
	std::uint8_t digest[SHA3_256_DIGEST_SIZE];
	char data[1000];
	std::uint32_t size = 0;
	char hash[SHA3_256_DIGEST_SIZE * 2 + 1];
	
	while (true)
	{
		if (Serial.available() > 0)
		{
			char c = Serial.read();
			if (c == '\n') break;
			data[size++] = c;
			if (size == 999) break;
		}
		else
		{
			delay(10);
		}
	}
	data[size] = 0;
	
	auto t0 = micros();
	sha3_256(data, size, digest);
	auto t1 = micros();
	
	hex(digest, hash, SHA3_256_DIGEST_SIZE);
	Serial.print("sha3-256("); Serial.print(data); Serial.print(") : "); Serial.print(hash); Serial.print(" ("); Serial.print(t1 - t0); Serial.println(" us)");
}
