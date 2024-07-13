#include "ecrypt_main.h"

namespace ecrypt { namespace sha512
{
	constexpr int digest_size = CryptoPP::SHA512::DIGESTSIZE;
	struct digest
	{
		unsigned char digest[digest_size];

		const unsigned char* calc(void* data, size_t data_len)
		{
			CryptoPP::SHA512().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
			return digest;
		}
		void nrcalc(void* data, size_t data_len)
		{
			CryptoPP::SHA512().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
		}

		inline const unsigned char* icalc(void* data, size_t data_len)
		{
			CryptoPP::SHA512().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
			return digest;
		}
		inline void inrcalc(void* data, size_t data_len)
		{
			CryptoPP::SHA512().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
		}
	};
}}
