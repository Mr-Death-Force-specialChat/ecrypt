#include "ecrypt_main.h"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

namespace ecrypt { namespace weak { namespace md5
{
	constexpr int digest_size = CryptoPP::Weak::MD5::DIGESTSIZE;
	struct digest
	{
		unsigned char digest[digest_size];

		const unsigned char* calc(void* data, size_t data_len)
		{
			CryptoPP::Weak::MD5().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
			return digest;
		}
		void nrcalc(void* data, size_t data_len)
		{
			CryptoPP::Weak::MD5().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
		}

		inline const unsigned char* icalc(void* data, size_t data_len)
		{
			CryptoPP::Weak::MD5().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
			return digest;
		}
		inline void inrcalc(void* data, size_t data_len)
		{
			CryptoPP::Weak::MD5().CalculateDigest(digest, reinterpret_cast<const unsigned char*>(data), data_len);
		}
	};
}}}
