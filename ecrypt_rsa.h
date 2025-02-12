#include "ecrypt_main.h"
#include <cryptopp/rsa.h>

namespace ecrypt { namespace asymmetric { namespace rsa {
	struct key_pair_t
	{
		std::string sk;
		std::string pk;
	};
	struct encryptor
	{
		key_pair_t* generate_keys(key_pair_t* kp, size_t key_size = 4096)
		{
			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::RSA::PrivateKey sk;
			CryptoPP::RSA::PublicKey pk;
			sk.GenerateRandomWithKeySize(rng, key_size);
			pk = CryptoPP::RSA::PublicKey(sk);

			CryptoPP::StringSink ss(kp->sk);
			sk.DEREncode(ss);

			CryptoPP::StringSink ps(kp->pk);
			pk.DEREncode(ps);

			return kp;
		}

		std::string* encrypt(const std::string& input, const key_pair_t& kp, std::string* result)
		{
			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::RSA::PublicKey pk;
			CryptoPP::StringSource ps(kp.pk, true);
			pk.BERDecode(ps);

			CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(pk);
			CryptoPP::StringSource(input, true, new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(*result)));

			return result;
		}

		std::string* decrypt(const std::string& input, const key_pair_t& kp, std::string* result)
		{
			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::RSA::PrivateKey sk;
			CryptoPP::StringSource ss(kp.sk, true);
			sk.BERDecode(ss);

			CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(sk);
			CryptoPP::StringSource(input, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(*result)));

			return result;
		}
	};
}}}
