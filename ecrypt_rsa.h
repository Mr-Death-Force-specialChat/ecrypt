#include "ecrypt_main.h"
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>

namespace ecrypt { namespace asymmetric { namespace rsa {
	struct key_pair_t
	{
		std::string sk;
		std::string pk;

		static key_pair_t* generate_keys(key_pair_t* kp, size_t key_size = 4096)
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
	};
	struct encryptor
	{
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
	struct signer
	{
		std::string* sign(const std::string& input, const key_pair_t& kp, std::string* signature)
		{
			CryptoPP::RSA::PrivateKey sk;
			CryptoPP::StringSource ss(kp.sk, true);
			sk.BERDecode(ss);

			CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA512>::Signer s(sk);
			signature->resize(s.MaxSignatureLength());
			CryptoPP::AutoSeededRandomPool rng;

			s.SignMessage(
				rng,
				reinterpret_cast<const unsigned char*>(input.data()),
				input.size(),
				reinterpret_cast<unsigned char*>(signature->data()));

			return signature;
		}
		int verify(const std::string& input, const std::string& signature, const key_pair_t& kp)
		{
			CryptoPP::RSA::PublicKey pk;
			CryptoPP::StringSource ps(kp.pk, true);
			pk.BERDecode(ps);

			CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA512>::Verifier v(pk);
			CryptoPP::AutoSeededRandomPool rng;

			int result = 0;
			CryptoPP::StringSource ss(
					signature + input,
					true,
					new CryptoPP::SignatureVerificationFilter(
						v,
						new CryptoPP::ArraySink(
							reinterpret_cast<unsigned char*>(&result),
							sizeof(result))));

			return result;
		}
	};
}}}
