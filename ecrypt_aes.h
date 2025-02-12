#include "ecrypt_main.h"

namespace ecrypt { namespace symmetric { namespace aes {
	static constexpr size_t AES_KEY_SIZE = 256 / 8; // AES-256
	struct aes_key_t
	{
		public:
		std::vector<uint8_t> key;
		std::vector<uint8_t> iv;
		aes_key_t()
		{
			key.resize(AES_KEY_SIZE);
			iv.resize(CryptoPP::AES::BLOCKSIZE);
		}
	};
	struct encryptor
	{
		void nrgenerate_key(aes_key_t* key)
		{
			CryptoPP::BlockingRng rng;
			rng.GenerateBlock(key->key.data(), key->key.size());
			rng.GenerateBlock(key->iv.data(), key->iv.size());
		}
		void nrencrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_encryptor = CryptoPP::AES::Encryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes_encryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));
		}
		void nrencrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			encrypt(input_str, key, result);
		}
		void nrdecrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_decryptor = CryptoPP::AES::Decryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes_decryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));
		}
		void nrdecrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			decrypt(input_str, key, result);
		}

		aes_key_t* generate_key(aes_key_t* key)
		{
			CryptoPP::BlockingRng rng;
			rng.GenerateBlock(key->key.data(), key->key.size());
			rng.GenerateBlock(key->iv.data(), key->iv.size());
			return key;
		}
		std::string* encrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_encryptor = CryptoPP::AES::Encryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes_encryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));

			return result;
		}
		std::string* encrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			return encrypt(input_str, key, result);
		}
		std::string* decrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_decryptor = CryptoPP::AES::Decryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes_decryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));

			return result;
		}
		std::string* decrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			return decrypt(input_str, key, result);
		}
	};
	struct iencryptor
	{
		inline void nrgenerate_key(aes_key_t* key)
		{
			CryptoPP::BlockingRng rng;
			rng.GenerateBlock(key->key.data(), key->key.size());
			rng.GenerateBlock(key->iv.data(), key->iv.size());
		}
		inline void nrencrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_encryptor = CryptoPP::AES::Encryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes_encryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));
		}
		inline void nrencrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			encrypt(input_str, key, result);
		}
		inline void nrdecrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_decryptor = CryptoPP::AES::Decryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes_decryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));
		}
		inline void nrdecrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			decrypt(input_str, key, result);
		}

		inline aes_key_t* generate_key(aes_key_t* key)
		{
			CryptoPP::BlockingRng rng;
			rng.GenerateBlock(key->key.data(), key->key.size());
			rng.GenerateBlock(key->iv.data(), key->iv.size());
			return key;
		}
		inline std::string* encrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_encryptor = CryptoPP::AES::Encryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes_encryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));

			return result;
		}
		inline std::string* encrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			return encrypt(input_str, key, result);
		}
		inline std::string* decrypt(const std::string& input, const aes_key_t& key, std::string* result)
		{
			auto aes_decryptor = CryptoPP::AES::Decryption(key.key.data(), key.key.size());
			auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes_decryptor, key.iv.data());

			CryptoPP::StringSource ss(
					input,
					true,
					new CryptoPP::StreamTransformationFilter(
						aes_cbc,
						new CryptoPP::StringSink(*result)));

			return result;
		}
		inline std::string* decrypt(const char* input, const aes_key_t& key, std::string* result)
		{
			std::string input_str(input);
			return decrypt(input_str, key, result);
		}
	};
}}}
