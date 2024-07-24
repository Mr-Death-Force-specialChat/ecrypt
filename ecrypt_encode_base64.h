#include "ecrypt_main.h"
#include <cryptopp/base64.h>

namespace ecrypt { namespace encode { namespace base64
{
	struct encoder
	{
		void nrencode_get_size(const unsigned char* data, const size_t& data_len, size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();
			result_len = encoder.MaxRetrievable();
		}
		void nrencode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();

			encoder.Get(result, result_len);
		}

		size_t encode_get_size(const unsigned char* data, const size_t& data_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();
			return encoder.MaxRetrievable();
		}
		unsigned char* encode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();

			encoder.Get(result, result_len);
			return result;
		}
	};

	struct iencoder
	{
		inline void nrencode_get_size(const unsigned char* data, const size_t& data_len, size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();
			result_len = encoder.MaxRetrievable();
		}
		inline void nrencode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();

			encoder.Get(result, result_len);
		}

		inline size_t encode_get_size(const unsigned char* data, const size_t& data_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();
			return encoder.MaxRetrievable();
		}
		inline unsigned char* encode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Put(data, data_len);
			encoder.MessageEnd();

			encoder.Get(result, result_len);
			return result;
		}
	};


	struct decoder
	{
		void nrdeode_get_size(const unsigned char* data, const size_t& data_len, size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();
			result_len = decoder.MaxRetrievable();
		}
		void nrdecode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();

			decoder.Get(result, result_len);
		}

		size_t decode_get_size(const unsigned char* data, const size_t& data_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();
			return decoder.MaxRetrievable();
		}
		unsigned char* decode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();

			decoder.Get(result, result_len);
			return result;
		}
	};

	struct idecoder
	{
		inline void nrdecode_get_size(const unsigned char* data, const size_t& data_len, size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();
			result_len = decoder.MaxRetrievable();
		}
		inline void nrdecode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();

			decoder.Get(result, result_len);
		}

		inline size_t decode_get_size(const unsigned char* data, const size_t& data_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();
			return decoder.MaxRetrievable();
		}
		inline unsigned char* decode(const unsigned char* data, const size_t& data_len, unsigned char* result, const size_t& result_len)
		{
			CryptoPP::Base64Decoder decoder;
			decoder.Put(data, data_len);
			decoder.MessageEnd();

			decoder.Get(result, result_len);
			return result;
		}
	};
}}}
