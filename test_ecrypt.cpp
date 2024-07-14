#include <iostream>
#include <string>
#include "ecrypt_sha512.h"
#include "ecrypt_encode_hex.h"
#include "ecrypt_encode_base64.h"

int main(int argc, char** argv)
{
	std::string data_to_hash = "Hello, World!";
	std::string data_final = "";
	std::string data_final_64 = "";

	ecrypt::sha512::digest sha512;
	sha512.inrcalc(data_to_hash.data(), data_to_hash.size());
	ecrypt::encode::hex::iencoder hex;
	ecrypt::encode::base64::iencoder base64;
	size_t result_len = hex.encode_get_size(sha512.digest, ecrypt::sha512::digest_size);
	size_t result_len64 = base64.encode_get_size(sha512.digest, ecrypt::sha512::digest_size);
	data_final.resize(result_len);
	data_final_64.resize(result_len64);
	hex.nrencode(sha512.digest, ecrypt::sha512::digest_size, reinterpret_cast<unsigned char*>(data_final.data()), result_len);
	base64.nrencode(sha512.digest, ecrypt::sha512::digest_size, reinterpret_cast<unsigned char*>(data_final_64.data()), result_len64);

	std::cout << "Data to hash: " << data_to_hash << "\nData final [hex]: " << data_final << "\n";
	std::cout << "Data final [base64]: " << data_final_64 << "\n";

	return 0;
}
