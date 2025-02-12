#include <iostream>
#include <string>
#include "ecrypt_sha512.h"
#include "ecrypt_encode_hex.h"
#include "ecrypt_encode_base64.h"
#include "ecrypt_aes.h"
#include "ecrypt_rsa.h"

int main(int argc, char** argv)
{
	/*
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
	*/

	/*
	std::string data_to_encrypt = "super_secret_stuff_or_whatever1234%^&*\nazerty\rqwerty\n";
	std::string data_final = "";
	std::string data_decrypted = "";
	std::string data_to_encrypt1 = "super_secret_password_and_stuff123$%^7\razerty\nqwerty\n";
	std::string data_final1 = "";
	std::string data_decrypted1 = "";

	ecrypt::symmetric::aes::aes_key_t key;
	ecrypt::symmetric::aes::encryptor aes;
	aes.nrgenerate_key(&key);
	data_final = *aes.encrypt(data_to_encrypt, key, &data_final);
	data_final1 = *aes.encrypt(data_to_encrypt1, key, &data_final1);
	data_decrypted = *aes.decrypt(data_final, key, &data_decrypted);
	data_decrypted1 = *aes.decrypt(data_final1, key, &data_decrypted1);
	printf("Original data:\n%s\n", data_to_encrypt.c_str());
	printf("Decrypted data:\n%s\n", data_decrypted.c_str());
	printf("Original data1:\n%s\n", data_to_encrypt1.c_str());
	printf("Decrypted data1:\n%s\n", data_decrypted1.c_str());
	*/

	std::string data_to_encrypt = "Logan \"The Goat\" Sargeant";
	std::string data_encrypted = "";
	std::string data_decrypted = "";
	ecrypt::asymmetric::rsa::key_pair_t kp;
	ecrypt::asymmetric::rsa::encryptor rsa;
	rsa.generate_keys(&kp);
	
	rsa.encrypt(data_to_encrypt, kp, &data_encrypted);
	rsa.decrypt(data_encrypted, kp, &data_decrypted);
	ecrypt::encode::base64::iencoder base64;
	std::string base64_sk = "";
	std::string base64_pk = "";
	std::string base64_ev = "";
	base64_sk = *base64.encode_all(kp.sk, &base64_sk);
	base64_pk = *base64.encode_all(kp.sk, &base64_pk);
	base64_ev = *base64.encode_all(kp.sk, &base64_ev);

	//printf("SK: %s\nPK: %s\nOV: %s\nEV: %s\nDV: %s\n", base64_sk.c_str(), base64_pk.c_str(), data_to_encrypt.c_str(), base64_ev.c_str(), data_decrypted.c_str());
	printf("OV: %s\nDV: %s\n", data_to_encrypt.c_str(), data_decrypted.c_str());
	return 0;
}
