#include <string>
#include "pybind11/pybind11.h"
#include <openssl/sha.h>
#include <openssl/rand.h>


static char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

std::string calc_pow(const std::string &data)
{
	SHA_CTX cbase, c;
	SHA1_Init(&cbase);
	std::string beg = "commit " + std::to_string(data.size() + 20);
	beg += '\0';
	SHA1_Update(&cbase, beg.data(), beg.size());
	SHA1_Update(&cbase, data.data(), data.size());

	unsigned char digest[SHA_DIGEST_LENGTH];
	unsigned char message[20];
	while (1) {
		// Generate random message
		for (size_t i = 0; i < sizeof(message); ++i) {
			size_t randomnum;
			RAND_bytes((unsigned char*)&randomnum, sizeof(randomnum));
			message[i] = alphabet[randomnum % sizeof(alphabet)];
		}
		// Calc hash
		memcpy(&c, &cbase, sizeof(cbase));
		SHA1_Update(&c, message, 20);
		SHA1_Final(digest, &c);
		// Check digest
		if (digest[0] == '\x66' && (digest[1] & 0xf0) == (0x6 << 4))
			break;
	}

	return std::string((const char*)message, sizeof(message));
}

namespace py = pybind11;

PYBIND11_MODULE(pow, m) {
	m.def("calc_pow", calc_pow, py::arg("data"));
}
