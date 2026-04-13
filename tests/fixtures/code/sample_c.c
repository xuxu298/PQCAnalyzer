#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

int main() {
    // RSA key generation
    RSA_generate_key_ex(NULL, 2048, NULL, NULL);

    // EC key
    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    // MD5 (weak)
    EVP_md5();

    // SHA-1 (weak)
    EVP_sha1();

    // DES (broken)
    EVP_des_cbc();

    return 0;
}
