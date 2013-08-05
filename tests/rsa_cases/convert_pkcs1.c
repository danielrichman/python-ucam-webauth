#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(int argc, char **argv)
{
    EVP_PKEY *key;
    RSA *rsa;
    int r;

    key = PEM_read_PUBKEY(stdin, NULL, NULL, NULL);
    if (key == NULL) return 1;

    rsa = EVP_PKEY_get1_RSA(key);
    if (key == NULL) return 1;

    r = PEM_write_RSAPublicKey(stdout, rsa);
    if (!r) return 1;

    return 0;
}
