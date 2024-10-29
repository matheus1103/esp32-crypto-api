#include <stdio.h>
#include "CryptoAPI.h"

#define MY_RSA_KEY_SIZE 2048
#define MY_RSA_EXPONENT 65537

CryptoAPI crypto_api;

int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length);

extern "C" void app_main(void)
{
    int ret = perform_tests(Libraries::WOLFSSL_LIB, Algorithms::RSA, Hashes::MY_SHA3_256, 1024);
}

int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length)
{
    int ret = crypto_api.init(library, algorithm, hash, shake_256_length);
    if (ret != 0)
    {
        return ret;
    }

    if (crypto_api.get_chosen_algorithm() == Algorithms::RSA)
    {
        ret = crypto_api.gen_rsa_keys(MY_RSA_KEY_SIZE, MY_RSA_EXPONENT);
    }
    else
    {
        ret = crypto_api.gen_keys();
    }

    if (ret != 0)
    {
        return ret;
    }

    const unsigned char message[] = "Hello crypto library world!";
    size_t message_length = sizeof(message);

    const unsigned char other_message[] = "Hello crypto library world!";
    size_t other_message_length = sizeof(other_message);

    size_t signature_length = crypto_api.get_signature_size();
    unsigned char *signature = (unsigned char *)malloc(signature_length * sizeof(unsigned char));

    if (crypto_api.get_chosen_library() == Libraries::MICROECC_LIB)
    {
        ret = crypto_api.sign(message, message_length, signature);
        if (ret != 0)
        {
            return ret;
        }

        ret = crypto_api.verify(other_message, other_message_length, signature);
        if (ret != 0)
        {
            return ret;
        }
    }
    else
    {
        ret = crypto_api.sign(message, message_length, signature, &signature_length);
        if (ret != 0)
        {
            return ret;
        }

        ret = crypto_api.verify(other_message, other_message_length, signature, signature_length);
        if (ret != 0)
        {
            return ret;
        }
    }

    crypto_api.close();

    free(signature);

    return 0;
}