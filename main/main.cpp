#include <stdio.h>
#include "CryptoAPI.h"

#define MY_RSA_KEY_SIZE 4096
#define MY_RSA_EXPONENT 65537

static const char *TAG = "Main";

static const char private_key_path[] = "/littlefs/private_key.pem";
static const char public_key_path[] = "/littlefs/public_key.pem";
static const char signature_path[] = "/littlefs/signature.bin";

static const unsigned char message[] = "Hello crypto library world!";
static const size_t message_length = sizeof(message);

CryptoAPI crypto_api;

int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length);

extern "C" void app_main(void)
{
    int ret = perform_tests(Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_512, 1024);
    ESP_LOGI(TAG, "Finished status: %d", ret);
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

    size_t public_key_pem_size = crypto_api.get_public_key_pem_size();
    unsigned char *public_key_pem = (unsigned char *)malloc(public_key_pem_size * sizeof(unsigned char));
    ret = crypto_api.get_public_key_pem(public_key_pem);

    ESP_LOGI(TAG, "public_key_pem_size: %d", public_key_pem_size);
    ESP_LOGI(TAG, "public_key_pem:\n%s", public_key_pem);
    if (ret != 0)
    {
        return ret;
    }

    // // saving keys and signature
    // size_t private_key_size = 512; // crypto_api.get_private_key_size();
    // ESP_LOGI(TAG, "private_key_size: %d", crypto_api.get_private_key_size());

    // unsigned char *private_key = (unsigned char *)malloc(private_key_size * sizeof(unsigned char));
    // crypto_api.save_private_key(private_key_path, private_key, private_key_size);
    // ESP_LOGI(TAG, "Saved Private Key (PEM):\n%s", (char *)private_key);

    // size_t public_key_size = 512; // crypto_api.get_public_key_size();
    // ESP_LOGI(TAG, "public_key_size size: %d", crypto_api.get_public_key_size());

    // unsigned char *public_key = (unsigned char *)malloc(public_key_size * sizeof(unsigned char));
    // crypto_api.save_public_key(public_key_path, public_key, public_key_size);
    // ESP_LOGI(TAG, "Saved Public Key (PEM):\n%s", (char *)public_key);

    size_t signature_length = crypto_api.get_signature_size();
    ESP_LOGI(TAG, "signature_length: %zu", signature_length);

    unsigned char *signature = (unsigned char *)malloc(signature_length * sizeof(unsigned char));
    ESP_LOG_BUFFER_HEX("Signature", signature, signature_length);

    ret = crypto_api.sign(message, message_length, signature, &signature_length);
    if (ret != 0)
    {
        return ret;
    }

    ret = crypto_api.verify(message, message_length, signature, signature_length);
    if (ret != 0)
    {
        return ret;
    }

    // // loading keys and signature from memory
    // long private_key_file_size = crypto_api.get_file_size(private_key_path);
    // ESP_LOGI(TAG, "private_key_file_size: %ld", private_key_file_size);

    // unsigned char *loaded_private_key = (unsigned char *)malloc((private_key_file_size + 1) * sizeof(unsigned char)); // +1 for null terminator

    // crypto_api.load_private_key(private_key_path, loaded_private_key, private_key_file_size);
    // ESP_LOGI(TAG, "Loaded Private Key (PEM):\n%s", (char *)loaded_private_key);

    // long public_key_file_size = crypto_api.get_file_size(public_key_path);
    // ESP_LOGI(TAG, "public_key_file_size: %ld", public_key_file_size);

    // unsigned char *loaded_public_key = (unsigned char *)malloc((public_key_file_size + 1) * sizeof(unsigned char)); // +1 for null terminator

    // crypto_api.load_public_key(public_key_path, loaded_public_key, public_key_file_size);
    // ESP_LOGI(TAG, "Loaded Public Key (PEM):\n%s", (char *)loaded_public_key);

    // long loaded_sig_file_size = crypto_api.get_file_size(signature_path);
    // ESP_LOGI(TAG, "loaded_key_file_size: %ld", loaded_sig_file_size);

    // unsigned char *loaded_signature = (unsigned char *)malloc(loaded_sig_file_size * sizeof(unsigned char));
    // crypto_api.load_signature(signature_path, loaded_signature, loaded_sig_file_size);
    // ESP_LOG_BUFFER_HEX("Signature", loaded_signature, loaded_sig_file_size);

    crypto_api.close();

    free(signature);

    return 0;
}