#ifndef MBEDTLS_MODULE
#define MBEDTLS_MODULE

#include "CryptoApiCommons.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <string>

class MbedtlsModule
{
public:
  MbedtlsModule(CryptoApiCommons &commons);

  int init(Algorithms algorithm, Hashes hash);
  int get_signature_size();

  int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length);
  void close();

  int hash_message(const unsigned char *message, size_t message_length, unsigned char *hash);
  int get_pub_key(char *buffer, const int buffer_length);

private:
  CryptoApiCommons &commons;
  mbedtls_pk_context pk_ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  static const int ecdsa_sig_max_len = MBEDTLS_ECDSA_MAX_LEN;
  unsigned int rsa_key_size;

  mbedtls_md_type_t get_hash_type();
  mbedtls_ecp_group_id get_ecc_group_id();
};

#endif