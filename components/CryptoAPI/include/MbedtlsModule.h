#ifndef MBEDTLS_MODULE
#define MBEDTLS_MODULE

#include "ICryptoModule.h"
#include "CryptoApiCommons.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <string>

class MbedtlsModule : public ICryptoModule
{
public:
  MbedtlsModule(CryptoApiCommons &commons);

  int init(Algorithms algorithm, Hashes hash, size_t _);
  int get_signature_size();

  int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length);
  void close();

  int hash_message(const unsigned char *message, size_t message_length, unsigned char *hash);
  int base64_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);

  size_t get_public_key_size();
  size_t get_public_key_pem_size();
  int get_public_key_pem(unsigned char *public_key_pem);

  size_t get_private_key_size();

  void save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size);
  void save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size);
  void save_signature(const char *file_path, const unsigned char *signature, size_t sig_len);

  void load_file(const char *file_path, unsigned char *buffer, size_t buffer_size);

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