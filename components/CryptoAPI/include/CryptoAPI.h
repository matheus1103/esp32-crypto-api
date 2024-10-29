#include "CryptoApiCommons.h"

#ifndef CRYPTO_API
#define CRYPTO_API

enum Libraries
{
  MBEDTLS_LIB,
  WOLFSSL_LIB,
  MICROECC_LIB
};

class MbedtlsModule;
class WolfsslModule;
class MicroeccModule;

class CryptoAPI
{
public:
  CryptoAPI();
  ~CryptoAPI();

  int init(Libraries lib, Algorithms algorithm, Hashes hash, size_t length_of_shake256);
  int get_signature_size();

  int gen_rsa_keys(int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length);
  int sign(const unsigned char *message, size_t message_length, unsigned char *signature);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature);
  void close();

  Algorithms get_chosen_algorithm();
  Libraries get_chosen_library();

private:
  CryptoApiCommons commons;
  MbedtlsModule *mbedtls_module;
  WolfsslModule *wolfssl_module;
  MicroeccModule *microecc_module;
  Libraries chosen_library;

  void print_init_configuration(Libraries library, Algorithms algorithm, Hashes hash, size_t length_of_shake256);
};

#endif