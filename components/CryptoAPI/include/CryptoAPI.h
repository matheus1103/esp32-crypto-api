#include "CryptoApiCommons.h"
#include "ICryptoModule.h"

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

class CryptoAPI : public ICryptoModule
{
public:
  CryptoAPI();
  ~CryptoAPI();

  int init(Libraries lib, Algorithms algorithm, Hashes hash, size_t length_of_shake256);
  int init(Algorithms algorithm, Hashes hash, size_t length_of_shake256);
  int get_signature_size();

  int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length);
  void close();

  size_t get_public_key_size();
  size_t get_public_key_pem_size();
  int get_public_key_pem(unsigned char *public_key_pem);

  Algorithms get_chosen_algorithm();
  Libraries get_chosen_library();

  // file operations:

  // void save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size);
  // void save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size);
  // void save_signature(const char *file_path, const unsigned char *signature, size_t sig_len);

  // void load_private_key(const char *file_path, unsigned char *private_key, size_t file_size);
  // void load_public_key(const char *file_path, unsigned char *public_key, size_t file_size);
  // void load_signature(const char *file_path, unsigned char *signature, size_t file_size);

  // long get_file_size(const char *file_path);
  // size_t get_private_key_size();

private:
  CryptoApiCommons commons;
  MbedtlsModule *mbedtls_module;
  WolfsslModule *wolfssl_module;
  MicroeccModule *microecc_module;
  Libraries chosen_library;

  void print_init_configuration(Libraries library, Algorithms algorithm, Hashes hash, size_t length_of_shake256);
};

#endif