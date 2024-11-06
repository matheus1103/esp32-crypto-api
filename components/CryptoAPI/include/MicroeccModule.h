#ifndef MICROECC_MODULE
#define MICROECC_MODULE

#include "ICryptoModule.h"
#include "CryptoApiCommons.h"
#include "uECC.h"

#define MY_ECC_256_PRIVATE_KEY_SIZE 32
#define MY_ECC_256_PUBLIC_KEY_SIZE 64

class MbedtlsModule;

class MicroeccModule : public ICryptoModule
{
public:
  MicroeccModule(CryptoApiCommons &commons, MbedtlsModule &mbedtls_module);

  int init(Algorithms _, Hashes hash, size_t __);
  int get_signature_size();

  int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *_);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t _);
  void close();

  size_t get_public_key_size();
  size_t get_public_key_pem_size();
  int get_public_key_pem(unsigned char *public_key_pem);

private:
  CryptoApiCommons &commons;
  MbedtlsModule &mbedtls_module;
  unsigned char *private_key;
  unsigned char *public_key;
  static int rng_function(unsigned char *dest, unsigned int size);
  int public_key_to_pem_format(unsigned char *public_key_buffer);
};

#endif