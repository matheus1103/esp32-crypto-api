#ifndef MICROECC_MODULE
#define MICROECC_MODULE

#include "CryptoApiCommons.h"
#include "uECC.h"

#define MY_ECC_256_KEY_SIZE 32

class MbedtlsModule;

class MicroeccModule
{
public:
  MicroeccModule(CryptoApiCommons &commons);

  int init(Hashes hash);

  int gen_keys();

  int sign(const uint8_t *message, size_t message_length, uint8_t *signature);
  int verify(const uint8_t *message, size_t message_length, const uint8_t *signature);
  void close();

private:
  CryptoApiCommons &commons;
  MbedtlsModule *mbedtls_module;
  uint8_t *private_key;
  uint8_t *public_key;
  static int rng_function(uint8_t *dest, unsigned size);
};

#endif