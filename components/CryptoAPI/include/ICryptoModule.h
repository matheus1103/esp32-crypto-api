#include "Common.h"

#ifndef I_CRYPTO_MODULE
#define I_CRYPTO_MODULE

class ICryptoModule
{
public:
  virtual ~ICryptoModule() {}
  virtual void init(Algorithms algorithm, Hashes hash) = 0;
  virtual void gen_keys() = 0;
  virtual void gen_keys(unsigned int rsa_key_size, int rsa_exponent) = 0;
  virtual void sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length) = 0;
  virtual void verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length) = 0;
  virtual void close() = 0;
};

#endif