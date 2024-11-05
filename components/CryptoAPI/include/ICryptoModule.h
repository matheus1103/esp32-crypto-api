#include "CryptoApiCommons.h"

#ifndef I_CRYPTO_MODULE
#define I_CRYPTO_MODULE

class ICryptoModule
{
public:
  virtual ~ICryptoModule() {}

  virtual int init(Algorithms algorithm, Hashes hash, size_t length_of_shake256) = 0;
  virtual int get_signature_size() = 0;

  virtual int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent) = 0;
  virtual int gen_keys() = 0;

  virtual int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length) = 0;
  virtual int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length) = 0;
  virtual void close() = 0;

  virtual size_t get_public_key_size() = 0;
  virtual size_t get_public_key_pem_size() = 0;
  virtual int get_public_key_pem(unsigned char *public_key_pem) = 0;
};

#endif