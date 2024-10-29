#include "MbedtlsModule.h"
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>

static const char *TAG = "MbedtlsModule";

MbedtlsModule::MbedtlsModule(CryptoApiCommons &commons) : commons(commons) {}

int MbedtlsModule::init(Algorithms algorithm, Hashes hash)
{
  // if (!SPIFFS.begin(true))
  // {
  //   commons.log_error("SPIFFS.begin");
  // }

  commons.set_chosen_algorithm(algorithm);
  commons.set_chosen_hash(hash);

  mbedtls_pk_type_t pk_type;
  if (commons.get_chosen_algorithm() == Algorithms::RSA)
  {
    pk_type = MBEDTLS_PK_RSA;
  }
  else
  {
    pk_type = MBEDTLS_PK_ECKEY;
  }

  mbedtls_pk_init(&pk_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const unsigned char pers[] = "personalized_data";

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
  if (ret != 0)
  {
    commons.log_error("mbedtls_ctr_drbg_seed");
    return ret;
  }

  ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(pk_type));
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_setup");
    return ret;
  }

  commons.log_success("init");
  return 0;
}

int MbedtlsModule::gen_keys()
{
  mbedtls_ecp_group_id group_id = get_ecc_group_id();

  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  int ret = mbedtls_ecp_gen_key(group_id, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0)
  {
    commons.log_error("mbedtls_ecp_gen_key");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_gen_keys");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_gen_keys");

  commons.log_success("gen_keys");
  return 0;
}

int MbedtlsModule::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
  this->rsa_key_size = rsa_key_size;

  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  int ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg, rsa_key_size, rsa_exponent);
  if (ret != 0)
  {
    commons.log_error("mbedtls_rsa_gen_key");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_gen_keys");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_gen_keys");

  commons.log_success("gen_keys");
  return 0;
}

int MbedtlsModule::sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length)
{
  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  ret = mbedtls_pk_sign(&pk_ctx, get_hash_type(), hash, hash_length, signature, get_signature_size(), signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_sign");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_sign");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_sign");

  free(hash);

  commons.log_success("sign");
  return 0;
}

int MbedtlsModule::verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length)
{
  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  ret = mbedtls_pk_verify(&pk_ctx, get_hash_type(), hash, hash_length, signature, signature_length);
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_verify");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_verify");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_verify");

  free(hash);

  commons.log_success("verify");
  return 0;
}

int MbedtlsModule::hash_message(const unsigned char *message, size_t message_length, unsigned char *hash)
{
  switch (commons.get_chosen_hash())
  {
  case Hashes::MY_SHA_256:
    return mbedtls_sha256(message, message_length, hash, 0);
  case Hashes::MY_SHA_512:
    return mbedtls_sha512(message, message_length, hash, 0);
  case Hashes::MY_SHA3_256:
    return mbedtls_sha3(MBEDTLS_SHA3_256, message, message_length, hash, 32);
  default:
    return mbedtls_sha256(message, message_length, hash, 0);
  }
}

mbedtls_md_type_t MbedtlsModule::get_hash_type()
{
  switch (commons.get_chosen_hash())
  {
  case Hashes::MY_SHA_256:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA256;
  case Hashes::MY_SHA_512:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA512;
  case Hashes::MY_SHA3_256:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA3_256;
  default:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA256;
  }
}

mbedtls_ecp_group_id MbedtlsModule::get_ecc_group_id()
{
  switch (commons.get_chosen_algorithm())
  {
  case ECDSA_SECP256R1:
    return MBEDTLS_ECP_DP_SECP256R1;
  case ECDSA_SECP521R1:
    return MBEDTLS_ECP_DP_SECP521R1;
  case ECDSA_BP256R1:
    return MBEDTLS_ECP_DP_BP256R1;
  default:
    return MBEDTLS_ECP_DP_BP512R1;
  }
}

int MbedtlsModule::get_pub_key(char *buffer, const int buffer_length)
{
  int ret = mbedtls_pk_write_pubkey_pem(&pk_ctx, (unsigned char *)buffer, buffer_length);
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_write_pubkey_pem");
    return ret;
  }

  commons.log_success("get_pub_key");
  return 0;
}

int MbedtlsModule::get_signature_size()
{
  return commons.get_chosen_algorithm() == Algorithms::RSA ? rsa_key_size : ecdsa_sig_max_len;
}

void MbedtlsModule::close()
{
  mbedtls_pk_free(&pk_ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  ESP_LOGI(TAG, "> mbedtls closed.");
}