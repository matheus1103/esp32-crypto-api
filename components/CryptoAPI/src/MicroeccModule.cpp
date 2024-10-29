#include "MicroeccModule.h"
#include "MbedtlsModule.h"
#include "esp_random.h"

static const char *TAG = "MicroeccModule";

MicroeccModule::MicroeccModule(CryptoApiCommons &commons) : commons(commons)
{
  mbedtls_module = new MbedtlsModule(commons);
}

const struct uECC_Curve_t *curve = uECC_secp256r1();

int MicroeccModule::init(Hashes hash)
{
  commons.set_chosen_hash(hash);

  unsigned int seed = esp_random();
  srandom(seed);
  uECC_set_rng(&MicroeccModule::rng_function);

  commons.log_success("init");
  return 0;
}

int MicroeccModule::gen_keys()
{
  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t private_key_size = MY_ECC_256_KEY_SIZE;
  size_t public_key_size = private_key_size * 2;

  private_key = (uint8_t *)malloc(private_key_size * sizeof(uint8_t));
  public_key = (uint8_t *)malloc(public_key_size * sizeof(uint8_t));

  int ret = uECC_make_key(public_key, private_key, uECC_secp256r1());
  if (ret == 0)
  {
    commons.log_error("uECC_make_key");
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "micro_gen_keys");
  commons.print_used_memory(initial_memory, final_memory, "micro_gen_keys");

  commons.print_hex(private_key, private_key_size);
  commons.print_hex(public_key, public_key_size);

  commons.log_success("gen_keys");
  return 0;
}

int MicroeccModule::sign(const uint8_t *message, size_t message_length, uint8_t *signature)
{
  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = mbedtls_module->hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  ret = uECC_sign(private_key, hash, hash_length, signature, uECC_secp256r1());
  if (ret == 0)
  {
    commons.log_error("uECC_sign");
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "micro_sign");
  commons.print_used_memory(initial_memory, final_memory, "micro_sign");

  free(hash);

  commons.log_success("sign");
  return 0;
}

int MicroeccModule::verify(const uint8_t *message, size_t message_length, const uint8_t *signature)
{
  int initial_memory = esp_get_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = mbedtls_module->hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  ret = uECC_verify(public_key, hash, hash_length, signature, uECC_secp256r1());
  if (ret != 1)
  {
    commons.log_error("uECC_verify");
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_free_heap_size();

  commons.print_elapsed_time(start_time, end_time, "micro_verify");
  commons.print_used_memory(initial_memory, final_memory, "micro_verify");

  free(hash);

  commons.log_success("verify");
  return 0;
}

void MicroeccModule::close()
{
  free(private_key);
  free(public_key);
  ESP_LOGI(TAG, "> microecc closed.");
}

int MicroeccModule::rng_function(uint8_t *dest, unsigned size)
{
  // Fill dest with `size` random bytes
  while (size--)
  {
    *dest++ = (uint8_t)(esp_random() & 0xFF); // Mask to get a byte (0-255)
  }
  return 1; // Return 1 to indicate success
}