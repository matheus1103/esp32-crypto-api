#include "CryptoApiCommons.h"

static const char *TAG = "CryptoApiCommons";

CryptoApiCommons::CryptoApiCommons() {}

Algorithms CryptoApiCommons::get_chosen_algorithm()
{
  return chosen_algorithm;
}

void CryptoApiCommons::set_chosen_algorithm(Algorithms algorithm)
{
  chosen_algorithm = algorithm;
}

Hashes CryptoApiCommons::get_chosen_hash()
{
  return chosen_hash;
}

void CryptoApiCommons::set_chosen_hash(Hashes hash)
{
  chosen_hash = hash;
}

void CryptoApiCommons::set_shake256_hash_length(size_t length)
{
  shake256_hash_length = length;
}

size_t CryptoApiCommons::get_hash_length()
{
  switch (chosen_hash)
  {
  case Hashes::MY_SHA_256:
    return 32;
  case Hashes::MY_SHA_512:
    return 64;
  case Hashes::MY_SHA3_256:
    return 32;
  case Hashes::MY_SHAKE_256:
    return shake256_hash_length;
  default:
    return 32;
  }
}

void CryptoApiCommons::save_pub_key(const char *pubkey_filename, char *public_key_pem, const int buffer_length)
{
  // ESP_LOGI(TAG, "Saving public key PEM...");

  // File pubkey_file = SPIFFS.open(pubkey_filename, "w");
  // if (!pubkey_file)
  // {
  //   ESP_LOGE(TAG, "Failed to open pubkey file for writing");
  // }

  // size_t bytes_written = pubkey_file.write((const uint8_t *)public_key_pem, buffer_length);
  // if (bytes_written != buffer_length)
  // {
  //   ESP_LOGE(TAG, "Error writing to pubkey file");
  // }

  // pubkey_file.close();
}

// std::string CryptoApiCommons::load_pub_key(const char *pubkey_filename)
// {
// Serial.println("Loading public key PEM...");

// File pubkey_file = SPIFFS.open(pubkey_filename, "r");
// if (!pubkey_file)
// {
//   Serial.println("Failed to open public key file");
//   pubkey_file.close();
//   return "error";
// }

// std::string public_key_pem;
// while (pubkey_file.available())
// {
//   public_key_pem += (char)pubkey_file.read();
// }
// pubkey_file.close();

// return public_key_pem;
// }

void CryptoApiCommons::print_hex(const uint8_t *data, size_t length)
{
  // Use ESP_LOG_BUFFER_HEX to log the hex representation of a buffer
  ESP_LOG_BUFFER_HEX(TAG, data, length);
}

void CryptoApiCommons::log_success(const char *msg)
{
  ESP_LOGI(TAG, "SUCCESS AT %s", msg);
}

void CryptoApiCommons::log_error(const char *msg)
{
  ESP_LOGE(TAG, "Failed at %s", msg);
}

void CryptoApiCommons::print_elapsed_time(unsigned long start, unsigned long end, const char *label)
{
  ESP_LOGI(TAG, "%s time: %lu ms", label, end - start);
}

void CryptoApiCommons::print_used_memory(unsigned long initial, unsigned long final, const char *label)
{
  ESP_LOGI(TAG, "%s memory: %lu bytes", label, initial - final);
}