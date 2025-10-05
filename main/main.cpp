#include <stdio.h>
#include "CryptoAPI.h"
#include "esp_system.h"
#include <esp_log.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <string.h>
#include "../experiments/test_strings_exact.h"
#include <driver/gpio.h>
#include <cmath>

static const char *TAG = "CryptoTest";

#define MY_RSA_KEY_SIZE 2048
#define MY_RSA_EXPONENT 65537
#define NUM_KEY_GENERATIONS 10
#define NUM_SIGN_TESTS 10
#define NUM_VERIFY_TESTS 10

CryptoAPI crypto_api;

// Estrutura expandida para medições detalhadas de memória
typedef struct {
    // Métricas de geração de chaves
    struct {
        int64_t time_us;
        size_t heap_start;
        size_t heap_end;
        size_t heap_used;
    } key_generation[NUM_KEY_GENERATIONS];
    
    // Métricas detalhadas de memória para operações cripto
    struct {
        size_t heap_base;           // Heap antes de qualquer operação
        size_t heap_after_init;     // Heap após init
        size_t heap_after_keygen;   // Heap após gerar chave
        size_t heap_after_first_sign;   // Heap após primeira assinatura
        size_t heap_after_first_verify; // Heap após primeira verificação
        
        size_t memory_init;         // Memória usada pelo init
        size_t memory_keygen;       // Memória usada pela chave
        size_t memory_first_sign;   // Memória da primeira assinatura (setup cost)
        size_t memory_first_verify; // Memória da primeira verificação
        size_t memory_incremental_sign;   // Memória das assinaturas subsequentes
        size_t memory_incremental_verify; // Memória das verificações subsequentes
    } memory_profile;
    
    // Métricas para cada tamanho de string
    struct {
        size_t string_size;
        
        // Primeira operação (com alocação de buffers)
        struct {
            int64_t time_us;
            size_t heap_used;
        } first_signature;
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } first_verification;
        
        // Operações subsequentes (reutilizando buffers)
        struct {
            int64_t time_us;
            size_t heap_used;
        } subsequent_signatures[NUM_SIGN_TESTS - 1];  // 9 medições
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } subsequent_verifications[NUM_VERIFY_TESTS - 1];  // 9 medições
        
    } string_tests[NUM_TEST_STRINGS];
    
} TestMetrics;

typedef struct {
    Libraries lib;
    Algorithms algo;
    Hashes hash;
    int rsa_key_size;
    const char* name;
    TestMetrics metrics;
} TestConfig;

// Configurações de teste
// Para benchmark completo mas prático
TestConfig test_configs[] = {
    // RSA básico
    // {Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_256, 2048, "MBEDTLS_RSA_2048_SHA256"},
    
   // ============ ECDSA P-256 (secp256r1) ============
    //{Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_P256_SHA256"},
    //{Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_P256_SHA512"},
    
    // // ============ ECDSA P-521 (secp521r1) ============
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_P521_SHA256"},
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_P521_SHA512"},
    
    // // ============ BRAINPOOL CURVES ============
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_BP256_SHA256"},
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_BP256_SHA512"},
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_BP512_SHA256"},
    // {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_BP512_SHA512"},
};

// Função auxiliar para estabilizar heap (simplificada)
void heap_stabilize() {
    vTaskDelay(pdMS_TO_TICKS(10));
}

// Função para executar medições detalhadas de memória
void execute_memory_profiling(TestConfig* config) {
    TestMetrics* metrics = &config->metrics;
    
    // ========== PERFIL DE MEMÓRIA INICIAL ==========
    heap_stabilize();
    metrics->memory_profile.heap_base = esp_get_free_heap_size();
    
    // Inicializar biblioteca
    crypto_api.init(config->lib, config->algo, config->hash, 0);
    heap_stabilize();
    metrics->memory_profile.heap_after_init = esp_get_free_heap_size();
    metrics->memory_profile.memory_init = 
        metrics->memory_profile.heap_base - metrics->memory_profile.heap_after_init;
    
    // Gerar uma chave para análise de memória
    if (config->algo == Algorithms::RSA) {
        crypto_api.gen_rsa_keys(config->rsa_key_size, MY_RSA_EXPONENT);
    } else {
        crypto_api.gen_keys();
    }
    heap_stabilize();
    metrics->memory_profile.heap_after_keygen = esp_get_free_heap_size();
    metrics->memory_profile.memory_keygen = 
        metrics->memory_profile.heap_after_init - metrics->memory_profile.heap_after_keygen;
    
    // Testar primeira assinatura (aloca buffers internos)
    static const unsigned char test_msg[] = "Memory profiling test";
    size_t test_msg_len = sizeof(test_msg) - 1;
    size_t sig_size = crypto_api.get_signature_size();
    unsigned char test_signature[512];  // Buffer estático para assinatura
    size_t test_sig_len = sig_size;

    crypto_api.sign(test_msg, test_msg_len, test_signature, &test_sig_len);
    heap_stabilize();
    metrics->memory_profile.heap_after_first_sign = esp_get_free_heap_size();
    metrics->memory_profile.memory_first_sign =
        metrics->memory_profile.heap_after_keygen - metrics->memory_profile.heap_after_first_sign;

    // Testar primeira verificação
    crypto_api.verify(test_msg, test_msg_len, test_signature, test_sig_len);
    heap_stabilize();
    metrics->memory_profile.heap_after_first_verify = esp_get_free_heap_size();
    metrics->memory_profile.memory_first_verify =
        metrics->memory_profile.heap_after_first_sign - metrics->memory_profile.heap_after_first_verify;

    // Limpar para próximas medições
    crypto_api.close();
    heap_stabilize();
}

// Função para executar testes sem logs
void execute_silent_measurements(TestConfig* config) {
    TestMetrics* metrics = &config->metrics;
    
    // ========== FASE 1: GERAÇÃO DE CHAVES (10x) ==========
    for (int k = 0; k < NUM_KEY_GENERATIONS; k++) {
        if (k > 0) {
            crypto_api.close();
            heap_stabilize();
        }
        
        metrics->key_generation[k].heap_start = esp_get_free_heap_size();
        
        int64_t start_time = esp_timer_get_time();
        
        int ret = crypto_api.init(config->lib, config->algo, config->hash, 0);
        if (ret == 0) {
            if (config->algo == Algorithms::RSA) {
                ret = crypto_api.gen_rsa_keys(config->rsa_key_size, MY_RSA_EXPONENT);
            } else {
                ret = crypto_api.gen_keys();
            }
        }
        
        int64_t end_time = esp_timer_get_time();
        
        metrics->key_generation[k].heap_end = esp_get_free_heap_size();
        metrics->key_generation[k].time_us = end_time - start_time;
        metrics->key_generation[k].heap_used = 
            metrics->key_generation[k].heap_start - metrics->key_generation[k].heap_end;
    }
    
    // Última chave permanece carregada
    
    // ========== FASE 2: ASSINATURA E VERIFICAÇÃO COM ANÁLISE DE MEMÓRIA ==========
    for (int s = 0; s < NUM_TEST_STRINGS; s++) {
        const unsigned char* msg = (const unsigned char*)test_strings[s];
        size_t msg_len = test_string_sizes[s];
        
        metrics->string_tests[s].string_size = msg_len;
        
        size_t sig_size = crypto_api.get_signature_size();
        unsigned char* signature = (unsigned char*)malloc(sig_size);
        size_t sig_len = sig_size;  // Variável para armazenar o tamanho real da assinatura

        if (signature == NULL) {
            for (int i = 0; i < NUM_SIGN_TESTS; i++) {
                if (i == 0) {
                    metrics->string_tests[s].first_signature.time_us = -1;
                    metrics->string_tests[s].first_signature.heap_used = 0;
                } else {
                    metrics->string_tests[s].subsequent_signatures[i-1].time_us = -1;
                    metrics->string_tests[s].subsequent_signatures[i-1].heap_used = 0;
                }
            }
            continue;
        }

        // === ASSINATURAS: Primeira vs Subsequentes ===
        for (int i = 0; i < NUM_SIGN_TESTS; i++) {
            sig_len = sig_size;  // Resetar para cada iteração
            size_t heap_before = esp_get_free_heap_size();

            int64_t start_time = esp_timer_get_time();
            crypto_api.sign(msg, msg_len, signature, &sig_len);
            int64_t end_time = esp_timer_get_time();

            size_t heap_after = esp_get_free_heap_size();

            if (i == 0) {
                // Primeira assinatura (pode alocar buffers internos)
                metrics->string_tests[s].first_signature.time_us = end_time - start_time;
                metrics->string_tests[s].first_signature.heap_used = heap_before - heap_after;
            } else {
                // Assinaturas subsequentes (reutilizam buffers)
                metrics->string_tests[s].subsequent_signatures[i-1].time_us = end_time - start_time;
                metrics->string_tests[s].subsequent_signatures[i-1].heap_used = heap_before - heap_after;
            }
        }

        // === VERIFICAÇÕES: Primeira vs Subsequentes ===
        for (int i = 0; i < NUM_VERIFY_TESTS; i++) {
            size_t heap_before = esp_get_free_heap_size();

            int64_t start_time = esp_timer_get_time();
            crypto_api.verify(msg, msg_len, signature, sig_len);  // Usar sig_len real
            int64_t end_time = esp_timer_get_time();

            size_t heap_after = esp_get_free_heap_size();

            if (i == 0) {
                // Primeira verificação
                metrics->string_tests[s].first_verification.time_us = end_time - start_time;
                metrics->string_tests[s].first_verification.heap_used = heap_before - heap_after;
            } else {
                // Verificações subsequentes
                metrics->string_tests[s].subsequent_verifications[i-1].time_us = end_time - start_time;
                metrics->string_tests[s].subsequent_verifications[i-1].heap_used = heap_before - heap_after;
            }
        }

        free(signature);
    }
    
    crypto_api.close();
}

// Função para calcular estatísticas
typedef struct {
    int64_t min;
    int64_t max;
    int64_t avg;
    int64_t median;
    int64_t std_dev;
} TimeStats;

TimeStats calculate_stats(int64_t* values, int count) {
    TimeStats stats = {0};
    if (count == 0) return stats;

    stats.min = values[0];
    stats.max = values[0];
    int64_t sum = 0;

    // Single pass para min, max e soma
    for (int i = 0; i < count; i++) {
        int64_t val = values[i];
        if (val < stats.min) stats.min = val;
        if (val > stats.max) stats.max = val;
        sum += val;
    }
    stats.avg = sum / count;

    // Calcular desvio padrão em um único loop
    int64_t variance_sum = 0;
    for (int i = 0; i < count; i++) {
        int64_t diff = values[i] - stats.avg;
        variance_sum += diff * diff;
    }
    stats.std_dev = (int64_t)sqrt((double)(variance_sum / count));

    stats.median = values[count / 2];

    return stats;
}

// Função para imprimir resultados detalhados
void print_all_results() {
    int num_configs = sizeof(test_configs) / sizeof(TestConfig);
    
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, "=======================================================");
    ESP_LOGI(TAG, "         RESULTADOS COMPLETOS - ANÁLISE DETALHADA     ");
    ESP_LOGI(TAG, "=======================================================");
    ESP_LOGI(TAG, "Heap livre atual: %lu bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "");
    
    for (int cfg = 0; cfg < num_configs; cfg++) {
        TestConfig* config = &test_configs[cfg];
        TestMetrics* metrics = &config->metrics;
        
        ESP_LOGI(TAG, "=======================================================");
        ESP_LOGI(TAG, "Configuração: %s", config->name);
        ESP_LOGI(TAG, "=======================================================");
        
        // === PERFIL DE MEMÓRIA ===
        ESP_LOGI(TAG, "\n--- PERFIL DE MEMÓRIA ---");
        ESP_LOGI(TAG, "Análise de alocação de memória:");
        ESP_LOGI(TAG, "  Heap base inicial:         %d bytes", metrics->memory_profile.heap_base);
        ESP_LOGI(TAG, "  Memória para init():       %d bytes", metrics->memory_profile.memory_init);
        ESP_LOGI(TAG, "  Memória para chave:        %d bytes", metrics->memory_profile.memory_keygen);
        ESP_LOGI(TAG, "  Memória 1ª assinatura:     %d bytes (setup cost)", 
                 metrics->memory_profile.memory_first_sign);
        ESP_LOGI(TAG, "  Memória 1ª verificação:    %d bytes", 
                 metrics->memory_profile.memory_first_verify);
        ESP_LOGI(TAG, "  TOTAL em uso:              %d bytes", 
                 metrics->memory_profile.memory_init + 
                 metrics->memory_profile.memory_keygen + 
                 metrics->memory_profile.memory_first_sign +
                 metrics->memory_profile.memory_first_verify);
        

        // === GERAÇÃO DE CHAVES ===
        ESP_LOGI(TAG, "\n--- GERAÇÃO DE CHAVES (10 gerações independentes) ---");

        int64_t key_times[NUM_KEY_GENERATIONS];
        for (int i = 0; i < NUM_KEY_GENERATIONS; i++) {
            key_times[i] = metrics->key_generation[i].time_us;
        }

        TimeStats key_stats = calculate_stats(key_times, NUM_KEY_GENERATIONS);

        ESP_LOGI(TAG, "Estatísticas de Tempo:");
        ESP_LOGI(TAG, "  Min: %.2f ms", key_stats.min / 1000.0);
        ESP_LOGI(TAG, "  Max: %.2f ms", key_stats.max / 1000.0);
        ESP_LOGI(TAG, "  Avg: %.2f ms", key_stats.avg / 1000.0);
        ESP_LOGI(TAG, "  Std: %.2f ms", key_stats.std_dev / 1000.0);
        ESP_LOGI(TAG, "  CV:  %.1f%%", (key_stats.std_dev * 100.0) / key_stats.avg);
        
        // === ASSINATURA E VERIFICAÇÃO POR TAMANHO ===
        ESP_LOGI(TAG, "\n--- ASSINATURA E VERIFICAÇÃO ---");
        ESP_LOGI(TAG, "Análise: Primeira operação vs Operações subsequentes\n");
        
        for (int s = 0; s < NUM_TEST_STRINGS; s++) {
            ESP_LOGI(TAG, ">>> Mensagem de %d bytes <<<", 
                     metrics->string_tests[s].string_size);
            
            // ASSINATURA - Análise detalhada
            ESP_LOGI(TAG, "ASSINATURA:");
            ESP_LOGI(TAG, "  Primeira (com alocação):");
            ESP_LOGI(TAG, "    Tempo: %.2f ms", 
                     metrics->string_tests[s].first_signature.time_us / 1000.0);
            ESP_LOGI(TAG, "    Heap:  %d bytes", 
                     metrics->string_tests[s].first_signature.heap_used);
            
            // Estatísticas das operações subsequentes
            int64_t sub_sign_times[NUM_SIGN_TESTS - 1];
            size_t total_incremental_heap = 0;
            for (int i = 0; i < NUM_SIGN_TESTS - 1; i++) {
                sub_sign_times[i] = metrics->string_tests[s].subsequent_signatures[i].time_us;
                total_incremental_heap += metrics->string_tests[s].subsequent_signatures[i].heap_used;
            }
            
            TimeStats sub_sign_stats = calculate_stats(sub_sign_times, NUM_SIGN_TESTS - 1);
            
            ESP_LOGI(TAG, "  Subsequentes (buffers reutilizados):");
            ESP_LOGI(TAG, "    Tempo médio: %.2f ms", sub_sign_stats.avg / 1000.0);
            ESP_LOGI(TAG, "    Heap médio:  %d bytes", total_incremental_heap / (NUM_SIGN_TESTS - 1));
            
            // VERIFICAÇÃO - Análise detalhada
            ESP_LOGI(TAG, "VERIFICAÇÃO:");
            ESP_LOGI(TAG, "  Primeira:");
            ESP_LOGI(TAG, "    Tempo: %.2f ms", 
                     metrics->string_tests[s].first_verification.time_us / 1000.0);
            ESP_LOGI(TAG, "    Heap:  %d bytes", 
                     metrics->string_tests[s].first_verification.heap_used);
            
            // Estatísticas das operações subsequentes
            int64_t sub_verify_times[NUM_VERIFY_TESTS - 1];
            total_incremental_heap = 0;
            for (int i = 0; i < NUM_VERIFY_TESTS - 1; i++) {
                sub_verify_times[i] = metrics->string_tests[s].subsequent_verifications[i].time_us;
                total_incremental_heap += metrics->string_tests[s].subsequent_verifications[i].heap_used;
            }
            
            TimeStats sub_verify_stats = calculate_stats(sub_verify_times, NUM_VERIFY_TESTS - 1);
            
            ESP_LOGI(TAG, "  Subsequentes:");
            ESP_LOGI(TAG, "    Tempo médio: %.2f ms", sub_verify_stats.avg / 1000.0);
            ESP_LOGI(TAG, "    Heap médio:  %d bytes", total_incremental_heap / (NUM_VERIFY_TESTS - 1));
            
            ESP_LOGI(TAG, "");
        }

        // === FORMATO CSV DETALHADO ===
        ESP_LOGI(TAG, "\n--- DADOS EM CSV (FORMATO DETALHADO) ---");
        ESP_LOGI(TAG, "Config,Operation,StringSize,Type,Iteration,Time_us,HeapUsed");

        // Key generation
        for (int i = 0; i < NUM_KEY_GENERATIONS; i++) {
            ESP_LOGI(TAG, "%s,KeyGen,0,Full,%d,%lld,%d",
                     config->name,
                     i,
                     metrics->key_generation[i].time_us,
                     metrics->key_generation[i].heap_used);
        }

        // Sign/Verify com distinção primeira vs subsequentes
        for (int s = 0; s < NUM_TEST_STRINGS; s++) {
            // Primeira assinatura
            ESP_LOGI(TAG, "%s,Sign,%d,First,0,%lld,%d",
                     config->name,
                     metrics->string_tests[s].string_size,
                     metrics->string_tests[s].first_signature.time_us,
                     metrics->string_tests[s].first_signature.heap_used);

            // Assinaturas subsequentes
            for (int i = 0; i < NUM_SIGN_TESTS - 1; i++) {
                ESP_LOGI(TAG, "%s,Sign,%d,Subsequent,%d,%lld,%d",
                         config->name,
                         metrics->string_tests[s].string_size,
                         i + 1,
                         metrics->string_tests[s].subsequent_signatures[i].time_us,
                         metrics->string_tests[s].subsequent_signatures[i].heap_used);
            }

            // Primeira verificação
            ESP_LOGI(TAG, "%s,Verify,%d,First,0,%lld,%d",
                     config->name,
                     metrics->string_tests[s].string_size,
                     metrics->string_tests[s].first_verification.time_us,
                     metrics->string_tests[s].first_verification.heap_used);

            // Verificações subsequentes
            for (int i = 0; i < NUM_VERIFY_TESTS - 1; i++) {
                ESP_LOGI(TAG, "%s,Verify,%d,Subsequent,%d,%lld,%d",
                         config->name,
                         metrics->string_tests[s].string_size,
                         i + 1,
                         metrics->string_tests[s].subsequent_verifications[i].time_us,
                         metrics->string_tests[s].subsequent_verifications[i].heap_used);
            }
        }

        ESP_LOGI(TAG, "");
    }
    
    // === RESUMO EXECUTIVO ===
    ESP_LOGI(TAG, "=======================================================");
    ESP_LOGI(TAG, "                  RESUMO EXECUTIVO                    ");
    ESP_LOGI(TAG, "=======================================================");
    
    for (int cfg = 0; cfg < num_configs; cfg++) {
        TestConfig* config = &test_configs[cfg];
        TestMetrics* metrics = &config->metrics;
        
        ESP_LOGI(TAG, "\n%s:", config->name);
        ESP_LOGI(TAG, "  Memória Total Necessária: %d bytes",
                 metrics->memory_profile.memory_init + 
                 metrics->memory_profile.memory_keygen + 
                 metrics->memory_profile.memory_first_sign);
        ESP_LOGI(TAG, "  - Setup inicial:     %d bytes", 
                 metrics->memory_profile.memory_init);
        ESP_LOGI(TAG, "  - Chave RSA-2048:    %d bytes", 
                 metrics->memory_profile.memory_keygen);
        ESP_LOGI(TAG, "  - Buffers operação:  %d bytes", 
                 metrics->memory_profile.memory_first_sign);
        ESP_LOGI(TAG, "  Custo incremental:   %d bytes (após setup)", 0);
        
        // Calcular tempo médio para operações principais
        int64_t total_sign_time = 0;
        int64_t total_verify_time = 0;
        int count = 0;
        
        for (int s = 0; s < NUM_TEST_STRINGS; s++) {
            for (int i = 0; i < NUM_SIGN_TESTS - 1; i++) {
                total_sign_time += metrics->string_tests[s].subsequent_signatures[i].time_us;
                count++;
            }
        }
        
        for (int s = 0; s < NUM_TEST_STRINGS; s++) {
            for (int i = 0; i < NUM_VERIFY_TESTS - 1; i++) {
                total_verify_time += metrics->string_tests[s].subsequent_verifications[i].time_us;
            }
        }
        
        ESP_LOGI(TAG, "  Tempo médio Sign:    %.2f ms", (total_sign_time / count) / 1000.0);
        ESP_LOGI(TAG, "  Tempo médio Verify:  %.2f ms", (total_verify_time / count) / 1000.0);
    }
    
    ESP_LOGI(TAG, "\n=======================================================");
    ESP_LOGI(TAG, "                   FIM DOS RESULTADOS                 ");
    ESP_LOGI(TAG, "=======================================================");
}

// Função principal de testes
void perform_complete_tests() {
    int num_configs = sizeof(test_configs) / sizeof(TestConfig);
    
    #define LED_PIN GPIO_NUM_8
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    
    // ========== FASE 1: PERFIL DE MEMÓRIA ==========
    for (int cfg = 0; cfg < num_configs; cfg++) {
        gpio_set_level(LED_PIN, 1);
        execute_memory_profiling(&test_configs[cfg]);
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // ========== FASE 2: MEDIÇÕES COMPLETAS EM SILÊNCIO ==========
    for (int cfg = 0; cfg < num_configs; cfg++) {
        gpio_set_level(LED_PIN, cfg % 2);
        execute_silent_measurements(&test_configs[cfg]);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    gpio_set_level(LED_PIN, 0);

    // ========== FASE 3: APRESENTAÇÃO DOS RESULTADOS ==========
    vTaskDelay(pdMS_TO_TICKS(1000));
    print_all_results();
}

extern "C" void app_main(void) {
    esp_task_wdt_deinit();
    
    ESP_LOGI(TAG, "=== ESP32C6 Crypto Benchmark v2.0 ===");
    ESP_LOGI(TAG, "Análise detalhada: Setup Cost vs Operational Cost");
    ESP_LOGI(TAG, "Heap inicial: %lu bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "Iniciando em 5 segundos...");
    
    vTaskDelay(pdMS_TO_TICKS(5000));
    
    perform_complete_tests();
    
    ESP_LOGI(TAG, "*** BENCHMARK FINALIZADO ***");
    ESP_LOGI(TAG, "Heap final: %lu bytes", esp_get_free_heap_size());
    
    while(1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}