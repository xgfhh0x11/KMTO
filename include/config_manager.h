#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "mitigation_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Configuration manager context
typedef struct config_manager_context config_manager_context_t;

// Initialize configuration manager
config_manager_context_t* config_manager_init(const char* config_file);

// Cleanup configuration manager
void config_manager_cleanup(config_manager_context_t* ctx);

// Load configuration from file
bool config_manager_load(config_manager_context_t* ctx, mitigation_config_t* config);

// Save configuration to file
bool config_manager_save(config_manager_context_t* ctx, const mitigation_config_t* config);

// Create configuration matrix (all combinations)
typedef struct {
    mitigation_config_t* configs;
    size_t count;
} config_matrix_t;

config_matrix_t* config_manager_create_matrix(config_manager_context_t* ctx);

void config_manager_free_matrix(config_matrix_t* matrix);

// Get default configuration
mitigation_config_t config_manager_get_default(void);

// Validate configuration
bool config_manager_validate(const mitigation_config_t* config);

// Print configuration
void config_manager_print(const mitigation_config_t* config);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_MANAGER_H

