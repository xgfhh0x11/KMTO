/* strdup() is POSIX; glibc hides it under a strict -std=c11 compile unless a
 * feature-test macro is set before any system header. Without the declaration
 * the compiler assumes an int return and truncates the pointer on LP64. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "config_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

struct config_manager_context {
    char* config_file;
    bool initialized;
};

config_manager_context_t* config_manager_init(const char* config_file) {
    config_manager_context_t* ctx = (config_manager_context_t*)calloc(1, sizeof(config_manager_context_t));
    if (!ctx) return NULL;
    
    if (config_file) {
        ctx->config_file = strdup(config_file);
    }
    
    ctx->initialized = true;
    return ctx;
}

void config_manager_cleanup(config_manager_context_t* ctx) {
    if (ctx) {
        if (ctx->config_file) {
            free(ctx->config_file);
        }
        free(ctx);
    }
}

bool config_manager_load(config_manager_context_t* ctx, mitigation_config_t* config) {
    if (!ctx || !config) return false;
    
    if (!ctx->config_file) {
        // Return default if no config file specified
        *config = config_manager_get_default();
        return true;
    }
    
    FILE* f = fopen(ctx->config_file, "r");
    if (!f) {
        *config = config_manager_get_default();
        return false;
    }
    
    // Simple text-based config format
    char line[256];
    *config = config_manager_get_default();
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SMEP=", 5) == 0) {
            config->smep_enabled = (line[5] == '1');
            if (config->smep_enabled) {
                config->enabled_mitigations |= MITIGATION_SMEP;
            }
        } else if (strncmp(line, "SMAP=", 5) == 0) {
            config->smap_enabled = (line[5] == '1');
            if (config->smap_enabled) {
                config->enabled_mitigations |= MITIGATION_SMAP;
            }
        } else if (strncmp(line, "PAC=", 4) == 0) {
            config->pac_enabled = (line[4] == '1');
            if (config->pac_enabled) {
                config->enabled_mitigations |= MITIGATION_PAC;
            }
        } else if (strncmp(line, "CFG=", 4) == 0) {
            config->cfg_enabled = (line[4] == '1');
            if (config->cfg_enabled) {
                config->enabled_mitigations |= MITIGATION_CFG;
            }
        } else if (strncmp(line, "KASLR=", 6) == 0) {
            config->kaslr_enabled = (line[6] == '1');
            if (config->kaslr_enabled) {
                config->enabled_mitigations |= MITIGATION_KASLR;
            }
        } else if (strncmp(line, "KASLR_BASE=", 12) == 0) {
            sscanf(line + 12, "%llx", (unsigned long long*)&config->kaslr_base);
        }
    }
    
    fclose(f);
    return true;
}

bool config_manager_save(config_manager_context_t* ctx, const mitigation_config_t* config) {
    if (!ctx || !config) return false;
    
    if (!ctx->config_file) return false;
    
    FILE* f = fopen(ctx->config_file, "w");
    if (!f) return false;
    
    fprintf(f, "# Mitigation Configuration\n");
    fprintf(f, "SMEP=%d\n", config->smep_enabled ? 1 : 0);
    fprintf(f, "SMAP=%d\n", config->smap_enabled ? 1 : 0);
    fprintf(f, "PAC=%d\n", config->pac_enabled ? 1 : 0);
    fprintf(f, "CFG=%d\n", config->cfg_enabled ? 1 : 0);
    fprintf(f, "KASLR=%d\n", config->kaslr_enabled ? 1 : 0);
    if (config->kaslr_enabled) {
        fprintf(f, "KASLR_BASE=0x%016llx\n", (unsigned long long)config->kaslr_base);
    }
    
    fclose(f);
    return true;
}

config_matrix_t* config_manager_create_matrix(config_manager_context_t* ctx) {
    (void)ctx; // Unused for now
    
    // Create all combinations of SMEP/SMAP/PAC
    // 2^3 = 8 combinations
    config_matrix_t* matrix = (config_matrix_t*)calloc(1, sizeof(config_matrix_t));
    if (!matrix) return NULL;
    
    matrix->count = 8;
    matrix->configs = (mitigation_config_t*)calloc(8, sizeof(mitigation_config_t));
    if (!matrix->configs) {
        free(matrix);
        return NULL;
    }
    
    for (int i = 0; i < 8; i++) {
        mitigation_config_t* cfg = &matrix->configs[i];
        *cfg = config_manager_get_default();
        
        cfg->smep_enabled = (i & 1) != 0;
        cfg->smap_enabled = (i & 2) != 0;
        cfg->pac_enabled = (i & 4) != 0;
        
        if (cfg->smep_enabled) cfg->enabled_mitigations |= MITIGATION_SMEP;
        if (cfg->smap_enabled) cfg->enabled_mitigations |= MITIGATION_SMAP;
        if (cfg->pac_enabled) cfg->enabled_mitigations |= MITIGATION_PAC;
    }
    
    return matrix;
}

void config_manager_free_matrix(config_matrix_t* matrix) {
    if (matrix) {
        if (matrix->configs) {
            free(matrix->configs);
        }
        free(matrix);
    }
}

mitigation_config_t config_manager_get_default(void) {
    mitigation_config_t config = {0};
    // Default: all mitigations disabled (will be detected)
    return config;
}

bool config_manager_validate(const mitigation_config_t* config) {
    if (!config) return false;
    
    // Basic validation
    // SMEP and SMAP are x86_64 only
    // PAC is ARM64 only
    // Can't have both enabled simultaneously in this framework
    
    return true;
}

void config_manager_print(const mitigation_config_t* config) {
    if (!config) return;
    
    printf("=== Mitigation Configuration ===\n");
    printf("SMEP: %s\n", config->smep_enabled ? "ENABLED" : "DISABLED");
    printf("SMAP: %s\n", config->smap_enabled ? "ENABLED" : "DISABLED");
    printf("PAC:  %s\n", config->pac_enabled ? "ENABLED" : "DISABLED");
    printf("CFG:  %s\n", config->cfg_enabled ? "ENABLED" : "DISABLED");
    printf("KASLR: %s", config->kaslr_enabled ? "ENABLED" : "DISABLED");
    if (config->kaslr_enabled) {
        printf(" (Base: 0x%016llx)", (unsigned long long)config->kaslr_base);
    }
    printf("\n");
    printf("Enabled mitigations mask: 0x%08x\n", config->enabled_mitigations);
}

