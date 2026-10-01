#ifndef MITIGATION_DETECTOR_H
#define MITIGATION_DETECTOR_H

#include "mitigation_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Detect available mitigations on the current system
mitigation_config_t detect_mitigations(void);

// Check if specific mitigation is enabled
bool is_mitigation_enabled(mitigation_config_t* config, mitigation_type_t type);

// Get CPU features (x86_64)
uint32_t get_cpu_features_x86(void);

// Get CPU features (ARM64)
uint32_t get_cpu_features_arm64(void);

// Check SMEP bit in CR4
bool check_smep_cr4(uint64_t cr4);

// Check SMAP bit in CR4
bool check_smap_cr4(uint64_t cr4);

// Detect PAC support (ARM64)
bool detect_pac_arm64(void);

// Get PAC key (requires kernel mode or special privileges)
uint64_t get_pac_key(pac_key_domain_t domain);

#ifdef __cplusplus
}
#endif

#endif // MITIGATION_DETECTOR_H

