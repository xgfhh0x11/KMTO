#ifndef MITIGATION_TYPES_H
#define MITIGATION_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Mitigation types
typedef enum {
    MITIGATION_SMEP = 1 << 0,
    MITIGATION_SMAP = 1 << 1,
    MITIGATION_PAC  = 1 << 2,
    MITIGATION_CFG  = 1 << 3,
    MITIGATION_KCFG = 1 << 4,
    MITIGATION_KASLR = 1 << 5,
    MITIGATION_KPTI  = 1 << 6,
    MITIGATION_VBS   = 1 << 7,
    MITIGATION_HYPERGUARD = 1 << 8
} mitigation_type_t;

// Fault types
typedef enum {
    FAULT_NONE = 0,
    FAULT_SMEP_VIOLATION,
    FAULT_SMAP_VIOLATION,
    FAULT_PAC_AUTH_FAILURE,
    FAULT_GPF,
    FAULT_PAGE_FAULT,
    FAULT_CFG_VIOLATION,
    FAULT_UNKNOWN
} fault_type_t;

// Access type
typedef enum {
    ACCESS_READ,
    ACCESS_WRITE,
    ACCESS_EXECUTE,
    ACCESS_COPY_FROM_USER,
    ACCESS_COPY_TO_USER
} access_type_t;

// Memory domain
typedef enum {
    DOMAIN_USER,
    DOMAIN_KERNEL,
    DOMAIN_HYPERVISOR
} memory_domain_t;

// PAC key domain (ARM64)
typedef enum {
    PAC_KEY_A,  // Instruction pointer key
    PAC_KEY_B   // Data pointer key
} pac_key_domain_t;

// Test outcome
typedef struct {
    fault_type_t fault_type;
    uint64_t fault_address;
    memory_domain_t source_domain;
    memory_domain_t target_domain;
    access_type_t access_type;
    bool pac_verified;
    uint64_t timestamp;
    uint32_t call_stack_depth;
    uint64_t call_stack[16];
} test_outcome_t;

// Mitigation configuration
typedef struct {
    uint32_t enabled_mitigations;
    bool smep_enabled;
    bool smap_enabled;
    bool pac_enabled;
    bool cfg_enabled;
    bool kaslr_enabled;
    bool kpti_enabled;
    uint64_t kaslr_base;
    uint64_t pac_key_a;
    uint64_t pac_key_b;
} mitigation_config_t;

#ifdef __cplusplus
}
#endif

#endif // MITIGATION_TYPES_H

