#include "test_harness.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

struct test_harness_context {
    telemetry_context_t* telemetry;
    mitigation_config_t* config;
    bool initialized;
};

static uint64_t get_timestamp_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (counter.QuadPart * 1000000000ULL) / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

test_harness_context_t* test_harness_init(telemetry_context_t* telemetry,
                                          mitigation_config_t* config) {
    test_harness_context_t* ctx = (test_harness_context_t*)calloc(1, sizeof(test_harness_context_t));
    if (!ctx) return NULL;
    
    ctx->telemetry = telemetry;
    ctx->config = config;
    ctx->initialized = true;
    
    return ctx;
}

void test_harness_set_config(test_harness_context_t* ctx, mitigation_config_t* config) {
    if (!ctx) return;
    ctx->config = config;
}

void test_harness_cleanup(test_harness_context_t* ctx) {
    if (ctx) {
        free(ctx);
    }
}

test_outcome_t test_harness_run(test_harness_context_t* ctx, test_type_t test_type) {
    test_outcome_t outcome = {0};
    
    if (!ctx || !ctx->initialized) {
        outcome.fault_type = FAULT_UNKNOWN;
        return outcome;
    }
    
    outcome.timestamp = get_timestamp_ns();
    
    switch (test_type) {
        case TEST_BASELINE_USER_KERNEL_BOUNDARY:
            outcome = test_user_kernel_boundary(ctx);
            break;
        case TEST_BASELINE_SMEP_VIOLATION:
            outcome = test_smep_violation_observation(ctx);
            break;
        case TEST_BASELINE_SMAP_VIOLATION:
            outcome = test_smap_violation_observation(ctx);
            break;
        case TEST_BASELINE_PAC_VERIFICATION:
            outcome = test_pac_verification_flow(ctx);
            break;
        case TEST_POINTER_SEMANTICS:
            outcome = test_pointer_semantics(ctx);
            break;
        case TEST_DATA_CODE_SEPARATION:
            outcome = test_data_code_separation(ctx);
            break;
        case TEST_TRANSIENT_WINDOWS:
            outcome = test_transient_windows(ctx);
            break;
        case TEST_MITIGATION_INTERACTION:
            outcome = test_mitigation_interaction(ctx);
            break;
        default:
            outcome.fault_type = FAULT_UNKNOWN;
            break;
    }

    // Attribute this outcome to the mitigation configuration that was
    // active when it was produced (matters for matrix mode, where each
    // row swaps the config via test_harness_set_config()).
    if (ctx->config) {
        outcome.config = *ctx->config;
    }

    return outcome;
}

test_outcome_t test_user_kernel_boundary(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    outcome.source_domain = DOMAIN_USER;
    outcome.target_domain = DOMAIN_KERNEL;
    outcome.access_type = ACCESS_COPY_FROM_USER;
    
    // Simulate user->kernel boundary observation
    // This is a conceptual test - we observe the boundary without crossing it
    
    uint64_t user_addr = 0x00007fff00000000ULL; // Typical user space address
    uint64_t kernel_addr = 0xffff800000000000ULL; // Typical kernel space address
    
    // Log memory access attempt (simulated)
    telemetry_log_memory_access(ctx->telemetry,
                               DOMAIN_USER,
                               DOMAIN_KERNEL,
                               ACCESS_COPY_FROM_USER,
                               user_addr,
                               true);
    
    // Check if SMAP would block this (conceptual)
    if (ctx->config && ctx->config->smap_enabled) {
        // SMAP would block direct kernel access to user memory
        // But copy_from_user functions have special handling
        telemetry_log_memory_access(ctx->telemetry,
                                   DOMAIN_KERNEL,
                                   DOMAIN_USER,
                                   ACCESS_READ,
                                   user_addr,
                                   true); // copy_from_user handles SMAP
    }
    
    outcome.fault_type = FAULT_NONE;
    return outcome;
}

test_outcome_t test_smep_violation_observation(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    outcome.source_domain = DOMAIN_KERNEL;
    outcome.target_domain = DOMAIN_USER;
    outcome.access_type = ACCESS_EXECUTE;
    
    // Simulate SMEP violation observation
    // We don't actually trigger it, just model the behavior
    
    if (ctx->config && ctx->config->smep_enabled) {
        uint64_t user_code_addr = 0x00007fff00001000ULL;
        
        // Log what would happen if kernel tried to execute user code
        telemetry_log_fault(ctx->telemetry,
                           FAULT_SMEP_VIOLATION,
                           user_code_addr,
                           DOMAIN_KERNEL,
                           ACCESS_EXECUTE);
        
        outcome.fault_type = FAULT_SMEP_VIOLATION;
        outcome.fault_address = user_code_addr;
    } else {
        outcome.fault_type = FAULT_NONE;
    }
    
    return outcome;
}

test_outcome_t test_smap_violation_observation(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    outcome.source_domain = DOMAIN_KERNEL;
    outcome.target_domain = DOMAIN_USER;
    outcome.access_type = ACCESS_READ;
    
    // Simulate SMAP violation observation
    if (ctx->config && ctx->config->smap_enabled) {
        uint64_t user_data_addr = 0x00007fff00002000ULL;
        
        // Log what would happen if kernel tried to directly access user data
        // (without using copy_from_user). On real hardware SMAP would raise
        // a #PF/#GP, and helpers like copy_from_user temporarily bracket the
        // access with STAC/CLAC to keep it safe.
        telemetry_log_fault(ctx->telemetry,
                           FAULT_SMAP_VIOLATION,
                           user_data_addr,
                           DOMAIN_KERNEL,
                           ACCESS_READ);
        
        outcome.fault_type = FAULT_SMAP_VIOLATION;
        outcome.fault_address = user_data_addr;
    } else {
        outcome.fault_type = FAULT_NONE;
    }
    
    return outcome;
}

test_outcome_t test_pac_verification_flow(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    
    // Simulate PAC verification flow
    if (ctx->config && ctx->config->pac_enabled) {
        uint64_t function_ptr = 0xffff800012345678ULL;
        uint64_t original_ptr = 0xffff800012345000ULL;
        
        // Simulate PAC signing
        // In real ARM64, pointer would be signed with PAC
        bool pac_verified = true; // Simulated success
        
        telemetry_log_pac_auth(ctx->telemetry,
                              function_ptr,
                              PAC_KEY_A,
                              pac_verified,
                              original_ptr);
        
        telemetry_log_control_flow(ctx->telemetry,
                                  0xffff800011111111ULL,
                                  function_ptr,
                                  pac_verified);
        
        outcome.pac_verified = pac_verified;
        outcome.fault_type = pac_verified ? FAULT_NONE : FAULT_PAC_AUTH_FAILURE;
    } else {
        outcome.fault_type = FAULT_NONE;
    }
    
    return outcome;
}

test_outcome_t test_pointer_semantics(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    
    // Test pointer semantics with PAC
    if (ctx->config && ctx->config->pac_enabled) {
        // Simulate function pointer with PAC
        uint64_t func_ptr = 0xffff8000abcd1234ULL;
        uint64_t return_addr = 0xffff8000abcd5678ULL;
        
        // Test function pointer authentication
        telemetry_log_pac_auth(ctx->telemetry, func_ptr, PAC_KEY_A, true, func_ptr);
        telemetry_log_control_flow(ctx->telemetry, 0, func_ptr, true);
        
        // Test return address authentication
        telemetry_log_pac_auth(ctx->telemetry, return_addr, PAC_KEY_A, true, return_addr);
        telemetry_log_control_flow(ctx->telemetry, func_ptr, return_addr, true);
        
        outcome.pac_verified = true;
        outcome.fault_type = FAULT_NONE;
    } else {
        outcome.fault_type = FAULT_NONE;
    }
    
    return outcome;
}

test_outcome_t test_data_code_separation(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    
    // Test data vs code separation
    uint64_t data_addr = 0xffff8000deadbeefULL;
    uint64_t code_addr = 0xffff8000cafebabeULL;
    
    // Attempt to use data as code (should be blocked by mitigations)
    if (ctx->config && ctx->config->smep_enabled) {
        // SMEP would prevent executing data
        telemetry_log_memory_access(ctx->telemetry,
                                   DOMAIN_KERNEL,
                                   DOMAIN_KERNEL,
                                   ACCESS_EXECUTE,
                                   data_addr,
                                   false);
    }
    
    // Normal code execution
    telemetry_log_memory_access(ctx->telemetry,
                               DOMAIN_KERNEL,
                               DOMAIN_KERNEL,
                               ACCESS_EXECUTE,
                               code_addr,
                               true);
    
    outcome.fault_type = FAULT_NONE;
    return outcome;
}

test_outcome_t test_transient_windows(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    
    // Test transient access windows (exception handlers, copy gateways)
    // These are brief periods where mitigations might be temporarily relaxed
    
    uint64_t user_addr = 0x00007fff00003000ULL;
    
    // Simulate copy_from_user gateway (SMAP exception window)
    if (ctx->config && ctx->config->smap_enabled) {
        // During copy_from_user, SMAP is temporarily disabled via STAC
        telemetry_log_memory_access(ctx->telemetry,
                                   DOMAIN_KERNEL,
                                   DOMAIN_USER,
                                   ACCESS_READ,
                                   user_addr,
                                   true); // Allowed during transient window
    }
    
    outcome.fault_type = FAULT_NONE;
    return outcome;
}

test_outcome_t test_mitigation_interaction(test_harness_context_t* ctx) {
    test_outcome_t outcome = {0};
    outcome.timestamp = get_timestamp_ns();
    
    // Test how multiple mitigations interact
    bool smep = ctx->config && ctx->config->smep_enabled;
    bool smap = ctx->config && ctx->config->smap_enabled;
    bool pac = ctx->config && ctx->config->pac_enabled;
    
    // Scenario: Control flow hijack attempt with multiple mitigations
    uint64_t hijacked_ptr = 0x00007fff00004000ULL; // User space pointer
    
    if (smep) {
        // SMEP would block execution
        telemetry_log_fault(ctx->telemetry,
                           FAULT_SMEP_VIOLATION,
                           hijacked_ptr,
                           DOMAIN_KERNEL,
                           ACCESS_EXECUTE);
    }
    
    if (pac) {
        // PAC would fail authentication
        telemetry_log_pac_auth(ctx->telemetry,
                              hijacked_ptr,
                              PAC_KEY_A,
                              false,
                              hijacked_ptr);
    }
    
    outcome.fault_type = (smep || pac) ? FAULT_SMEP_VIOLATION : FAULT_NONE;
    outcome.fault_address = hijacked_ptr;
    
    return outcome;
}

// NOTE: not currently called anywhere in this codebase (also not exercised
// by report_generate_config_comparison(), which likewise has no caller).
// It discards outcome1/outcome2 rather than reporting them — wiring it up
// would need a report_generate_config_comparison() call added here, which
// is left as a documented gap rather than done speculatively.
void test_harness_compare_configs(test_harness_context_t* ctx,
                                  mitigation_config_t* config1,
                                  mitigation_config_t* config2,
                                  test_type_t test_type) {
    if (!ctx) return;
    
    // Save original config
    mitigation_config_t* original = ctx->config;
    
    // Run test with config1
    ctx->config = config1;
    test_outcome_t outcome1 = test_harness_run(ctx, test_type);
    
    // Run test with config2
    ctx->config = config2;
    test_outcome_t outcome2 = test_harness_run(ctx, test_type);
    
    // Restore original config
    ctx->config = original;
    
    // Log comparison (would be handled by reporting module)
    (void)outcome1;
    (void)outcome2;
}

