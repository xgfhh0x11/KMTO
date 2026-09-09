#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include "mitigation_types.h"
#include "telemetry.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Test harness context
typedef struct test_harness_context test_harness_context_t;

// Initialize test harness
test_harness_context_t* test_harness_init(telemetry_context_t* telemetry,
                                          mitigation_config_t* config);

// Cleanup test harness
void test_harness_cleanup(test_harness_context_t* ctx);

// Update active mitigation configuration
void test_harness_set_config(test_harness_context_t* ctx, mitigation_config_t* config);

// Baseline validation tests
typedef enum {
    TEST_BASELINE_USER_KERNEL_BOUNDARY,
    TEST_BASELINE_SMEP_VIOLATION,
    TEST_BASELINE_SMAP_VIOLATION,
    TEST_BASELINE_PAC_VERIFICATION,
    TEST_POINTER_SEMANTICS,
    TEST_DATA_CODE_SEPARATION,
    TEST_TRANSIENT_WINDOWS,
    TEST_MITIGATION_INTERACTION
} test_type_t;

// Run a test scenario
test_outcome_t test_harness_run(test_harness_context_t* ctx, test_type_t test_type);

// Test: User->Kernel boundary observation
test_outcome_t test_user_kernel_boundary(test_harness_context_t* ctx);

// Test: SMEP violation observation (simulated, no actual violation)
test_outcome_t test_smep_violation_observation(test_harness_context_t* ctx);

// Test: SMAP violation observation (simulated, no actual violation)
test_outcome_t test_smap_violation_observation(test_harness_context_t* ctx);

// Test: PAC verification flow (simulated)
test_outcome_t test_pac_verification_flow(test_harness_context_t* ctx);

// Test: Pointer semantics with PAC
test_outcome_t test_pointer_semantics(test_harness_context_t* ctx);

// Test: Data vs code separation
test_outcome_t test_data_code_separation(test_harness_context_t* ctx);

// Test: Transient access windows
test_outcome_t test_transient_windows(test_harness_context_t* ctx);

// Test: Mitigation interaction analysis
test_outcome_t test_mitigation_interaction(test_harness_context_t* ctx);

// Compare test outcomes with different mitigation configurations
void test_harness_compare_configs(test_harness_context_t* ctx,
                                  mitigation_config_t* config1,
                                  mitigation_config_t* config2,
                                  test_type_t test_type);

#ifdef __cplusplus
}
#endif

#endif // TEST_HARNESS_H

