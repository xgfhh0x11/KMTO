#ifndef REPORTING_H
#define REPORTING_H

#include "mitigation_types.h"
#include "telemetry.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Report generator context
typedef struct report_context report_context_t;

// Initialize report generator
report_context_t* report_init(const char* output_dir);

// Cleanup report generator
void report_cleanup(report_context_t* ctx);

// Generate control flow diagram
void report_generate_control_flow_diagram(report_context_t* ctx,
                                           telemetry_context_t* telemetry,
                                           const char* filename);

// Generate memory access matrix
void report_generate_memory_access_matrix(report_context_t* ctx,
                                          telemetry_context_t* telemetry,
                                          const char* filename);

// Generate mitigation interaction summary
void report_generate_interaction_summary(report_context_t* ctx,
                                         mitigation_config_t* config,
                                         telemetry_stats_t* stats,
                                         const char* filename);

// Generate test outcome report
void report_generate_test_outcomes(report_context_t* ctx,
                                   test_outcome_t* outcomes,
                                   size_t outcome_count,
                                   const char* filename);

// Generate configuration comparison report
void report_generate_config_comparison(report_context_t* ctx,
                                       mitigation_config_t* config1,
                                       mitigation_config_t* config2,
                                       telemetry_stats_t* stats1,
                                       telemetry_stats_t* stats2,
                                       const char* filename);

// Generate JSON report
void report_generate_json(report_context_t* ctx,
                          mitigation_config_t* config,
                          telemetry_stats_t* stats,
                          test_outcome_t* outcomes,
                          size_t outcome_count,
                          const char* filename);

// Generate markdown summary
void report_generate_markdown_summary(report_context_t* ctx,
                                       mitigation_config_t* config,
                                       telemetry_stats_t* stats,
                                       const char* filename);

#ifdef __cplusplus
}
#endif

#endif // REPORTING_H

