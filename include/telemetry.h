#ifndef TELEMETRY_H
#define TELEMETRY_H

#include "mitigation_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Telemetry context
typedef struct telemetry_context telemetry_context_t;

// Initialize telemetry system
telemetry_context_t* telemetry_init(const char* log_file);

// Cleanup telemetry system
void telemetry_cleanup(telemetry_context_t* ctx);

// Log control flow event
void telemetry_log_control_flow(telemetry_context_t* ctx, 
                                 uint64_t from_addr, 
                                 uint64_t to_addr,
                                 bool pac_verified);

// Log memory access attempt
void telemetry_log_memory_access(telemetry_context_t* ctx,
                                 memory_domain_t source,
                                 memory_domain_t target,
                                 access_type_t access_type,
                                 uint64_t address,
                                 bool success);

// Log fault event
void telemetry_log_fault(telemetry_context_t* ctx,
                         fault_type_t fault_type,
                         uint64_t fault_address,
                         memory_domain_t source_domain,
                         access_type_t access_type);

// Log PAC authentication event
void telemetry_log_pac_auth(telemetry_context_t* ctx,
                            uint64_t pointer,
                            pac_key_domain_t key_domain,
                            bool success,
                            uint64_t original_pointer);

// Log timing information
void telemetry_log_timing(telemetry_context_t* ctx,
                          const char* event_name,
                          uint64_t duration_ns);

// Get statistics
typedef struct {
    uint64_t total_control_flow_events;
    uint64_t total_memory_accesses;
    uint64_t total_faults;
    uint64_t smep_violations;
    uint64_t smap_violations;
    uint64_t pac_failures;
    uint64_t pac_successes;
    uint64_t total_execution_time_ns;
} telemetry_stats_t;

void telemetry_get_stats(telemetry_context_t* ctx, telemetry_stats_t* stats);

// Flush telemetry data
void telemetry_flush(telemetry_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // TELEMETRY_H

