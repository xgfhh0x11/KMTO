#include "telemetry.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

struct telemetry_context {
    FILE* log_file;
    telemetry_stats_t stats;
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

telemetry_context_t* telemetry_init(const char* log_file) {
    telemetry_context_t* ctx = (telemetry_context_t*)calloc(1, sizeof(telemetry_context_t));
    if (!ctx) return NULL;
    
    if (log_file) {
        ctx->log_file = fopen(log_file, "w");
        if (!ctx->log_file) {
            free(ctx);
            return NULL;
        }
        fprintf(ctx->log_file, "=== Telemetry Log ===\n");
    }
    
    ctx->initialized = true;
    ctx->stats.total_execution_time_ns = get_timestamp_ns();
    
    return ctx;
}

void telemetry_cleanup(telemetry_context_t* ctx) {
    if (!ctx) return;
    
    if (ctx->log_file) {
        telemetry_flush(ctx);
        fclose(ctx->log_file);
    }
    
    free(ctx);
}

void telemetry_log_control_flow(telemetry_context_t* ctx, 
                                 uint64_t from_addr, 
                                 uint64_t to_addr,
                                 bool pac_verified) {
    if (!ctx || !ctx->initialized) return;
    
    ctx->stats.total_control_flow_events++;
    if (pac_verified) {
        ctx->stats.pac_successes++;
    } else {
        ctx->stats.pac_failures++;
    }
    
    if (ctx->log_file) {
        fprintf(ctx->log_file, "[CONTROL_FLOW] 0x%016llx -> 0x%016llx, PAC: %s\n",
                (unsigned long long)from_addr,
                (unsigned long long)to_addr,
                pac_verified ? "VERIFIED" : "FAILED");
    }
}

void telemetry_log_memory_access(telemetry_context_t* ctx,
                                 memory_domain_t source,
                                 memory_domain_t target,
                                 access_type_t access_type,
                                 uint64_t address,
                                 bool success) {
    if (!ctx || !ctx->initialized) return;
    
    ctx->stats.total_memory_accesses++;
    
    if (ctx->log_file) {
        const char* source_str = (source == DOMAIN_USER) ? "USER" : 
                                (source == DOMAIN_KERNEL) ? "KERNEL" : "HYPERVISOR";
        const char* target_str = (target == DOMAIN_USER) ? "USER" : 
                                (target == DOMAIN_KERNEL) ? "KERNEL" : "HYPERVISOR";
        const char* access_str = (access_type == ACCESS_READ) ? "READ" :
                                (access_type == ACCESS_WRITE) ? "WRITE" :
                                (access_type == ACCESS_EXECUTE) ? "EXECUTE" :
                                (access_type == ACCESS_COPY_FROM_USER) ? "COPY_FROM_USER" :
                                "COPY_TO_USER";
        
        fprintf(ctx->log_file, "[MEMORY_ACCESS] %s -> %s, %s, 0x%016llx, %s\n",
                source_str, target_str, access_str,
                (unsigned long long)address,
                success ? "SUCCESS" : "BLOCKED");
    }
}

void telemetry_log_fault(telemetry_context_t* ctx,
                         fault_type_t fault_type,
                         uint64_t fault_address,
                         memory_domain_t source_domain,
                         access_type_t access_type) {
    if (!ctx || !ctx->initialized) return;
    
    ctx->stats.total_faults++;
    
    switch (fault_type) {
        case FAULT_SMEP_VIOLATION:
            ctx->stats.smep_violations++;
            break;
        case FAULT_SMAP_VIOLATION:
            ctx->stats.smap_violations++;
            break;
        case FAULT_PAC_AUTH_FAILURE:
            ctx->stats.pac_failures++;
            break;
        default:
            break;
    }
    
    if (ctx->log_file) {
        const char* fault_str = (fault_type == FAULT_SMEP_VIOLATION) ? "SMEP_VIOLATION" :
                               (fault_type == FAULT_SMAP_VIOLATION) ? "SMAP_VIOLATION" :
                               (fault_type == FAULT_PAC_AUTH_FAILURE) ? "PAC_AUTH_FAILURE" :
                               (fault_type == FAULT_GPF) ? "GPF" :
                               (fault_type == FAULT_PAGE_FAULT) ? "PAGE_FAULT" :
                               "UNKNOWN";
        
        fprintf(ctx->log_file, "[FAULT] %s, 0x%016llx, Domain: %d, Access: %d\n",
                fault_str,
                (unsigned long long)fault_address,
                source_domain,
                access_type);
    }
}

void telemetry_log_pac_auth(telemetry_context_t* ctx,
                            uint64_t pointer,
                            pac_key_domain_t key_domain,
                            bool success,
                            uint64_t original_pointer) {
    if (!ctx || !ctx->initialized) return;
    
    if (success) {
        ctx->stats.pac_successes++;
    } else {
        ctx->stats.pac_failures++;
    }
    
    if (ctx->log_file) {
        fprintf(ctx->log_file, "[PAC_AUTH] Pointer: 0x%016llx, Original: 0x%016llx, Key: %s, %s\n",
                (unsigned long long)pointer,
                (unsigned long long)original_pointer,
                (key_domain == PAC_KEY_A) ? "A-KEY" : "B-KEY",
                success ? "SUCCESS" : "FAILURE");
    }
}

void telemetry_log_timing(telemetry_context_t* ctx,
                          const char* event_name,
                          uint64_t duration_ns) {
    if (!ctx || !ctx->initialized) return;
    
    if (ctx->log_file) {
        fprintf(ctx->log_file, "[TIMING] %s: %llu ns\n",
                event_name ? event_name : "UNKNOWN",
                (unsigned long long)duration_ns);
    }
}

void telemetry_get_stats(telemetry_context_t* ctx, telemetry_stats_t* stats) {
    if (!ctx || !stats) return;
    
    if (ctx->initialized) {
        uint64_t end_time = get_timestamp_ns();
        ctx->stats.total_execution_time_ns = end_time - ctx->stats.total_execution_time_ns;
    }
    
    memcpy(stats, &ctx->stats, sizeof(telemetry_stats_t));
}

void telemetry_flush(telemetry_context_t* ctx) {
    if (!ctx || !ctx->log_file) return;
    fflush(ctx->log_file);
}

