/* strdup() is POSIX; glibc hides it under a strict -std=c11 compile unless a
 * feature-test macro is set before any system header. Without the declaration
 * the compiler assumes an int return and truncates the pointer on LP64. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "reporting.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <direct.h>
#define KMTO_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define KMTO_MKDIR(p) mkdir((p), 0755)
#endif

struct report_context {
    char* output_dir;
    bool initialized;
};

// Create `path` and any missing parent directories (mkdir -p semantics).
// Returns 0 on success (or if it already exists), -1 otherwise. Treats both
// '/' and '\\' as separators so a Windows-style path also works.
static int ensure_directory(const char* path) {
    if (!path || !*path) return -1;

    char buf[512];
    size_t len = strlen(path);
    if (len >= sizeof(buf)) return -1;
    memcpy(buf, path, len + 1);

    for (char* p = buf + 1; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            if (KMTO_MKDIR(buf) != 0 && errno != EEXIST) return -1;
            *p = sep;
        }
    }
    if (KMTO_MKDIR(buf) != 0 && errno != EEXIST) return -1;
    return 0;
}

report_context_t* report_init(const char* output_dir) {
    report_context_t* ctx = (report_context_t*)calloc(1, sizeof(report_context_t));
    if (!ctx) return NULL;

    if (output_dir) {
        ctx->output_dir = strdup(output_dir);
    } else {
        ctx->output_dir = strdup(".");
    }

    if (!ctx->output_dir) {
        free(ctx);
        return NULL;
    }

    // Reports are written with fopen(..., "w"), which cannot create missing
    // parent directories; create the output directory up front so a caller
    // passing a not-yet-existing -o DIR actually gets files written.
    if (ensure_directory(ctx->output_dir) != 0) {
        fprintf(stderr, "[!] could not create output directory '%s': %s\n",
                ctx->output_dir, strerror(errno));
        free(ctx->output_dir);
        free(ctx);
        return NULL;
    }

    ctx->initialized = true;
    return ctx;
}

void report_cleanup(report_context_t* ctx) {
    if (ctx) {
        if (ctx->output_dir) {
            free(ctx->output_dir);
        }
        free(ctx);
    }
}

// NOTE: this is a static reference diagram, not derived from `telemetry` or
// from the current run. It illustrates the mitigation model KMTO's scripted
// scenarios are based on, not observed control flow. The `telemetry`
// parameter is accepted for API symmetry with the other report_generate_*
// functions and to leave room for a future per-run variant, but is not read.
void report_generate_control_flow_diagram(report_context_t* ctx,
                                           telemetry_context_t* telemetry,
                                           const char* filename) {
    if (!ctx || !filename) return;
    (void)telemetry;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);

    FILE* f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "// STATIC TEMPLATE: fixed reference diagram, not derived from this run's telemetry.\n");
    fprintf(f, "digraph ControlFlow {\n");
    fprintf(f, "  rankdir=LR;\n");
    fprintf(f, "  node [shape=box];\n");
    fprintf(f, "  \"User Space\" -> \"Kernel Space\" [label=\"SMEP/SMAP Guard\"];\n");
    fprintf(f, "  \"Kernel Space\" -> \"PAC Verify\" [label=\"Function Pointer\"];\n");
    fprintf(f, "  \"PAC Verify\" -> \"Execute\" [label=\"Success\"];\n");
    fprintf(f, "  \"PAC Verify\" -> \"Fault\" [label=\"Failure\"];\n");
    fprintf(f, "}\n");

    fclose(f);
}

// NOTE: this is a static reference table, not derived from `telemetry` or
// from the current run. It documents the mitigation model KMTO's scripted
// scenarios are based on, not observed accesses. The `telemetry` parameter
// is accepted for API symmetry with the other report_generate_* functions
// and to leave room for a future per-run variant, but is not read.
void report_generate_memory_access_matrix(report_context_t* ctx,
                                          telemetry_context_t* telemetry,
                                          const char* filename) {
    if (!ctx || !filename) return;
    (void)telemetry;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);

    FILE* f = fopen(path, "w");
    if (!f) return;

    fprintf(f, "=== Memory Access Matrix (STATIC TEMPLATE) ===\n");
    fprintf(f, "=== Fixed reference table, not derived from this run's telemetry ===\n\n");
    fprintf(f, "Source Domain -> Target Domain | Access Type | Result\n");
    fprintf(f, "--------------------------------|-------------|--------\n");
    fprintf(f, "USER -> KERNEL                  | COPY_FROM   | ALLOWED (via copy_from_user)\n");
    fprintf(f, "KERNEL -> USER                  | DIRECT      | BLOCKED (SMAP)\n");
    fprintf(f, "KERNEL -> USER                  | EXECUTE     | BLOCKED (SMEP)\n");
    fprintf(f, "KERNEL -> KERNEL                | EXECUTE     | ALLOWED (if PAC verified)\n");

    fclose(f);
}

void report_generate_interaction_summary(report_context_t* ctx,
                                         mitigation_config_t* config,
                                         telemetry_stats_t* stats,
                                         const char* filename) {
    if (!ctx || !filename) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);
    
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    time_t now = time(NULL);
    fprintf(f, "=== Mitigation Interaction Summary ===\n");
    fprintf(f, "Generated: %s\n\n", ctime(&now));
    
    if (config) {
        fprintf(f, "Configuration:\n");
        fprintf(f, "  SMEP: %s\n", config->smep_enabled ? "ENABLED" : "DISABLED");
        fprintf(f, "  SMAP: %s\n", config->smap_enabled ? "ENABLED" : "DISABLED");
        fprintf(f, "  PAC:  %s\n", config->pac_enabled ? "ENABLED" : "DISABLED");
        fprintf(f, "\n");
    }
    
    if (stats) {
        fprintf(f, "Statistics:\n");
        fprintf(f, "  Total Control Flow Events: %llu\n", (unsigned long long)stats->total_control_flow_events);
        fprintf(f, "  Total Memory Accesses: %llu\n", (unsigned long long)stats->total_memory_accesses);
        fprintf(f, "  Total Faults: %llu\n", (unsigned long long)stats->total_faults);
        fprintf(f, "  SMEP Violations: %llu\n", (unsigned long long)stats->smep_violations);
        fprintf(f, "  SMAP Violations: %llu\n", (unsigned long long)stats->smap_violations);
        fprintf(f, "  PAC Failures: %llu\n", (unsigned long long)stats->pac_failures);
        fprintf(f, "  PAC Successes: %llu\n", (unsigned long long)stats->pac_successes);
        fprintf(f, "  Execution Time: %llu ns\n", (unsigned long long)stats->total_execution_time_ns);
    }
    
    fprintf(f, "\n=== Interaction Findings ===\n");
    fprintf(f, "1. SMEP and SMAP work together to prevent kernel execution of user code/data\n");
    fprintf(f, "2. PAC provides additional protection for control flow integrity\n");
    fprintf(f, "3. Transient windows (copy_from_user) allow controlled access\n");
    
    fclose(f);
}

void report_generate_test_outcomes(report_context_t* ctx,
                                   test_outcome_t* outcomes,
                                   size_t outcome_count,
                                   const char* filename) {
    if (!ctx || !filename) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);
    
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "=== Test Outcomes ===\n\n");
    
    for (size_t i = 0; i < outcome_count; i++) {
        test_outcome_t* outcome = &outcomes[i];
        fprintf(f, "Test %zu:\n", i + 1);
        fprintf(f, "  Fault Type: %d\n", outcome->fault_type);
        fprintf(f, "  Fault Address: 0x%016llx\n", (unsigned long long)outcome->fault_address);
        fprintf(f, "  Source Domain: %d\n", outcome->source_domain);
        fprintf(f, "  Target Domain: %d\n", outcome->target_domain);
        fprintf(f, "  Access Type: %d\n", outcome->access_type);
        fprintf(f, "  PAC Verified: %s\n", outcome->pac_verified ? "YES" : "NO");
        fprintf(f, "  Timestamp: %llu ns\n", (unsigned long long)outcome->timestamp);
        fprintf(f, "  Config: SMEP=%s SMAP=%s PAC=%s\n",
                outcome->config.smep_enabled ? "ON" : "OFF",
                outcome->config.smap_enabled ? "ON" : "OFF",
                outcome->config.pac_enabled ? "ON" : "OFF");
        fprintf(f, "\n");
    }
    
    fclose(f);
}

void report_generate_config_comparison(report_context_t* ctx,
                                       mitigation_config_t* config1,
                                       mitigation_config_t* config2,
                                       telemetry_stats_t* stats1,
                                       telemetry_stats_t* stats2,
                                       const char* filename) {
    if (!ctx || !filename) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);
    
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "=== Configuration Comparison ===\n\n");
    
    fprintf(f, "Configuration 1:\n");
    if (config1) {
        fprintf(f, "  SMEP: %s, SMAP: %s, PAC: %s\n",
                config1->smep_enabled ? "ON" : "OFF",
                config1->smap_enabled ? "ON" : "OFF",
                config1->pac_enabled ? "ON" : "OFF");
    }
    if (stats1) {
        fprintf(f, "  Faults: %llu, PAC Failures: %llu\n",
                (unsigned long long)stats1->total_faults,
                (unsigned long long)stats1->pac_failures);
    }
    
    fprintf(f, "\nConfiguration 2:\n");
    if (config2) {
        fprintf(f, "  SMEP: %s, SMAP: %s, PAC: %s\n",
                config2->smep_enabled ? "ON" : "OFF",
                config2->smap_enabled ? "ON" : "OFF",
                config2->pac_enabled ? "ON" : "OFF");
    }
    if (stats2) {
        fprintf(f, "  Faults: %llu, PAC Failures: %llu\n",
                (unsigned long long)stats2->total_faults,
                (unsigned long long)stats2->pac_failures);
    }
    
    fclose(f);
}

void report_generate_json(report_context_t* ctx,
                          mitigation_config_t* config,
                          telemetry_stats_t* stats,
                          test_outcome_t* outcomes,
                          size_t outcome_count,
                          const char* filename) {
    if (!ctx || !filename) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);
    
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"config\": {\n");
    if (config) {
        fprintf(f, "    \"smep\": %s,\n", config->smep_enabled ? "true" : "false");
        fprintf(f, "    \"smap\": %s,\n", config->smap_enabled ? "true" : "false");
        fprintf(f, "    \"pac\": %s\n", config->pac_enabled ? "true" : "false");
    }
    fprintf(f, "  },\n");
    
    fprintf(f, "  \"stats\": {\n");
    if (stats) {
        fprintf(f, "    \"total_faults\": %llu,\n", (unsigned long long)stats->total_faults);
        fprintf(f, "    \"smep_violations\": %llu,\n", (unsigned long long)stats->smep_violations);
        fprintf(f, "    \"smap_violations\": %llu,\n", (unsigned long long)stats->smap_violations);
        fprintf(f, "    \"pac_failures\": %llu\n", (unsigned long long)stats->pac_failures);
    }
    fprintf(f, "  },\n");
    
    fprintf(f, "  \"outcomes\": [\n");
    for (size_t i = 0; i < outcome_count; i++) {
        test_outcome_t* outcome = &outcomes[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"fault_type\": %d,\n", outcome->fault_type);
        fprintf(f, "      \"fault_address\": \"0x%016llx\",\n", (unsigned long long)outcome->fault_address);
        fprintf(f, "      \"pac_verified\": %s,\n", outcome->pac_verified ? "true" : "false");
        fprintf(f, "      \"config\": { \"smep\": %s, \"smap\": %s, \"pac\": %s }\n",
                outcome->config.smep_enabled ? "true" : "false",
                outcome->config.smap_enabled ? "true" : "false",
                outcome->config.pac_enabled ? "true" : "false");
        fprintf(f, "    }%s\n", (i < outcome_count - 1) ? "," : "");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
}

void report_generate_markdown_summary(report_context_t* ctx,
                                       mitigation_config_t* config,
                                       telemetry_stats_t* stats,
                                       const char* filename) {
    if (!ctx || !filename) return;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", ctx->output_dir, filename);
    
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "# Mitigation Research Summary\n\n");
    
    if (config) {
        fprintf(f, "## Configuration\n\n");
        fprintf(f, "- SMEP: %s\n", config->smep_enabled ? "✅ Enabled" : "❌ Disabled");
        fprintf(f, "- SMAP: %s\n", config->smap_enabled ? "✅ Enabled" : "❌ Disabled");
        fprintf(f, "- PAC:  %s\n", config->pac_enabled ? "✅ Enabled" : "❌ Disabled");
        fprintf(f, "\n");
    }
    
    if (stats) {
        fprintf(f, "## Statistics\n\n");
        fprintf(f, "| Metric | Value |\n");
        fprintf(f, "|--------|-------|\n");
        fprintf(f, "| Total Faults | %llu |\n", (unsigned long long)stats->total_faults);
        fprintf(f, "| SMEP Violations | %llu |\n", (unsigned long long)stats->smep_violations);
        fprintf(f, "| SMAP Violations | %llu |\n", (unsigned long long)stats->smap_violations);
        fprintf(f, "| PAC Failures | %llu |\n", (unsigned long long)stats->pac_failures);
        fprintf(f, "\n");
    }
    
    fprintf(f, "## Findings\n\n");
    fprintf(f, "This research framework provides systematic observation of mitigation behaviors.\n");
    
    fclose(f);
}

