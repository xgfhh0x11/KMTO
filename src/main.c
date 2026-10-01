#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mitigation_detector.h"
#include "telemetry.h"
#include "test_harness.h"
#include "config_manager.h"
#include "reporting.h"

#define MAX_OUTCOMES 100

static void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -c, --config FILE      Configuration file path\n");
    printf("  -o, --output DIR       Output directory for reports\n");
    printf("  -l, --log FILE         Telemetry log file\n");
    printf("  -t, --test TYPE        Run specific test type\n");
    printf("  -m, --matrix           Run all configuration combinations\n");
    printf("  -h, --help             Show this help\n");
    printf("\nTest Types:\n");
    printf("  baseline-boundary      User->Kernel boundary observation\n");
    printf("  baseline-smep          SMEP enforcement observation\n");
    printf("  baseline-smap          SMAP enforcement observation\n");
    printf("  baseline-pac           PAC verification flow\n");
    printf("  pointer-semantics      Pointer semantics with PAC\n");
    printf("  data-code-sep          Data vs code separation\n");
    printf("  transient-windows      Transient access windows\n");
    printf("  interaction            Mitigation interaction analysis\n");
    printf("  all                    Run all tests\n");
}

// Returns a test_type_t value, or -1 if the string names no known test.
static int parse_test_type(const char* test_str) {
    if (strcmp(test_str, "baseline-boundary") == 0) {
        return TEST_BASELINE_USER_KERNEL_BOUNDARY;
    } else if (strcmp(test_str, "baseline-smep") == 0) {
        return TEST_BASELINE_SMEP_VIOLATION;
    } else if (strcmp(test_str, "baseline-smap") == 0) {
        return TEST_BASELINE_SMAP_VIOLATION;
    } else if (strcmp(test_str, "baseline-pac") == 0) {
        return TEST_BASELINE_PAC_VERIFICATION;
    } else if (strcmp(test_str, "pointer-semantics") == 0) {
        return TEST_POINTER_SEMANTICS;
    } else if (strcmp(test_str, "data-code-sep") == 0) {
        return TEST_DATA_CODE_SEPARATION;
    } else if (strcmp(test_str, "transient-windows") == 0) {
        return TEST_TRANSIENT_WINDOWS;
    } else if (strcmp(test_str, "interaction") == 0) {
        return TEST_MITIGATION_INTERACTION;
    }
    return -1;
}

int main(int argc, char* argv[]) {
    const char* config_file = NULL;
    const char* output_dir = "output";
    const char* log_file = "telemetry.log";
    const char* test_type_str = "all";
    bool run_matrix = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                config_file = argv[++i];
            }
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output_dir = argv[++i];
            }
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) {
            if (i + 1 < argc) {
                log_file = argv[++i];
            }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
            if (i + 1 < argc) {
                test_type_str = argv[++i];
            }
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--matrix") == 0) {
            run_matrix = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    printf("=== KMTO — Kernel Mitigation Telemetry Observatory ===\n\n");

    printf("[*] Initializing components...\n");

    mitigation_config_t config = detect_mitigations();
    printf("[*] Detected mitigations:\n");
    config_manager_print(&config);

    config_manager_context_t* config_mgr = config_manager_init(config_file);
    if (config_file) {
        mitigation_config_t loaded_config;
        if (config_manager_load(config_mgr, &loaded_config)) {
            printf("[*] Loaded configuration from file\n");
            config = loaded_config;
        }
    }

    telemetry_context_t* telemetry = telemetry_init(log_file);
    if (!telemetry) {
        fprintf(stderr, "[-] Failed to initialize telemetry\n");
        return 1;
    }
    printf("[*] Telemetry initialized\n");

    test_harness_context_t* harness = test_harness_init(telemetry, &config);
    if (!harness) {
        fprintf(stderr, "[-] Failed to initialize test harness\n");
        telemetry_cleanup(telemetry);
        return 1;
    }
    printf("[*] Test harness initialized\n");

    report_context_t* reporter = report_init(output_dir);
    if (!reporter) {
        fprintf(stderr, "[-] Failed to initialize reporter\n");
        test_harness_cleanup(harness);
        telemetry_cleanup(telemetry);
        return 1;
    }
    printf("[*] Reporter initialized\n");

    printf("\n[*] Running observation tests...\n");

    test_outcome_t outcomes[MAX_OUTCOMES];
    size_t outcome_count = 0;

    if (run_matrix) {
        printf("[*] Running configuration matrix...\n");
        config_matrix_t* matrix = config_manager_create_matrix(config_mgr);
        if (matrix) {
            for (size_t i = 0; i < matrix->count && outcome_count < MAX_OUTCOMES; i++) {
                printf("[*] Testing configuration %zu/%zu\n", i + 1, matrix->count);
                config_manager_print(&matrix->configs[i]);
                test_harness_set_config(harness, &matrix->configs[i]);

                test_type_t test_types[] = {
                    TEST_BASELINE_USER_KERNEL_BOUNDARY,
                    TEST_BASELINE_SMEP_VIOLATION,
                    TEST_BASELINE_SMAP_VIOLATION,
                    TEST_BASELINE_PAC_VERIFICATION,
                    TEST_MITIGATION_INTERACTION
                };

                for (size_t j = 0; j < sizeof(test_types)/sizeof(test_types[0]); j++) {
                    if (outcome_count < MAX_OUTCOMES) {
                        outcomes[outcome_count++] = test_harness_run(harness, test_types[j]);
                    }
                }
            }
            config_manager_free_matrix(matrix);
        }
    } else {
        if (strcmp(test_type_str, "all") == 0) {
            test_type_t test_types[] = {
                TEST_BASELINE_USER_KERNEL_BOUNDARY,
                TEST_BASELINE_SMEP_VIOLATION,
                TEST_BASELINE_SMAP_VIOLATION,
                TEST_BASELINE_PAC_VERIFICATION,
                TEST_POINTER_SEMANTICS,
                TEST_DATA_CODE_SEPARATION,
                TEST_TRANSIENT_WINDOWS,
                TEST_MITIGATION_INTERACTION
            };

            for (size_t i = 0; i < sizeof(test_types)/sizeof(test_types[0]); i++) {
                printf("[*] Running test %zu...\n", i + 1);
                if (outcome_count < MAX_OUTCOMES) {
                    outcomes[outcome_count++] = test_harness_run(harness, test_types[i]);
                }
            }
        } else {
            int test_type = parse_test_type(test_type_str);
            if (test_type != -1) {
                printf("[*] Running test: %s\n", test_type_str);
                if (outcome_count < MAX_OUTCOMES) {
                    outcomes[outcome_count++] = test_harness_run(harness, (test_type_t)test_type);
                }
            } else {
                fprintf(stderr, "[-] Unknown test type: %s\n", test_type_str);
            }
        }
    }

    telemetry_stats_t stats;
    telemetry_get_stats(telemetry, &stats);

    printf("\n[*] Generating reports...\n");
    report_generate_interaction_summary(reporter, &config, &stats, "interaction_summary.txt");
    report_generate_markdown_summary(reporter, &config, &stats, "summary.md");
    report_generate_json(reporter, &config, &stats, outcomes, outcome_count, "results.json");
    report_generate_test_outcomes(reporter, outcomes, outcome_count, "test_outcomes.txt");
    report_generate_control_flow_diagram(reporter, telemetry, "control_flow.dot");
    report_generate_memory_access_matrix(reporter, telemetry, "memory_access_matrix.txt");

    printf("[*] Reports generated in: %s\n", output_dir);

    printf("\n=== Summary ===\n");
    printf("Total Control Flow Events: %llu\n", (unsigned long long)stats.total_control_flow_events);
    printf("Total Memory Accesses: %llu\n", (unsigned long long)stats.total_memory_accesses);
    printf("Total Faults: %llu\n", (unsigned long long)stats.total_faults);
    printf("SMEP Violations: %llu\n", (unsigned long long)stats.smep_violations);
    printf("SMAP Violations: %llu\n", (unsigned long long)stats.smap_violations);
    printf("PAC Failures: %llu\n", (unsigned long long)stats.pac_failures);
    printf("PAC Successes: %llu\n", (unsigned long long)stats.pac_successes);

    report_cleanup(reporter);
    test_harness_cleanup(harness);
    telemetry_cleanup(telemetry);
    config_manager_cleanup(config_mgr);

    printf("\n[+] Observation session complete\n");
    return 0;
}
