#include "mitigation_detector.h"
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#elif __linux__
#include <cpuid.h>
#include <sys/auxv.h>
#endif

mitigation_config_t detect_mitigations(void) {
    mitigation_config_t config = {0};
    
#ifdef _WIN32
    // Windows detection
    // Check SMEP/SMAP via CPUID and CR4 (requires kernel mode for CR4)
    uint32_t cpu_info[4] = {0};
    
    // CPUID leaf 7, subleaf 0
    __cpuidex((int*)cpu_info, 7, 0);
    
    // Check SMEP support (bit 7 of EBX)
    bool smep_supported = (cpu_info[1] & (1 << 7)) != 0;
    
    // Check SMAP support (bit 20 of EBX)
    bool smap_supported = (cpu_info[1] & (1 << 20)) != 0;
    
    // Try to read CR4 (may fail in user mode)
    // In user mode, we typically can't read CR4 directly
    // We'll use a safer approach: check if the feature is supported
    // and assume it's enabled if supported (conservative approach for research)
    config.smep_enabled = smep_supported;
    config.smap_enabled = smap_supported;
    
    // Attempt to read CR4 if possible (requires kernel mode or special privileges)
    // This is commented out for user-mode safety
    /*
    uint64_t cr4 = 0;
    __try {
        cr4 = __readcr4();
        config.smep_enabled = check_smep_cr4(cr4);
        config.smap_enabled = check_smap_cr4(cr4);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Fall back to feature support check
        config.smep_enabled = smep_supported;
        config.smap_enabled = smap_supported;
    }
    */
    
    if (smep_supported) {
        config.enabled_mitigations |= MITIGATION_SMEP;
    }
    if (smap_supported) {
        config.enabled_mitigations |= MITIGATION_SMAP;
    }
    
    // Check for VBS/HyperGuard (Windows-specific)
    // This requires registry/system queries
    
#elif __linux__
    // Linux detection
    unsigned int eax, ebx, ecx, edx;
    
    // CPUID leaf 7, subleaf 0
    if (__get_cpuid_max(0, NULL) >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        
        // Check SMEP support (bit 7 of EBX)
        if (ebx & (1 << 7)) {
            config.enabled_mitigations |= MITIGATION_SMEP;
            config.smep_enabled = true;
        }
        
        // Check SMAP support (bit 20 of EBX)
        if (ebx & (1 << 20)) {
            config.enabled_mitigations |= MITIGATION_SMAP;
            config.smap_enabled = true;
        }
    }
    
    // Check KASLR (via /proc/kallsyms or kernel config)
    // Check KPTI (via /proc/cpuinfo or kernel version)
    
    // Check PAC (ARM64 only)
    #ifdef __aarch64__
    config.pac_enabled = detect_pac_arm64();
    if (config.pac_enabled) {
        config.enabled_mitigations |= MITIGATION_PAC;
    }
    #endif
#endif
    
    return config;
}

bool is_mitigation_enabled(mitigation_config_t* config, mitigation_type_t type) {
    if (!config) return false;
    return (config->enabled_mitigations & type) != 0;
}

uint32_t get_cpu_features_x86(void) {
    uint32_t features = 0;
    
#ifdef _WIN32
    uint32_t cpu_info[4] = {0};
    __cpuid((int*)cpu_info, 1);
    
    // Check various features
    if (cpu_info[3] & (1 << 20)) features |= 0x01; // NX bit
    
    __cpuidex((int*)cpu_info, 7, 0);
    if (cpu_info[1] & (1 << 7)) features |= 0x02;  // SMEP
    if (cpu_info[1] & (1 << 20)) features |= 0x04; // SMAP
#elif __linux__
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (edx & (1 << 20)) features |= 0x01; // NX bit
    
    if (__get_cpuid_max(0, NULL) >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        if (ebx & (1 << 7)) features |= 0x02;  // SMEP
        if (ebx & (1 << 20)) features |= 0x04; // SMAP
    }
#endif
    
    return features;
}

uint32_t get_cpu_features_arm64(void) {
    uint32_t features = 0;
    
#ifdef __aarch64__
    // ARM64 feature detection via ID_AA64ISAR1_EL1
    // This typically requires kernel mode or special system calls
    // For user mode, we can check via /proc/cpuinfo or HWCAP
    #ifdef __linux__
    unsigned long hwcap = getauxval(AT_HWCAP);
    // Check for PAC support (implementation dependent)
    #endif
#endif
    
    return features;
}

// NOTE: check_smep_cr4()/check_smap_cr4() are not currently called anywhere
// in this codebase. Their only prior caller was a commented-out CR4 read in
// detect_mitigations() above (guarded out for user-mode safety on Windows).
// A former read_cr4() wrapper around that same commented-out path was
// removed entirely: it was dead code that also broke the MinGW build (it
// depended on MSVC-only __try/__except + <intrin.h>, neither supported by
// the MinGW-w64 toolchain the Makefile's Windows path invokes). These two
// bit-decoders are kept as documented extension points for a future
// privileged CR4 source (e.g. the Windows kernel driver).
bool check_smep_cr4(uint64_t cr4) {
    // SMEP is bit 20 of CR4
    return (cr4 & (1ULL << 20)) != 0;
}

bool check_smap_cr4(uint64_t cr4) {
    // SMAP is bit 21 of CR4
    return (cr4 & (1ULL << 21)) != 0;
}

bool detect_pac_arm64(void) {
#ifdef __aarch64__
    #ifdef __linux__
    // Check via /proc/cpuinfo or HWCAP
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Features") && strstr(line, "paca")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    #endif
#endif
    return false;
}

// NOTE: not currently called anywhere in this codebase.
uint64_t get_pac_key(pac_key_domain_t domain) {
    // Getting PAC keys requires kernel mode or special system calls
    // This is a placeholder - actual implementation would need
    // kernel module or privileged access
    (void)domain;
    return 0;
}

