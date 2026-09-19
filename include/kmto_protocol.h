#ifndef KMTO_PROTOCOL_H
#define KMTO_PROTOCOL_H

#include <stdint.h>

#ifdef _WIN32
#ifndef _KERNEL_MODE
#include <windows.h>
#endif
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

// =================================================================
// Protocol version
// =================================================================
//
// 0x00010000 — initial release (handshake only)
// 0x00020000 — adds: CR4/MSR snapshot, per-CPU event ring, stats,
//              reset, configure. Wire-format types appended below.
//
#define KMTO_PROTOCOL_VERSION 0x00020000

#define KMTO_DEVICE_NAME      L"\\Device\\KMTO"
#define KMTO_SYMLINK_NAME     L"\\DosDevices\\KMTO"
#define KMTO_USER_DEVICE_PATH "\\\\.\\KMTO"

// =================================================================
// IOCTL surface (function codes 0x900-0x905)
// =================================================================

#define KMTO_IOCTL_HANDSHAKE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMTO_IOCTL_GET_CR4_SNAPSHOT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMTO_IOCTL_GET_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMTO_IOCTL_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMTO_IOCTL_RESET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KMTO_IOCTL_CONFIGURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS)

// =================================================================
// Client capability flags (handshake.capabilities)
// =================================================================

enum {
    KMTO_CAP_TELEMETRY      = 1u << 0,
    KMTO_CAP_TEST_MATRIX    = 1u << 1,
    KMTO_CAP_PAC_OBSERVER   = 1u << 2,
    KMTO_CAP_VISUAL_CONSOLE = 1u << 3,
    KMTO_CAP_EVENT_RING     = 1u << 4   // v2: client knows how to drain the ring
};

enum {
    KMTO_HANDSHAKE_OK        = 0,
    KMTO_HANDSHAKE_ERR_STATE = 1,
    KMTO_HANDSHAKE_ERR_PROTO = 2
};

// =================================================================
// Handshake (v1, unchanged)
// =================================================================

#pragma pack(push, 1)
typedef struct kmto_handshake_request {
    uint32_t version;
    uint32_t capabilities;
    uint64_t timestamp_ns;
    char     client_name[32];
} kmto_handshake_request_t;

typedef struct kmto_handshake_response {
    uint32_t status;
    uint32_t driver_build;
    uint64_t session_token;
    char     author[32];
    char     banner[64];
} kmto_handshake_response_t;
#pragma pack(pop)

// =================================================================
// v2: CR4 / MSR snapshot
// =================================================================
//
// Read on demand by the driver in kernel mode. Userland CPUID can
// tell you a feature is *supported*; only kernel-mode CR4/MSR reads
// can tell you it is *enabled*. This is the v2 surface's reason for
// existing.
//

// MSR indices the snapshot reports. (Read-only — KMTO never writes
// MSRs.)
#define KMTO_MSR_IA32_EFER             0xC0000080u  // NXE bit, LMA, LME
#define KMTO_MSR_IA32_FEATURE_CONTROL  0x0000003Au  // VMX / SGX gating
#define KMTO_MSR_IA32_PAT              0x00000277u  // Page-attribute table
#define KMTO_MSR_IA32_FS_BASE          0xC0000100u
#define KMTO_MSR_IA32_GS_BASE          0xC0000101u

#pragma pack(push, 1)
typedef struct kmto_cr4_snapshot {
    uint64_t cr4;                 // __readcr4()
    uint64_t ia32_efer;           // MSR 0xC0000080
    uint64_t ia32_feature_control;// MSR 0x0000003A
    uint64_t ia32_pat;            // MSR 0x00000277
    uint64_t ia32_fs_base;        // MSR 0xC0000100
    uint64_t ia32_gs_base;        // MSR 0xC0000101
    uint64_t timestamp_qpc;
    uint32_t cpu;                 // CPU the snapshot was taken on
    uint32_t _pad;
} kmto_cr4_snapshot_t;
#pragma pack(pop)

// =================================================================
// v2: Event ring
// =================================================================
//
// The driver maintains a per-CPU ring buffer. A periodic timer DPC
// samples CR4/MSRs on each CPU and writes events; a registered
// BugCheck callback writes a final event at crash time. Userland
// drains via IOCTL_GET_EVENTS.
//

// Event types — appended only, never renumbered.
enum {
    KMTO_EVT_NONE         = 0,
    KMTO_EVT_CR4_SAMPLE   = 1,   // data[0..4] = CR4 + EFER + FEATURE_CONTROL + PAT + FS_BASE/GS_BASE-packed
    KMTO_EVT_MSR_SAMPLE   = 2,   // periodic sampler: data[0..4] = EFER, FEATURE_CONTROL, PAT, FS_BASE, GS_BASE (one per cycle)
    KMTO_EVT_BUGCHECK     = 3,   // data[0] = bugcheck code, data[1..4] = bugcheck params
    KMTO_EVT_DRIVER_INIT  = 4,   // emitted once at DriverEntry
    KMTO_EVT_DRIVER_STOP  = 5    // emitted at unload
};

#pragma pack(push, 1)
typedef struct kmto_event {
    uint64_t timestamp_qpc;
    uint32_t cpu;
    uint32_t event_type;     // one of KMTO_EVT_*
    uint64_t sequence_id;    // monotonic per CPU; gaps imply lost events
    uint64_t data[5];
} kmto_event_t;
#pragma pack(pop)

// IOCTL_GET_EVENTS — drain up to MaxEvents from a specific CPU's ring.
#pragma pack(push, 1)
typedef struct kmto_get_events_request {
    uint32_t cpu_number;         // which CPU's ring to drain
    uint32_t max_events;         // max events the caller's buffer holds
} kmto_get_events_request_t;

typedef struct kmto_get_events_response {
    uint32_t event_count;        // number actually returned
    uint32_t lost_events;        // counter snapshot for this CPU
    kmto_event_t events[1];      // variable length; size from request
} kmto_get_events_response_t;
#pragma pack(pop)

// =================================================================
// v2: Stats
// =================================================================

#pragma pack(push, 1)
typedef struct kmto_stats {
    uint64_t total_events_written;
    uint64_t total_events_drained;
    uint64_t total_lost_events;       // ring-full drops, summed across CPUs
    uint64_t cr4_samples;
    uint64_t msr_samples;
    uint64_t bugcheck_events;
    uint32_t active_cpus;
    uint32_t sampling_interval_ms;
    uint64_t driver_uptime_ms;
    uint64_t driver_build;            // mirrors handshake.driver_build
} kmto_stats_t;
#pragma pack(pop)

// =================================================================
// v2: Configure
// =================================================================

// Configure flags — bit-mask in `enable`.
#define KMTO_CFG_CR4_SAMPLER  (1u << 0)   // periodic CR4/MSR snapshots
#define KMTO_CFG_BUGCHECK_CB  (1u << 1)   // KeBugCheckCallback registration
#define KMTO_CFG_ALL          (KMTO_CFG_CR4_SAMPLER | KMTO_CFG_BUGCHECK_CB)

#pragma pack(push, 1)
typedef struct kmto_configure_request {
    uint32_t enable_mask;             // bits from KMTO_CFG_*
    uint32_t sampling_interval_ms;    // 0 = leave unchanged; valid 50..60000
} kmto_configure_request_t;

typedef struct kmto_configure_response {
    uint32_t active_mask;             // mask actually in effect after the call
    uint32_t sampling_interval_ms;
} kmto_configure_response_t;
#pragma pack(pop)

#endif /* KMTO_PROTOCOL_H */
