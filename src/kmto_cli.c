#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "kmto_protocol.h"

#define ANSI_CYAN    "\x1b[38;2;100;200;230m"
#define ANSI_WHITE   "\x1b[38;2;230;230;230m"
#define ANSI_GRAY    "\x1b[38;2;160;160;160m"
#define ANSI_GREEN   "\x1b[38;2;130;200;130m"
#define ANSI_AMBER   "\x1b[38;2;220;180;90m"
#define ANSI_RESET   "\x1b[0m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_DIM     "\x1b[2m"

typedef struct kmto_runtime_state {
    bool driver_ready;
    HANDLE device;
    kmto_handshake_response_t handshake;
    char last_error[256];
} kmto_runtime_state_t;

// =================================================================
// Utility
// =================================================================

static uint64_t
kmto_timestamp_ns(void)
{
    FILETIME ft;
    ULARGE_INTEGER ticks;
    GetSystemTimeAsFileTime(&ft);
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    const uint64_t WINDOWS_TO_UNIX_100NS = 116444736000000000ULL;
    if (ticks.QuadPart < WINDOWS_TO_UNIX_100NS) {
        return ticks.QuadPart * 100;
    }
    return (ticks.QuadPart - WINDOWS_TO_UNIX_100NS) * 100;
}

static void
kmto_enable_utf8(void)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, mode);
    }
}

static bool
kmto_stdout_is_console(void)
{
    return GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR;
}

static void
kmto_clear_screen(void)
{
    // Only emit the clear-screen / cursor-home sequence to a real console.
    // When stdout is redirected (piped, captured via `!`, or written to a
    // file), ESC[2J ESC[H would jump the cursor and overwrite instead of
    // appending, garbling captured output. In that case do nothing so the
    // output flows linearly and can be captured cleanly.
    if (!kmto_stdout_is_console()) {
        return;
    }
    printf("\x1b[2J\x1b[H");
}

static void
kmto_banner(void)
{
    printf(ANSI_BOLD ANSI_CYAN);
    printf("\n  KMTO\n");
    printf(ANSI_RESET ANSI_CYAN);
    printf("  Kernel Mitigation Telemetry Observatory (v2)\n");
    printf(ANSI_DIM ANSI_GRAY);
    printf("  --------------------------------------------------\n");
    printf("  SMEP / SMAP / PAC enforcement observation\n");
    printf("  CR4 + MSR snapshot, per-CPU event ring, bugcheck cb\n");
    printf("  --------------------------------------------------\n");
    printf(ANSI_RESET "\n");
}

static void
kmto_show_intro(void)
{
    kmto_clear_screen();
    kmto_banner();
    printf(ANSI_GRAY "Author : Tylersec\n");
    printf("Build  : KMTO CLI / kernel handshake + telemetry\n");
    printf("Scope  : Observation and telemetry — no exploitation paths\n" ANSI_RESET "\n");
}

// =================================================================
// Driver IOCTL plumbing
// =================================================================

static bool
kmto_connect_driver(kmto_runtime_state_t* state)
{
    state->device = CreateFileA(KMTO_USER_DEVICE_PATH,
                                GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (state->device == INVALID_HANDLE_VALUE) {
        snprintf(state->last_error, sizeof(state->last_error),
                 "Driver handle failed (error %lu)", GetLastError());
        state->driver_ready = false;
        state->device = NULL;
        return false;
    }

    kmto_handshake_request_t request = {0};
    request.version = KMTO_PROTOCOL_VERSION;
    request.capabilities = KMTO_CAP_TELEMETRY |
                           KMTO_CAP_TEST_MATRIX |
                           KMTO_CAP_PAC_OBSERVER |
                           KMTO_CAP_VISUAL_CONSOLE |
                           KMTO_CAP_EVENT_RING;
    request.timestamp_ns = kmto_timestamp_ns();
    strncpy(request.client_name, "kmto_cli", sizeof(request.client_name) - 1);
    request.client_name[sizeof(request.client_name) - 1] = '\0';

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(state->device, KMTO_IOCTL_HANDSHAKE,
                              &request, sizeof(request),
                              &state->handshake, sizeof(state->handshake),
                              &bytesReturned, NULL);
    if (!ok || bytesReturned != sizeof(state->handshake)) {
        snprintf(state->last_error, sizeof(state->last_error),
                 "Handshake IOCTL failed (error %lu)", GetLastError());
        CloseHandle(state->device);
        state->device = NULL;
        state->driver_ready = false;
        return false;
    }

    state->driver_ready = (state->handshake.status == KMTO_HANDSHAKE_OK);
    if (!state->driver_ready) {
        snprintf(state->last_error, sizeof(state->last_error),
                 "Driver responded with status %u",
                 state->handshake.status);
    }
    return state->driver_ready;
}

static bool
kmto_ioctl_get_cr4(HANDLE device, kmto_cr4_snapshot_t *out)
{
    DWORD br = 0;
    BOOL ok = DeviceIoControl(device, KMTO_IOCTL_GET_CR4_SNAPSHOT,
                              NULL, 0,
                              out, sizeof(*out),
                              &br, NULL);
    return ok && br == sizeof(*out);
}

static bool
kmto_ioctl_get_events(HANDLE device, uint32_t cpu, uint32_t max_events,
                      kmto_event_t *events, uint32_t *out_count,
                      uint32_t *out_lost)
{
    size_t hdrSize = offsetof(kmto_get_events_response_t, events);
    size_t bufSize = hdrSize + (size_t)max_events * sizeof(kmto_event_t);

    uint8_t stack_buf[8192];  // 8 KB stack scratch — fits ~140 events
    uint8_t *buf = stack_buf;
    bool   heap = false;

    if (bufSize > sizeof(stack_buf)) {
        buf = (uint8_t *)malloc(bufSize);
        if (!buf) return false;
        heap = true;
    }

    kmto_get_events_request_t req = { .cpu_number = cpu, .max_events = max_events };
    DWORD br = 0;
    BOOL ok = DeviceIoControl(device, KMTO_IOCTL_GET_EVENTS,
                              &req, sizeof(req),
                              buf, (DWORD)bufSize,
                              &br, NULL);
    bool success = false;
    if (ok && br >= hdrSize) {
        kmto_get_events_response_t *resp = (kmto_get_events_response_t *)buf;
        *out_count = resp->event_count;
        *out_lost  = resp->lost_events;
        if (resp->event_count <= max_events) {
            memcpy(events, resp->events,
                   (size_t)resp->event_count * sizeof(kmto_event_t));
            success = true;
        }
    }

    if (heap) free(buf);
    return success;
}

static bool
kmto_ioctl_get_stats(HANDLE device, kmto_stats_t *out)
{
    DWORD br = 0;
    BOOL ok = DeviceIoControl(device, KMTO_IOCTL_GET_STATS,
                              NULL, 0,
                              out, sizeof(*out),
                              &br, NULL);
    return ok && br == sizeof(*out);
}

static bool
kmto_ioctl_reset(HANDLE device)
{
    DWORD br = 0;
    return DeviceIoControl(device, KMTO_IOCTL_RESET,
                           NULL, 0, NULL, 0, &br, NULL) ? true : false;
}

static bool
kmto_ioctl_configure(HANDLE device, uint32_t enable_mask, uint32_t interval_ms,
                     kmto_configure_response_t *out)
{
    kmto_configure_request_t req = {
        .enable_mask = enable_mask,
        .sampling_interval_ms = interval_ms
    };
    DWORD br = 0;
    BOOL ok = DeviceIoControl(device, KMTO_IOCTL_CONFIGURE,
                              &req, sizeof(req),
                              out, sizeof(*out),
                              &br, NULL);
    return ok && br == sizeof(*out);
}

// =================================================================
// Display helpers — interpret CR4 bits, event types, etc.
// =================================================================

static void
kmto_print_cr4_snapshot(const kmto_cr4_snapshot_t *snap)
{
    printf(ANSI_BOLD "  CR4 / MSR snapshot (CPU %u, t=%llu)\n" ANSI_RESET, snap->cpu,
           (unsigned long long)snap->timestamp_qpc);
    printf("  CR4                  : 0x%016llx\n", (unsigned long long)snap->cr4);
    printf("    [20] SMEP          : %s\n", (snap->cr4 & (1ULL << 20)) ? "ENABLED" : "disabled");
    printf("    [21] SMAP          : %s\n", (snap->cr4 & (1ULL << 21)) ? "ENABLED" : "disabled");
    printf("    [22] PKE           : %s\n", (snap->cr4 & (1ULL << 22)) ? "ENABLED" : "disabled");
    printf("    [23] CET           : %s\n", (snap->cr4 & (1ULL << 23)) ? "ENABLED" : "disabled");
    printf("    [17] PCIDE         : %s\n", (snap->cr4 & (1ULL << 17)) ? "ENABLED" : "disabled");
    printf("    [13] VMXE          : %s\n", (snap->cr4 & (1ULL << 13)) ? "ENABLED" : "disabled");
    printf("  IA32_EFER            : 0x%016llx\n", (unsigned long long)snap->ia32_efer);
    printf("    [11] NXE           : %s\n", (snap->ia32_efer & (1ULL << 11)) ? "ENABLED" : "disabled");
    printf("    [10] LMA           : %s\n", (snap->ia32_efer & (1ULL << 10)) ? "ENABLED" : "disabled");
    printf("  IA32_FEATURE_CONTROL : 0x%016llx\n", (unsigned long long)snap->ia32_feature_control);
    printf("    [0] Lock           : %s\n", (snap->ia32_feature_control & 1ULL) ? "LOCKED" : "unlocked");
    printf("    [2] VMX outside SMX: %s\n", (snap->ia32_feature_control & (1ULL << 2)) ? "ENABLED" : "disabled");
    printf("  IA32_PAT             : 0x%016llx\n", (unsigned long long)snap->ia32_pat);
    printf("  IA32_FS_BASE         : 0x%016llx\n", (unsigned long long)snap->ia32_fs_base);
    printf("  IA32_GS_BASE         : 0x%016llx\n", (unsigned long long)snap->ia32_gs_base);
}

static const char *
kmto_event_type_str(uint32_t et)
{
    switch (et) {
        case KMTO_EVT_CR4_SAMPLE:  return "CR4_SAMPLE";
        case KMTO_EVT_MSR_SAMPLE:  return "MSR_SAMPLE";
        case KMTO_EVT_BUGCHECK:    return "BUGCHECK";
        case KMTO_EVT_DRIVER_INIT: return "DRIVER_INIT";
        case KMTO_EVT_DRIVER_STOP: return "DRIVER_STOP";
        default:                   return "UNKNOWN";
    }
}

static void
kmto_print_event_row(const kmto_event_t *e)
{
    printf("  [seq=%6llu cpu=%u t=%llu] %-12s  d0=0x%016llx d1=0x%016llx\n",
           (unsigned long long)e->sequence_id,
           e->cpu,
           (unsigned long long)e->timestamp_qpc,
           kmto_event_type_str(e->event_type),
           (unsigned long long)e->data[0],
           (unsigned long long)e->data[1]);
}

static void
kmto_print_stats(const kmto_stats_t *s)
{
    printf(ANSI_BOLD "  Driver telemetry stats\n" ANSI_RESET);
    printf("  Active CPUs            : %u\n", s->active_cpus);
    printf("  Sampling interval (ms) : %u\n", s->sampling_interval_ms);
    printf("  Driver uptime (ms)     : %llu\n", (unsigned long long)s->driver_uptime_ms);
    printf("  Total events written   : %llu\n", (unsigned long long)s->total_events_written);
    printf("  Total events drained   : %llu\n", (unsigned long long)s->total_events_drained);
    printf("  Total lost events      : %llu\n", (unsigned long long)s->total_lost_events);
    printf("  CR4 samples            : %llu\n", (unsigned long long)s->cr4_samples);
    printf("  MSR samples            : %llu\n", (unsigned long long)s->msr_samples);
    printf("  BugCheck events        : %llu\n", (unsigned long long)s->bugcheck_events);
}

// =================================================================
// Status panel + menu
// =================================================================

static void
kmto_show_status_panel(const kmto_runtime_state_t* state)
{
    printf(ANSI_DIM);
    printf("  --------------------------------------------------\n");
    printf("  Driver link : %s%s%s\n",
           state->driver_ready ? ANSI_GREEN : ANSI_AMBER,
           state->driver_ready ? "ONLINE" : "OFFLINE (simulation mode)",
           ANSI_DIM);
    if (state->driver_ready) {
        printf("  Session tok : 0x%016llx\n",
               (unsigned long long)state->handshake.session_token);
        printf("  Driver build: %u\n", state->handshake.driver_build);
        printf("  Author      : %s\n", state->handshake.author);
        printf("  Banner      : %s\n", state->handshake.banner);
    } else {
        printf("  Reason      : %s\n", state->last_error);
    }
    printf("  --------------------------------------------------\n" ANSI_RESET "\n");
}

static void
kmto_show_menu(void)
{
    printf(ANSI_BOLD "Available actions:\n" ANSI_RESET);
    printf("  [1] CR4 / MSR snapshot (driver-side authoritative read)\n");
    printf("  [2] Drain event ring (CPU 0, 64 events)\n");
    printf("  [3] Show telemetry stats\n");
    printf("  [4] Configure: enable sampler + bugcheck callback (1 Hz)\n");
    printf("  [5] Configure: disable sampler + bugcheck callback\n");
    printf("  [6] Reset rings + counters\n");
    printf("  [7] Session log & driver handshake details\n");
    printf("  [9] Exit\n\n");
    printf("Choice > ");
}

static void
kmto_pause(void)
{
    printf("\nPress ENTER to continue...");
    (void)getchar();
}

static void
kmto_section_header(const char* title)
{
    kmto_clear_screen();
    kmto_banner();
    printf(ANSI_BOLD "%s\n" ANSI_RESET, title);
    printf(ANSI_GRAY "  --------------------------------------------------\n" ANSI_RESET);
}

static void
kmto_offline_notice(void)
{
    printf(ANSI_AMBER "  [simulation mode] Driver offline — IOCTL calls "
           "would normally be made here.\n" ANSI_RESET);
}

// =================================================================
// Menu actions
// =================================================================

static void
kmto_action_cr4_snapshot(kmto_runtime_state_t* state)
{
    kmto_section_header("CR4 / MSR SNAPSHOT");
    if (!state->driver_ready) {
        kmto_offline_notice();
        return;
    }
    kmto_cr4_snapshot_t snap;
    if (kmto_ioctl_get_cr4(state->device, &snap)) {
        kmto_print_cr4_snapshot(&snap);
    } else {
        printf(ANSI_AMBER "  IOCTL_GET_CR4_SNAPSHOT failed: %lu\n" ANSI_RESET,
               GetLastError());
    }
}

static void
kmto_action_drain_events(kmto_runtime_state_t* state)
{
    kmto_section_header("EVENT RING DRAIN (CPU 0, up to 64)");
    if (!state->driver_ready) {
        kmto_offline_notice();
        return;
    }
    kmto_event_t events[64];
    uint32_t count = 0, lost = 0;
    if (kmto_ioctl_get_events(state->device, 0, 64, events, &count, &lost)) {
        printf("  Drained %u events (lost since last drain: %u)\n\n",
               count, lost);
        for (uint32_t i = 0; i < count; i++) {
            kmto_print_event_row(&events[i]);
        }
        if (count == 0) {
            printf(ANSI_GRAY "  (no events — enable sampler via [4])\n" ANSI_RESET);
        }
    } else {
        printf(ANSI_AMBER "  IOCTL_GET_EVENTS failed: %lu\n" ANSI_RESET,
               GetLastError());
    }
}

static void
kmto_action_stats(kmto_runtime_state_t* state)
{
    kmto_section_header("TELEMETRY STATS");
    if (!state->driver_ready) {
        kmto_offline_notice();
        return;
    }
    kmto_stats_t stats;
    if (kmto_ioctl_get_stats(state->device, &stats)) {
        kmto_print_stats(&stats);
    } else {
        printf(ANSI_AMBER "  IOCTL_GET_STATS failed: %lu\n" ANSI_RESET,
               GetLastError());
    }
}

static void
kmto_action_configure(kmto_runtime_state_t* state, bool enable)
{
    kmto_section_header(enable ? "CONFIGURE — ENABLE OBSERVERS"
                                : "CONFIGURE — DISABLE OBSERVERS");
    if (!state->driver_ready) {
        kmto_offline_notice();
        return;
    }
    kmto_configure_response_t resp;
    uint32_t mask = enable ? KMTO_CFG_ALL : 0;
    uint32_t interval = enable ? 1000u : 0u;
    if (kmto_ioctl_configure(state->device, mask, interval, &resp)) {
        printf("  active_mask          : 0x%08x  (sampler=%c, bugcheck_cb=%c)\n",
               resp.active_mask,
               (resp.active_mask & KMTO_CFG_CR4_SAMPLER) ? 'Y' : 'N',
               (resp.active_mask & KMTO_CFG_BUGCHECK_CB) ? 'Y' : 'N');
        printf("  sampling_interval_ms : %u\n", resp.sampling_interval_ms);
    } else {
        printf(ANSI_AMBER "  IOCTL_CONFIGURE failed: %lu\n" ANSI_RESET,
               GetLastError());
    }
}

static void
kmto_action_reset(kmto_runtime_state_t* state)
{
    kmto_section_header("RESET — clear rings + counters");
    if (!state->driver_ready) {
        kmto_offline_notice();
        return;
    }
    if (kmto_ioctl_reset(state->device)) {
        printf(ANSI_GREEN "  Reset OK\n" ANSI_RESET);
    } else {
        printf(ANSI_AMBER "  IOCTL_RESET failed: %lu\n" ANSI_RESET,
               GetLastError());
    }
}

static void
kmto_action_session_info(kmto_runtime_state_t* state)
{
    kmto_section_header("SESSION LOG");
    kmto_show_status_panel(state);
    if (!state->driver_ready) {
        printf(ANSI_GRAY "  See TECHNICAL_DEEP_DIVE.md for driver bring-up.\n" ANSI_RESET);
    }
}

static void
kmto_handle_choice(int choice, kmto_runtime_state_t* state)
{
    switch (choice) {
        case 1: kmto_action_cr4_snapshot(state);    break;
        case 2: kmto_action_drain_events(state);    break;
        case 3: kmto_action_stats(state);           break;
        case 4: kmto_action_configure(state, true); break;
        case 5: kmto_action_configure(state, false);break;
        case 6: kmto_action_reset(state);           break;
        case 7: kmto_action_session_info(state);    break;
        default: return;
    }
    kmto_pause();
}

// =================================================================
// Non-interactive demo (linear output, capture/GIF-friendly)
// =================================================================

static void
kmto_run_demo(kmto_runtime_state_t* state)
{
    kmto_stats_t s0, s1;
    kmto_cr4_snapshot_t snap;
    kmto_configure_response_t cfg;
    kmto_event_t events[32];
    uint32_t count = 0, lost = 0, i;

    kmto_banner();
    kmto_show_status_panel(state);
    if (!state->driver_ready) {
        printf("Driver offline; nothing to demonstrate. Load the KMTO driver first.\n");
        return;
    }

    printf("== CR4 / MSR snapshot (driver-side authoritative read) ==\n");
    if (kmto_ioctl_get_cr4(state->device, &snap)) {
        kmto_print_cr4_snapshot(&snap);
    }

    printf("\n== Resetting rings + counters for a clean measurement window ==\n");
    if (kmto_ioctl_reset(state->device)) {
        printf("  reset OK (prior lifetime counters cleared; the deltas below are\n"
               "  measured from zero over this run, not since driver load)\n");
    }

    printf("\n== Enabling sampler + bugcheck callback (1 Hz) ==\n");
    if (kmto_ioctl_configure(state->device, KMTO_CFG_ALL, 1000, &cfg)) {
        printf("  active_mask=0x%08x  interval=%ums\n",
               cfg.active_mask, cfg.sampling_interval_ms);
    }

    kmto_ioctl_get_stats(state->device, &s0);
    printf("\n== Sampling for 5 seconds ==\n");
    Sleep(5000);
    kmto_ioctl_get_stats(state->device, &s1);

    printf("\n== Telemetry stats (after 5s) ==\n");
    kmto_print_stats(&s1);
    printf("  Delta over 5s: +%llu events (+%llu CR4, +%llu MSR), lost=%llu\n",
           (unsigned long long)(s1.total_events_written - s0.total_events_written),
           (unsigned long long)(s1.cr4_samples - s0.cr4_samples),
           (unsigned long long)(s1.msr_samples - s0.msr_samples),
           (unsigned long long)s1.total_lost_events);

    printf("\n== Draining CPU 0 event ring ==\n");
    if (kmto_ioctl_get_events(state->device, 0, 32, events, &count, &lost)) {
        printf("  %u events (lost since last drain: %u)\n", count, lost);
        for (i = 0; i < count && i < 16; i++) {
            kmto_print_event_row(&events[i]);
        }
    }
    printf("\n== demo complete ==\n");
}

// =================================================================
// main
// =================================================================

int
main(int argc, char** argv)
{
    kmto_runtime_state_t state = {0};
    bool demo = false;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--demo") == 0 || strcmp(argv[i], "-d") == 0) {
            demo = true;
        }
    }

    kmto_enable_utf8();
    SetConsoleTitleA("KMTO - Kernel Mitigation Telemetry Observatory");

    if (demo) {
        // Linear, non-interactive run: connect, exercise the telemetry path,
        // print everything top-to-bottom with no screen clears. Suitable for
        // piping / capture (kmto_cli --demo > out.txt) and for recording a GIF.
        (void)kmto_connect_driver(&state);
        kmto_run_demo(&state);
        if (state.device) CloseHandle(state.device);
        return 0;
    }

    kmto_show_intro();

    if (!kmto_connect_driver(&state)) {
        printf(ANSI_AMBER "[!] Kernel handshake unavailable. Running in simulation mode.\n" ANSI_RESET);
        Sleep(1000);
    } else {
        printf(ANSI_GREEN "[+] Driver handshake complete. Telemetry session open.\n" ANSI_RESET);
        Sleep(800);
    }

    (void)getchar();

    bool running = true;
    while (running) {
        kmto_clear_screen();
        kmto_banner();
        kmto_show_status_panel(&state);
        kmto_show_menu();

        int c = getchar();
        if (c == '\n' || c == '\r') continue;
        if (c == EOF) break;
        if (c == '9') { running = false; break; }
        kmto_handle_choice(c - '0', &state);
    }

    if (state.device) CloseHandle(state.device);

    kmto_clear_screen();
    printf(ANSI_CYAN ">>> KMTO session closed.\n" ANSI_RESET);
    return 0;
}

#else

int main(void) { return 0; }

#endif
