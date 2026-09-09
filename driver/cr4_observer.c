//
// KMTO — CR4 / MSR observer.
//
// Two telemetry sources:
//
// 1. Periodic sampler — a KTIMER fires on a configurable interval
//    (default 1000 ms). When the timer DPC runs, it queues one
//    targeted DPC per CPU. Each per-CPU DPC reads CR4 + a small
//    MSR set on its own CPU and emits a KMTO_EVT_CR4_SAMPLE event
//    into that CPU's ring. This is the only "live" observation
//    surface — it tells the operator that CR4[20]/CR4[21] are still
//    set today, the IA32_EFER NXE bit is still on, and so on.
//
// 2. BugCheck callback — KeRegisterBugCheckCallback registers a
//    routine that runs at HIGH_LEVEL during bug check. We write a
//    final marker (QPC + last-known CR4) into a NonPagedPool scratch
//    buffer. The scratch is reachable from a crash dump and gives
//    forensic context: "the system bugchecked and CR4 had value X
//    at that instant."
//
// Defensive constraints honoured:
//
//   - Reads only. No __writecr4, no __writemsr, no MSR write of any
//     kind. The driver never modifies privileged state.
//
//   - Sampler is opt-in via IOCTL_CONFIGURE. Default state at
//     DriverEntry is "not sampling, callback not registered" so
//     the driver imposes zero observable overhead until userland
//     explicitly enables it.
//
//   - BugCheck callback never accesses pageable memory and never
//     calls non-trivial kernel APIs (HIGH_LEVEL constraint).
//
//   - All __readmsr indices used here are architecturally present
//     on any x86_64 Windows-capable CPU; we do not probe optional
//     MSRs.
//

#include "../include/kmto_kernel_state.h"
#include <intrin.h>

#define KMTO_SAMPLING_INTERVAL_MIN_MS   50u
#define KMTO_SAMPLING_INTERVAL_MAX_MS   60000u
#define KMTO_SAMPLING_INTERVAL_DEFAULT  1000u

// -----------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------

static KDEFERRED_ROUTINE KmtopSamplerTimerDpc;
static KDEFERRED_ROUTINE KmtopPerCpuSamplerDpc;
static KBUGCHECK_CALLBACK_ROUTINE KmtopBugCheckCallback;

static VOID KmtopStartSampler(_Inout_ PKMTO_OBSERVER_STATE State);
static VOID KmtopStopSampler(_Inout_ PKMTO_OBSERVER_STATE State);
static VOID KmtopRegisterBugCheckCb(_Inout_ PKMTO_OBSERVER_STATE State);
static VOID KmtopUnregisterBugCheckCb(_Inout_ PKMTO_OBSERVER_STATE State);

// -----------------------------------------------------------------
// Public API
// -----------------------------------------------------------------

NTSTATUS
KmtoObserverInit(_Inout_ PKMTO_OBSERVER_STATE State)
{
    ULONG i;

    if (!State || !State->PerCpuRings) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate the per-CPU sampler DPC array. One DPC per CPU so we
    // can queue them independently from the master timer DPC.
    State->PerCpuSamplerDpc = (KDPC *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(KDPC) * State->ProcessorCount,
        KMTO_MEM_TAG);

    if (!State->PerCpuSamplerDpc) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < State->ProcessorCount; i++) {
        KeInitializeDpc(&State->PerCpuSamplerDpc[i],
                        KmtopPerCpuSamplerDpc,
                        (PVOID)(ULONG_PTR)i);    // context = CPU index
        KeSetTargetProcessorDpc(&State->PerCpuSamplerDpc[i], (CCHAR)i);
    }

    KeInitializeTimer(&State->SamplerTimer);
    KeInitializeDpc(&State->SamplerTimerDpc, KmtopSamplerTimerDpc, State);

    // BugCheck callback record — NOT yet registered; KmtoObserverConfigure
    // wires it in when KMTO_CFG_BUGCHECK_CB is set.
    KeInitializeCallbackRecord(&State->BugCheckRecord);
    RtlZeroMemory(State->BugCheckScratch, sizeof(State->BugCheckScratch));

    State->SamplingIntervalMs = KMTO_SAMPLING_INTERVAL_DEFAULT;
    State->SamplerActive      = FALSE;
    State->BugCheckRegistered = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] Observer init OK (%lu CPUs)\n",
               State->ProcessorCount);

    return STATUS_SUCCESS;
}

VOID
KmtoObserverCleanup(_Inout_ PKMTO_OBSERVER_STATE State)
{
    if (!State) {
        return;
    }

    KmtopStopSampler(State);
    KmtopUnregisterBugCheckCb(State);

    if (State->PerCpuSamplerDpc) {
        ExFreePoolWithTag(State->PerCpuSamplerDpc, KMTO_MEM_TAG);
        State->PerCpuSamplerDpc = NULL;
    }
}

NTSTATUS
KmtoObserverConfigure(
    _Inout_ PKMTO_OBSERVER_STATE State,
    _In_    ULONG                EnableMask,
    _In_    ULONG                IntervalMs,
    _Out_   PULONG               OutActiveMask,
    _Out_   PULONG               OutIntervalMs)
{
    BOOLEAN wantSampler;
    BOOLEAN wantBugCheck;

    if (!State || !OutActiveMask || !OutIntervalMs) {
        return STATUS_INVALID_PARAMETER;
    }

    // 0 means "leave unchanged"; otherwise clamp to legal range.
    if (IntervalMs != 0) {
        if (IntervalMs < KMTO_SAMPLING_INTERVAL_MIN_MS) {
            IntervalMs = KMTO_SAMPLING_INTERVAL_MIN_MS;
        } else if (IntervalMs > KMTO_SAMPLING_INTERVAL_MAX_MS) {
            IntervalMs = KMTO_SAMPLING_INTERVAL_MAX_MS;
        }
        State->SamplingIntervalMs = IntervalMs;
    }

    wantSampler  = (EnableMask & KMTO_CFG_CR4_SAMPLER) != 0;
    wantBugCheck = (EnableMask & KMTO_CFG_BUGCHECK_CB) != 0;

    if (wantSampler && !State->SamplerActive) {
        KmtopStartSampler(State);
    } else if (!wantSampler && State->SamplerActive) {
        KmtopStopSampler(State);
    } else if (wantSampler && State->SamplerActive &&
               IntervalMs != 0) {
        // Period changed mid-flight — restart with new interval.
        KmtopStopSampler(State);
        KmtopStartSampler(State);
    }

    if (wantBugCheck && !State->BugCheckRegistered) {
        KmtopRegisterBugCheckCb(State);
    } else if (!wantBugCheck && State->BugCheckRegistered) {
        KmtopUnregisterBugCheckCb(State);
    }

    *OutActiveMask =
        (State->SamplerActive      ? KMTO_CFG_CR4_SAMPLER : 0) |
        (State->BugCheckRegistered ? KMTO_CFG_BUGCHECK_CB : 0);
    *OutIntervalMs = State->SamplingIntervalMs;
    return STATUS_SUCCESS;
}

VOID
KmtoReadCr4Snapshot(_Out_ kmto_cr4_snapshot_t *Out)
{
    KIRQL oldIrql;
    LARGE_INTEGER qpc;

    if (!Out) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    // Pin to the current CPU so the snapshot is internally
    // consistent (the architectural CR4/MSR set is per-CPU; we
    // record which one we read on).
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    Out->cr4                  = __readcr4();
    Out->ia32_efer            = __readmsr(KMTO_MSR_IA32_EFER);
    Out->ia32_feature_control = __readmsr(KMTO_MSR_IA32_FEATURE_CONTROL);
    Out->ia32_pat             = __readmsr(KMTO_MSR_IA32_PAT);
    Out->ia32_fs_base         = __readmsr(KMTO_MSR_IA32_FS_BASE);
    Out->ia32_gs_base         = __readmsr(KMTO_MSR_IA32_GS_BASE);

    qpc = KeQueryPerformanceCounter(NULL);
    Out->timestamp_qpc = (ULONG64)qpc.QuadPart;
    Out->cpu           = KeGetCurrentProcessorNumber();

    KeLowerIrql(oldIrql);
}

VOID
KmtoStatsSnapshot(
    _In_  PKMTO_OBSERVER_STATE State,
    _Out_ kmto_stats_t        *Out)
{
    ULONG i;
    ULONG64 totalWritten = 0, totalDrained = 0, totalLost = 0;
    ULONG64 cr4Samples = 0, msrSamples = 0, bugChecks = 0;
    LARGE_INTEGER now;

    if (!Out) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    if (!State || !State->PerCpuRings) {
        return;
    }

    // Sum lightweight per-CPU counters. Reads of ULONG64 are not
    // strictly atomic on x86, but the per-CPU producer only writes
    // its own slot so torn reads at worst undercount by one — fine
    // for telemetry.
    for (i = 0; i < State->ProcessorCount; i++) {
        const KMTO_PERCPU_RING *ring = &State->PerCpuRings[i];
        totalWritten += ring->EventsWritten;
        totalDrained += ring->EventsDrained;
        totalLost    += ring->LostEvents;
    }

    // Per-event-type counters: walk live ring sequence ids would be
    // expensive; instead we maintain a running tally elsewhere
    // (Stats struct on State). For now, fold-in the cumulative
    // numbers we have.
    cr4Samples = State->Stats.cr4_samples;
    msrSamples = State->Stats.msr_samples;
    bugChecks  = State->Stats.bugcheck_events;

    Out->total_events_written = totalWritten;
    Out->total_events_drained = totalDrained;
    Out->total_lost_events    = totalLost;
    Out->cr4_samples          = cr4Samples;
    Out->msr_samples          = msrSamples;
    Out->bugcheck_events      = bugChecks;
    Out->active_cpus          = State->ProcessorCount;
    Out->sampling_interval_ms = State->SamplingIntervalMs;

    now = KeQueryPerformanceCounter(NULL);
    if (State->QpcFrequency.QuadPart > 0) {
        ULONG64 ticks = (ULONG64)(now.QuadPart - State->DriverStartQpc.QuadPart);
        Out->driver_uptime_ms =
            (ticks * 1000ULL) / (ULONG64)State->QpcFrequency.QuadPart;
    }
    Out->driver_build = 0x20251118ULL;
}

// -----------------------------------------------------------------
// Sampler — start / stop
// -----------------------------------------------------------------

static VOID
KmtopStartSampler(_Inout_ PKMTO_OBSERVER_STATE State)
{
    LARGE_INTEGER dueTime;
    LONG periodMs;

    if (!State || State->SamplerActive) {
        return;
    }

    periodMs = (LONG)State->SamplingIntervalMs;

    // Relative time — negative means "from now".
    dueTime.QuadPart = -((LONGLONG)periodMs * 10000LL);

    KeSetTimerEx(&State->SamplerTimer,
                 dueTime,
                 periodMs,
                 &State->SamplerTimerDpc);

    State->SamplerActive = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] Sampler started (%ld ms)\n", periodMs);
}

static VOID
KmtopStopSampler(_Inout_ PKMTO_OBSERVER_STATE State)
{
    ULONG i;

    if (!State || !State->SamplerActive) {
        return;
    }

    // Set the flag FIRST so any in-flight or about-to-fire DPCs
    // observe the disable and bail out before producing a sample.
    // The cancel + remove + flush chain below then handles cleanup
    // proper. Without this ordering, a periodic-timer fire racing
    // with KeCancelTimer can queue per-CPU DPCs that see
    // SamplerActive=TRUE and emit one more round of samples.
    State->SamplerActive = FALSE;

    KeCancelTimer(&State->SamplerTimer);

    // Make sure no per-CPU DPC is still queued before we return.
    // KeRemoveQueueDpc returns FALSE if it wasn't queued or
    // already dispatched.
    if (State->PerCpuSamplerDpc) {
        for (i = 0; i < State->ProcessorCount; i++) {
            (VOID)KeRemoveQueueDpc(&State->PerCpuSamplerDpc[i]);
        }
    }

    KeFlushQueuedDpcs();   // wait for in-flight DPCs to drain

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] Sampler stopped\n");
}

// -----------------------------------------------------------------
// Sampler — DPCs
// -----------------------------------------------------------------

// Master timer DPC. Runs on whichever CPU the timer fires on; its
// only job is to queue one targeted DPC per CPU so every CPU
// contributes a fresh CR4/MSR snapshot to its own ring.
static VOID
KmtopSamplerTimerDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArg1,
    _In_opt_ PVOID SystemArg2)
{
    PKMTO_OBSERVER_STATE state = (PKMTO_OBSERVER_STATE)DeferredContext;
    ULONG i;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);

    // Stale-fire defense: even if KeCancelTimer raced with us and
    // this DPC fires after KmtopStopSampler set the flag, a
    // disabled sampler must not produce events.
    if (!state || !state->PerCpuSamplerDpc || !state->SamplerActive) {
        return;
    }

    for (i = 0; i < state->ProcessorCount; i++) {
        // KeInsertQueueDpc returns FALSE if the DPC is already
        // queued; that's fine — we just skip this tick on that CPU.
        (VOID)KeInsertQueueDpc(&state->PerCpuSamplerDpc[i], NULL, NULL);
    }
}

// Per-CPU sampler DPC. Runs at DISPATCH_LEVEL on the target CPU.
// Reads CR4 / a small MSR set / QPC, emits a KMTO_EVT_CR4_SAMPLE
// event into the CPU's ring.
static VOID
KmtopPerCpuSamplerDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArg1,
    _In_opt_ PVOID SystemArg2)
{
    ULONG cpu = (ULONG)(ULONG_PTR)DeferredContext;
    ULONG64 data[5];

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);

    // Same stale-fire defense as the master timer DPC: if disable
    // raced with us, no sample.
    if (!g_KmtoState.SamplerActive) {
        return;
    }

    if (cpu != KeGetCurrentProcessorNumber()) {
        // We were rescheduled — unexpected, but harmless. The
        // event would no longer represent the targeted CPU's CR4.
        return;
    }

    data[0] = __readcr4();
    data[1] = __readmsr(KMTO_MSR_IA32_EFER);
    data[2] = __readmsr(KMTO_MSR_IA32_FEATURE_CONTROL);
    data[3] = __readmsr(KMTO_MSR_IA32_PAT);
    // pack FS_BASE high 32b | GS_BASE high 32b is lossy; instead
    // record FS_BASE only and let userland call IOCTL_GET_CR4_SNAPSHOT
    // if it wants the whole set.
    data[4] = __readmsr(KMTO_MSR_IA32_FS_BASE);

    KmtoRingWrite(&g_KmtoState, cpu, KMTO_EVT_CR4_SAMPLE, data);

    // Aggregate counter (PASSIVE-only write would race against the
    // sampler; use InterlockedIncrement to be safe).
    InterlockedIncrement64((volatile LONG64 *)&g_KmtoState.Stats.cr4_samples);
}

// -----------------------------------------------------------------
// BugCheck callback
// -----------------------------------------------------------------

// Runs at HIGH_LEVEL during bug check. Anything other than reading
// CR4 + writing into our pre-allocated scratch buffer is unsafe —
// no APIs that can fault, no allocations, no synchronization.
static VOID
KmtopBugCheckCallback(_In_ PVOID Buffer, _In_ ULONG Length)
{
    UCHAR *scratch = (UCHAR *)Buffer;
    ULONG64 cr4Now;
    LARGE_INTEGER qpcNow;

    if (!scratch || Length < 32) {
        return;
    }

    cr4Now = __readcr4();
    qpcNow = KeQueryPerformanceCounter(NULL);

    // Layout:
    //   0..7   : magic 'KMTOBC@@' (8 bytes)
    //   8..15  : qpcNow
    //   16..23 : cr4Now
    //   24..27 : CPU number
    //   28..31 : reserved
    RtlCopyMemory(scratch + 0, "KMTOBC@@", 8);
    *(ULONG64 *)(scratch + 8)  = (ULONG64)qpcNow.QuadPart;
    *(ULONG64 *)(scratch + 16) = cr4Now;
    *(ULONG *)(scratch + 24)   = KeGetCurrentProcessorNumber();
    *(ULONG *)(scratch + 28)   = 0;

    // We cannot safely write into the ring buffer from here (the
    // per-CPU DPC dispatch path is being torn down by the bug
    // check). The scratch buffer is what survives into a kernel
    // mini-dump if minidumps are enabled.
}

static VOID
KmtopRegisterBugCheckCb(_Inout_ PKMTO_OBSERVER_STATE State)
{
    BOOLEAN registered;

    if (State->BugCheckRegistered) {
        return;
    }

    RtlZeroMemory(State->BugCheckScratch, sizeof(State->BugCheckScratch));

    registered = KeRegisterBugCheckCallback(
        &State->BugCheckRecord,
        KmtopBugCheckCallback,
        State->BugCheckScratch,
        (ULONG)sizeof(State->BugCheckScratch),
        (PUCHAR)"KMTO");

    State->BugCheckRegistered = registered ? TRUE : FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] BugCheck callback %s\n",
               registered ? "registered" : "REGISTRATION FAILED");
}

static VOID
KmtopUnregisterBugCheckCb(_Inout_ PKMTO_OBSERVER_STATE State)
{
    if (!State->BugCheckRegistered) {
        return;
    }
    (VOID)KeDeregisterBugCheckCallback(&State->BugCheckRecord);
    State->BugCheckRegistered = FALSE;
}
