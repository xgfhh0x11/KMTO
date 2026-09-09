//
// KMTO — kernel-only state.
//
// Wire-format types live in kmto_protocol.h and are shared with
// userspace. The structures in this header are NOT exposed to
// userland — they are kernel-internal state for the per-CPU ring
// buffer, the periodic CR4/MSR sampler, and the BugCheck callback.
//
// This header MUST only be included from the driver (driver/*.c).
//
#pragma once

#ifndef KMTO_KERNEL_STATE_H
#define KMTO_KERNEL_STATE_H

#include <ntddk.h>
#include "../include/kmto_protocol.h"

// =================================================================
// Ring buffer
// =================================================================
//
// One ring per logical CPU. Producer side: a single timer DPC that
// runs on the CPU whose ring it writes — therefore lockless
// single-producer. Consumer side: the IOCTL handler running in an
// arbitrary user-context thread; reads use a snapshot of Head/Tail
// with InterlockedExchange semantics. Lost-event counter is
// incremented when the producer would overwrite an undrained tail.
//
// Sized at 256 events × ~56 bytes = ~14 KB per CPU; on a 32-thread
// host that's ~448 KB of NonPagedPool, well within budget.

#define KMTO_RING_SIZE   256u
#define KMTO_RING_MASK   (KMTO_RING_SIZE - 1u)

C_ASSERT((KMTO_RING_SIZE & KMTO_RING_MASK) == 0);  // power of two

typedef struct _KMTO_PERCPU_RING {
    volatile LONG  Head;              // next slot the producer writes
    volatile LONG  Tail;              // next slot the consumer reads
    ULONG          _Pad0;
    ULONG64        SequenceCounter;   // monotonic; written by producer only
    ULONG64        LostEvents;        // ring-full drops
    ULONG64        EventsWritten;     // total writes (including overwrites)
    ULONG64        EventsDrained;     // userland-acknowledged reads
    kmto_event_t   Slots[KMTO_RING_SIZE];
} KMTO_PERCPU_RING, *PKMTO_PERCPU_RING;

// =================================================================
// Observer state (singleton)
// =================================================================

typedef struct _KMTO_OBSERVER_STATE {
    PKMTO_PERCPU_RING   PerCpuRings;          // array of g_ProcessorCount rings
    ULONG               ProcessorCount;       // KeQueryActiveProcessorCount

    // Periodic CR4/MSR sampler (single timer + DPC; on fire, the DPC
    // queues per-CPU DPCs via KeInsertQueueDpc with KeSetTargetProcessorDpc).
    KTIMER              SamplerTimer;
    KDPC                SamplerTimerDpc;
    KDPC               *PerCpuSamplerDpc;     // one per CPU
    ULONG               SamplingIntervalMs;
    BOOLEAN             SamplerActive;

    // BugCheck callback record + scratch buffer the callback writes
    // into. Must be in NonPagedPool and remain valid until
    // KeDeregisterBugCheckCallback is called at driver unload.
    KBUGCHECK_CALLBACK_RECORD  BugCheckRecord;
    UCHAR                      BugCheckScratch[64];
    BOOLEAN                    BugCheckRegistered;

    // Performance-counter frequency, cached at init (KeQueryPerformanceCounter
    // returns the frequency on first call but querying once is cheaper).
    LARGE_INTEGER       QpcFrequency;
    LARGE_INTEGER       DriverStartQpc;

    // Aggregate stats, sampled cheaply from the per-CPU rings.
    kmto_stats_t        Stats;
} KMTO_OBSERVER_STATE, *PKMTO_OBSERVER_STATE;

#define KMTO_MEM_TAG  'OTMK'   // displays as 'KMTO' in tools

// =================================================================
// Ring API (event_ring.c)
// =================================================================

NTSTATUS KmtoRingInit(_Inout_ PKMTO_OBSERVER_STATE State);
VOID     KmtoRingCleanup(_Inout_ PKMTO_OBSERVER_STATE State);
VOID     KmtoRingReset(_Inout_ PKMTO_OBSERVER_STATE State);

// Producer: called from a DPC running on the target CPU. Never blocks.
VOID     KmtoRingWrite(
            _Inout_ PKMTO_OBSERVER_STATE State,
            _In_    ULONG                Cpu,
            _In_    ULONG                EventType,
            _In_reads_(5) const ULONG64 *Data);

// Consumer: drain up to MaxEvents from CPU's ring into Out. Returns
// the number actually drained and snapshots the lost-event counter.
ULONG    KmtoRingDrain(
            _Inout_ PKMTO_OBSERVER_STATE State,
            _In_    ULONG                Cpu,
            _In_    ULONG                MaxEvents,
            _Out_writes_(MaxEvents) kmto_event_t *Out,
            _Out_   PULONG64             OutLostEvents);

// =================================================================
// CR4 / MSR observer API (cr4_observer.c)
// =================================================================

NTSTATUS KmtoObserverInit(_Inout_ PKMTO_OBSERVER_STATE State);
VOID     KmtoObserverCleanup(_Inout_ PKMTO_OBSERVER_STATE State);

// Snapshot — synchronous, runs in the IOCTL caller's thread.
VOID     KmtoReadCr4Snapshot(_Out_ kmto_cr4_snapshot_t *Out);

// Configure — start / stop the periodic sampler and the BugCheck
// callback. Returns the mask actually in effect.
NTSTATUS KmtoObserverConfigure(
            _Inout_ PKMTO_OBSERVER_STATE State,
            _In_    ULONG                EnableMask,
            _In_    ULONG                IntervalMs,
            _Out_   PULONG               OutActiveMask,
            _Out_   PULONG               OutIntervalMs);

// =================================================================
// Stats helpers
// =================================================================

VOID KmtoStatsSnapshot(
        _In_  PKMTO_OBSERVER_STATE State,
        _Out_ kmto_stats_t        *Out);

// =================================================================
// Global state pointer — defined in kmto_driver.c, used by every
// other source file in driver/.
// =================================================================

extern KMTO_OBSERVER_STATE g_KmtoState;

#endif /* KMTO_KERNEL_STATE_H */
