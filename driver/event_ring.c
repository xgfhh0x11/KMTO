//
// KMTO — per-CPU event ring buffer.
//
// Design: one ring per logical CPU, NonPagedPool-backed, accessed
// lockless single-producer / multi-consumer:
//
//   Producer  — KmtoRingWrite() called from a DPC affinitized to
//               the target CPU. Writes are serialized within a CPU
//               by virtue of DPC dispatch ordering.
//   Consumer  — KmtoRingDrain() called from the IOCTL dispatcher
//               (PASSIVE_LEVEL, user-mode caller thread). Reads use
//               a Head snapshot; ring overruns are reported via
//               LostEvents instead of returning stale slots.
//
// Defensive constraints honoured:
//   - No allocations after init (preallocated NonPagedPool).
//   - No spinlocks held across function boundaries.
//   - The producer never blocks; overflow = increment LostEvents.
//   - Read side does not modify Head; only the producer writes Head.
//

#include "../include/kmto_kernel_state.h"

NTSTATUS
KmtoRingInit(_Inout_ PKMTO_OBSERVER_STATE State)
{
    ULONG i;
    SIZE_T allocSize;

    if (!State) {
        return STATUS_INVALID_PARAMETER;
    }

    State->ProcessorCount = KeQueryActiveProcessorCount(NULL);
    if (State->ProcessorCount == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    allocSize = (SIZE_T)State->ProcessorCount * sizeof(KMTO_PERCPU_RING);
    State->PerCpuRings = (PKMTO_PERCPU_RING)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, KMTO_MEM_TAG);
    if (!State->PerCpuRings) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(State->PerCpuRings, allocSize);

    KeQueryPerformanceCounter(&State->QpcFrequency);
    State->DriverStartQpc = KeQueryPerformanceCounter(NULL);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KMTO] Ring init: %lu CPUs x %lu slots = %llu bytes\n",
               State->ProcessorCount, (ULONG)KMTO_RING_SIZE,
               (ULONG64)allocSize);

    for (i = 0; i < State->ProcessorCount; i++) {
        // Head/Tail/SequenceCounter all zero from RtlZeroMemory.
        // No additional per-ring init required.
        UNREFERENCED_PARAMETER(i);
    }

    return STATUS_SUCCESS;
}

VOID
KmtoRingCleanup(_Inout_ PKMTO_OBSERVER_STATE State)
{
    if (!State) {
        return;
    }
    if (State->PerCpuRings) {
        ExFreePoolWithTag(State->PerCpuRings, KMTO_MEM_TAG);
        State->PerCpuRings = NULL;
    }
    State->ProcessorCount = 0;
}

VOID
KmtoRingReset(_Inout_ PKMTO_OBSERVER_STATE State)
{
    ULONG i;

    if (!State || !State->PerCpuRings) {
        return;
    }

    // Reset is allowed at PASSIVE_LEVEL (called from IOCTL_RESET).
    // We don't stop the producer first — instead, we write zeros and
    // accept that any in-flight DPC may write past us; the next
    // drain will see whatever the producer wrote post-reset.
    for (i = 0; i < State->ProcessorCount; i++) {
        PKMTO_PERCPU_RING ring = &State->PerCpuRings[i];
        InterlockedExchange(&ring->Head, 0);
        InterlockedExchange(&ring->Tail, 0);
        ring->SequenceCounter = 0;
        ring->LostEvents = 0;
        ring->EventsWritten = 0;
        ring->EventsDrained = 0;
        RtlZeroMemory(ring->Slots, sizeof(ring->Slots));
    }
}

VOID
KmtoRingWrite(
    _Inout_ PKMTO_OBSERVER_STATE State,
    _In_    ULONG                Cpu,
    _In_    ULONG                EventType,
    _In_reads_(5) const ULONG64 *Data)
{
    PKMTO_PERCPU_RING ring;
    LONG              head, nextHead, tail;
    kmto_event_t     *slot;
    LARGE_INTEGER     now;

    if (!State || !State->PerCpuRings || Cpu >= State->ProcessorCount) {
        return;
    }

    ring = &State->PerCpuRings[Cpu];

    head     = ring->Head;
    nextHead = (head + 1) & KMTO_RING_MASK;
    tail     = ring->Tail;

    if (nextHead == tail) {
        // Ring full — overwrite is not allowed (the reader's tail
        // would be invalidated). Drop the event and count it.
        InterlockedIncrement64((volatile LONG64 *)&ring->LostEvents);
        return;
    }

    slot = &ring->Slots[head];
    now  = KeQueryPerformanceCounter(NULL);

    slot->timestamp_qpc = (ULONG64)now.QuadPart;
    slot->cpu           = Cpu;
    slot->event_type    = EventType;
    slot->sequence_id   = ++ring->SequenceCounter;
    if (Data) {
        slot->data[0] = Data[0];
        slot->data[1] = Data[1];
        slot->data[2] = Data[2];
        slot->data[3] = Data[3];
        slot->data[4] = Data[4];
    } else {
        RtlZeroMemory(slot->data, sizeof(slot->data));
    }

    // Publish: bump head only after the slot is fully written. The
    // reader sees the new head after this and the slot is consistent.
    InterlockedExchange(&ring->Head, nextHead);
    ring->EventsWritten++;
}

ULONG
KmtoRingDrain(
    _Inout_ PKMTO_OBSERVER_STATE State,
    _In_    ULONG                Cpu,
    _In_    ULONG                MaxEvents,
    _Out_writes_(MaxEvents) kmto_event_t *Out,
    _Out_   PULONG64             OutLostEvents)
{
    PKMTO_PERCPU_RING ring;
    LONG  head, tail;
    ULONG drained;

    if (OutLostEvents) {
        *OutLostEvents = 0;
    }

    if (!State || !State->PerCpuRings || Cpu >= State->ProcessorCount ||
        !Out || MaxEvents == 0) {
        return 0;
    }

    ring = &State->PerCpuRings[Cpu];

    head = ring->Head;
    tail = ring->Tail;

    drained = 0;
    while (tail != head && drained < MaxEvents) {
        Out[drained] = ring->Slots[tail];
        tail = (tail + 1) & KMTO_RING_MASK;
        drained++;
    }

    if (drained > 0) {
        InterlockedExchange(&ring->Tail, tail);
        ring->EventsDrained += drained;
    }
    if (OutLostEvents) {
        *OutLostEvents = ring->LostEvents;
    }

    return drained;
}
