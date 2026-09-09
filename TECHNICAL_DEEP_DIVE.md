---
title: "KMTO — Kernel Mitigation Telemetry Observatory"
subtitle: "A defensive observation framework for hardware-assisted kernel mitigations"
author: "Tyler"
date: "2026-09-09"
keywords: [kernel security, SMEP, SMAP, PAC, CFG, KASLR, KPTI, telemetry, mitigation assurance, defensive engineering]
---

# KMTO — Kernel Mitigation Telemetry Observatory
## A Defensive Observation Framework for Hardware-Assisted Kernel Mitigations

---

## Author's Note

This project began as a self-imposed question. Modern kernels ship
with a dense stack of hardware-assisted mitigations — SMEP, SMAP,
PAC, CFG, KASLR, KPTI, VBS, HyperGuard — and each is documented
individually by its vendor. What is *not* documented is the
joint behavior: which mitigation fires first when an interaction
spans two of them, how long a STAC/CLAC bracket actually stays open
under contention, whether the PAC failure rate on a given build
reflects the policy the operator believes is in force. These are
defender questions, and they are easier to ask than to answer.

KMTO is the answer I built. It does not break any mitigation; it
observes them. The shape of the work is intentionally inverted from
the more common offensive pattern: instead of asking *"how do I get
past this guard?"*, KMTO asks *"is this guard doing what its data
sheet says it does, on this build, on this CPU?"*. The defensive
posture is not a sticker on the project; it is the design.

---

## Abstract

This document describes KMTO (Kernel Mitigation Telemetry
Observatory), a cross-platform C framework for observing
hardware-assisted kernel security mitigations. KMTO detects the
presence and enablement of SMEP, SMAP, PAC, CFG/KCFG, KASLR, KPTI,
VBS, and HyperGuard on a running system; exercises controlled
scenarios that should engage each mitigation; and produces
structured telemetry classifying every fault, control-flow event,
and memory-access attempt that results. A separate, optional Windows
KMDF-style driver and console front-end demonstrate a real kernel
handshake (CR4/MSR snapshot, event-ring drain, stats) over their own
IOCTL protocol; this driver/CLI pair is a distinct code path and is
not wired into the `kmto` scenario runner's `-t`/`-m` telemetry
described above. The framework is observation-only: it
contains no exploitation primitives, no privilege-escalation paths,
and no control-flow-hijack code. Its contribution is the
*systematic, reproducible, machine-parseable evidence* a defender
needs to assert that a configured mitigation stack is, in fact,
enforcing what it claims to enforce.

**Keywords:** kernel security, mitigation assurance, defensive
engineering, SMEP, SMAP, PAC, CFG, KASLR, KPTI, telemetry.

---

## 1. Background

### 1.1 The defender's problem

Modern operating systems advertise a long list of kernel
mitigations: Supervisor Mode Execution Prevention (SMEP),
Supervisor Mode Access Prevention (SMAP), Pointer Authentication
(PAC), Control Flow Guard (CFG), Kernel Address Space Layout
Randomization (KASLR), Kernel Page Table Isolation (KPTI), and on
Windows the Virtualization-Based Security (VBS) family including
HyperGuard. Each of these is, on its own, a well-understood control:
SMEP prevents the supervisor from executing user-space code, SMAP
prevents the supervisor from dereferencing user pointers outside
sanctioned windows, and so on.

What is harder to assess is the *operational* state. Was SMEP
actually enabled by the bootloader on this image? Is the kernel's
STAC/CLAC bracket short enough that no spurious user access slips
through? Does the PAC-failure event rate match the policy you
configured? Does the operating system honor its own mitigation
matrix uniformly across all worker threads?

Vendor documentation answers the *design* question. KMTO answers
the *did-it-do-what-it-said* question — for a given build, on a
given CPU, under a given workload — by emitting structured
telemetry that a defender, an auditor, or a regression test can
consume.

### 1.2 Why observation, not exploitation

There is a tradition in low-level security of demonstrating a
mitigation's value by demonstrating a bypass: the bypass exists,
therefore the mitigation matters. That posture is useful in
research, but it is the wrong shape for *operational assurance*. An
operator does not need to know that a determined attacker can defeat
a mitigation; the operator needs to know that the mitigation is
*on*, *behaving*, and *firing* against the failure modes it was
configured to catch. The instrument for that question is
observation, not exploitation. KMTO is built as that instrument.

---

## 2. Threat Model and Scope

### 2.1 Defender's question

KMTO answers a single, narrow question, in three forms:

1. *Presence.* Which mitigations are supported by the hardware and
   the kernel build on this system?
2. *Enablement.* Of those, which are actually engaged at runtime?
3. *Enforcement.* When a scenario crosses a mitigation's boundary,
   does the mitigation fire — and with what fault classification,
   timing, and call-site signature?

The answers feed into mitigation-assurance reviews, kernel
regression suites, compliance evidence collection, and classroom
demonstration of how the mitigation stack composes.

### 2.2 Out of scope

KMTO is **not**:

- An exploit framework or a vulnerability scanner.
- A privilege-escalation tool.
- A control-flow-hijack experiment harness.
- A bypass research vehicle.

It carries no weaponized payloads. The test scenarios use only the
documented, sanctioned kernel-interaction surfaces: copy-from-user,
the public IOCTL handshake, and CPU feature introspection via
CPUID/HWCAP. Where a scenario would otherwise need to trigger a
fault to observe it, KMTO models the fault path symbolically and
records the *expected* outcome under the active configuration — it
does not provoke the fault.

### 2.3 Defensive use cases

The framework is intended for:

- **Kernel-engineering regression**: a CI job that runs KMTO across
  a kernel branch's commits to detect unintended changes in
  mitigation enforcement.
- **Mitigation-assurance audit**: producing evidence that a
  configured stack (e.g., SMEP+SMAP+CFG) is engaged and behaving on
  a delivered image.
- **Compliance reporting**: machine-parseable JSON output for
  ingestion into a compliance pipeline.
- **Classroom and lab teaching**: a reproducible, observable way to
  show students *why* and *how* kernel mitigations behave.

---

## 3. Architecture

```
                       Main entry point
                          (src/main.c)
                               │
                Orchestrates initialization,
                test selection, reporting
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
  Config manager        Mitigation             Telemetry
  (src/config_           detector              (src/telemetry.c)
   manager.c)          (src/mitigation_
                        detector.c)
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │
                               ▼
                         Test harness
                       (src/test_harness.c)
                               │
                               ▼
                          Reporting
                       (src/reporting.c)
                               │
                               ▼
                     output/ — JSON, MD, DOT, TXT
```

### 3.1 Module responsibilities

| Module                    | Responsibility                                                                    | Failure mode it prevents                                  |
|---------------------------|------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `mitigation_detector`     | CPUID/HWCAP/CR4 introspection; distinguishes *supported* from *enabled*.           | False positives from feature-supported-but-disabled.      |
| `telemetry`               | Event capture (control-flow, memory access, fault, PAC, timing); statistics.       | Lost events under IRQ/exception reentrancy.               |
| `test_harness`            | Runs scripted observation scenarios; produces deterministic outcomes per config.   | Race conditions, pinning discipline violations.           |
| `config_manager`          | Normalizes mitigation configurations; generates the comparison matrix.             | Inconsistent runtime vs compile-time mitigation flags.    |
| `reporting`               | Renders outputs in JSON, Markdown, text, Graphviz DOT.                             | Output drift between runs at fixed configuration.         |

### 3.2 Data flow

A run proceeds:

1. `detect_mitigations()` reads CPUID leaf 7 (sub-leaf 0) for SMEP
   (EBX bit 7) and SMAP (EBX bit 20) on x86_64; on ARM64 it reads
   HWCAP for PAC presence. CR4 is read if the build has privileged
   access; otherwise the detector falls back to feature support and
   marks the configuration as "presumed enabled if supported."
2. `telemetry_init()` opens a log file and initializes the
   nanosecond timestamp baseline.
3. `test_harness_run()` executes the chosen scenarios; each
   scenario calls into `telemetry_log_*` to record its observations.
4. `report_generate_*` renders the accumulated state in five output
   formats.

---

## 4. Mitigation Surfaces Observed

### 4.1 SMEP — Supervisor Mode Execution Prevention (x86_64)

| Property             | Detail                                                                          |
|----------------------|---------------------------------------------------------------------------------|
| Control bit          | CR4[20]                                                                         |
| CPUID feature        | Leaf 7, sub-leaf 0, EBX bit 7                                                   |
| Failure mode         | Supervisor attempts to execute a user-space virtual address                     |
| Fault classification | `FAULT_SMEP_VIOLATION`                                                          |
| Observation surface  | The fault path — KMTO logs the expected fault under a modeled scenario.         |

When CR4[20] is set, the CPU raises a page fault if supervisor-mode
execution reaches a page whose user/supervisor flag indicates user
ownership. KMTO does not provoke the fault. Instead,
`test_smep_violation_observation` records what the *expected*
behavior is under the active configuration: with SMEP enabled, a
modeled execute-from-user attempt is logged as
`FAULT_SMEP_VIOLATION` at a user-space address; with SMEP disabled,
the same modeled attempt is logged as `FAULT_NONE`. The contrast
between the two runs is the evidence.

### 4.2 SMAP — Supervisor Mode Access Prevention (x86_64)

| Property             | Detail                                                                          |
|----------------------|---------------------------------------------------------------------------------|
| Control bit          | CR4[21]                                                                         |
| CPUID feature        | Leaf 7, sub-leaf 0, EBX bit 20                                                  |
| Transient gates      | `STAC` opens the window; `CLAC` closes it.                                      |
| Sanctioned access    | `copy_from_user` / `copy_to_user` and equivalent gateways.                      |
| Fault classification | `FAULT_SMAP_VIOLATION`                                                          |

SMAP is the data-side analogue of SMEP: when CR4[21] is set, the
supervisor cannot read or write user-space memory outside a STAC/CLAC
bracket. The interesting observation surface is the *duration* of the
bracket: a long-open STAC window broadens the population of in-flight
supervisor memory accesses and is a useful proxy for code-path
inefficiency. KMTO measures the STAC/CLAC duration with
nanosecond-resolution timestamps and reports the distribution.

### 4.3 PAC — Pointer Authentication (ARM64)

| Property             | Detail                                                                          |
|----------------------|---------------------------------------------------------------------------------|
| Introduced in        | ARMv8.3-A                                                                       |
| Key domains          | A (instruction pointers), B (data pointers); each with its own secret key.      |
| Fault classification | `FAULT_PAC_AUTH_FAILURE`                                                        |
| Detection            | HWCAP `paca` flag; ID register `ID_AA64ISAR1_EL1` (kernel-mode).                |

PAC signs a pointer at the moment it is constructed and verifies the
signature when it is dereferenced; a manipulated pointer fails
verification and raises an exception. The defender-relevant
question is the *failure rate*: a healthy build has near-zero
PAC failures under normal workload; a non-zero rate is a signal
that something is producing unsigned or wrongly-signed pointers.
KMTO records signed-pointer events with their key domain
(`PAC_KEY_A` / `PAC_KEY_B`) and the verification outcome.

### 4.4 CFG / KCFG — Control Flow Guard

Indirect-call validation in user (CFG) and kernel (KCFG) control
flow. KMTO records the presence of CFG-protected callsites in the
binary it is observing and tracks indirect-call success/failure
counts. The Windows-side detection uses image-load characteristics
and the documented `GetProcessMitigationPolicy` API.

### 4.5 KASLR and KPTI

KASLR shifts the kernel image base by a per-boot offset; KPTI
isolates kernel and user page tables so that a Meltdown-class
side-channel cannot leak kernel data. KMTO does not attempt to
defeat either. It records *presence* — whether the kernel base
appears randomized, and whether KPTI signatures are present — so
that a compliance run can assert "this image has KASLR and KPTI
engaged."

### 4.6 VBS and HyperGuard (Windows)

Virtualization-Based Security uses Hyper-V to host a Secure Kernel
that enforces kernel-integrity properties from outside the
attackable kernel itself. HyperGuard runs in that Secure Kernel and
periodically validates critical kernel structures. KMTO records
presence via the documented Windows mitigation-policy APIs; full
behavioral observation of HyperGuard requires admin privileges and
is not available from a user-mode probe.

---

## 5. Telemetry Design

### 5.1 Event types

| Event              | Recorded fields                                                                                       |
|--------------------|--------------------------------------------------------------------------------------------------------|
| Control flow       | `from_addr`, `to_addr`, `pac_verified` (bool)                                                          |
| Memory access      | `source_domain`, `target_domain`, `access_type`, `address`, `success`                                  |
| Fault              | `fault_type`, `fault_address`, `source_domain`, `access_type`                                          |
| PAC authentication | `pointer`, `key_domain`, `success`, `original_pointer`                                                 |
| Timing             | `event_name`, `duration_ns`                                                                            |

Each event also carries a nanosecond timestamp. Faults are
classified into a closed enumeration (`fault_type_t`) so that
downstream consumers can pivot on a stable key.

### 5.2 Statistics

The cumulative `telemetry_stats_t` carries the eight scalars the
reporting layer consumes:

```c
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
```

The PAC success counter is deliberately tracked alongside the
failure counter: in mitigation assurance, the *ratio* and the
*absolute success volume* both matter — a build that authenticates
zero pointers is a build whose PAC paths are not being exercised.

### 5.3 Timestamp precision

Timestamp acquisition uses `QueryPerformanceCounter` on Windows and
`clock_gettime(CLOCK_MONOTONIC)` on Linux. Both are monotonic and
unaffected by wall-clock adjustments. Resolution is nanoseconds
nominally; in practice the underlying timer's stability bounds the
useful precision near a few hundred nanoseconds on most hosts. STAC
duration measurements are reported at this granularity.

### 5.4 Log format

Telemetry is written as line-oriented text suitable for
`grep`-style triage:

```
[CONTROL_FLOW] 0xffff800011111111 -> 0xffff800012345678, PAC: VERIFIED
[MEMORY_ACCESS] KERNEL -> USER, READ, 0x00007fff00001000, BLOCKED
[FAULT] SMEP_VIOLATION, 0x00007fff00002000, Domain: 1, Access: 2
[PAC_AUTH] Pointer: 0xffff8000abcd1234, Original: 0xffff8000abcd0000, Key: A-KEY, SUCCESS
[TIMING] stac_clac_bracket: 218 ns
```

The same content is also emitted as JSON for machine consumers
(`results.json`).

---

## 6. Test Scenarios

The harness runs the following scenarios. Each is deterministic
under a fixed mitigation configuration; running the same scenario
twice on the same configuration produces the same outcome.

| Scenario                        | Surface observed                                                          |
|---------------------------------|---------------------------------------------------------------------------|
| `baseline-boundary`             | Reference: user → kernel boundary with no expected faults.                |
| `baseline-smep`                 | Models supervisor execute-from-user; expects `FAULT_SMEP_VIOLATION` if SMEP=on.|
| `baseline-smap`                 | Models supervisor read-from-user outside STAC; expects `FAULT_SMAP_VIOLATION`. |
| `baseline-pac`                  | Models a signed-pointer dereference; verifies PAC success path.           |
| `pointer-semantics`             | Compares A-key (instruction) vs B-key (data) domains on signed pointers.  |
| `data-code-sep`                 | Models execute-from-data; expects SMEP/NX-class fault if applicable.      |
| `transient-windows`             | Models a `copy_from_user` bracketed by STAC/CLAC; measures duration.      |
| `interaction`                   | Multi-mitigation scenario: which guard fires first when several apply.    |

### 6.1 Why the scenarios model rather than provoke

A real fault provocation would either (a) need privileged kernel
context to issue the offending instruction safely, or (b) become an
exploit primitive in user mode. KMTO sidesteps both. Each scenario
*declares* the action it would take and *records* the fault the
configured mitigation stack would produce, citing the bit in CR4 or
the HWCAP flag that determines the outcome. The evidence is the
configuration-dependent variance in the recorded outcomes across
runs — exactly what a defender needs.

### 6.2 The interaction scenario

The interaction scenario is the most informative. It models a
control-flow hijack attempt whose pointer is supervisor-targeting a
user address and whose value is unsigned (no PAC). The expected
fault depends on which mitigations are enabled:

```
SMEP=on,  PAC=off  →  FAULT_SMEP_VIOLATION (fires at supervisor exec attempt)
SMEP=on,  PAC=on   →  FAULT_SMEP_VIOLATION (fires before PAC verification)
SMEP=off, PAC=on   →  FAULT_PAC_AUTH_FAILURE
SMEP=off, PAC=off  →  FAULT_NONE  (the scenario completes — diagnostic)
```

A `FAULT_NONE` outcome here is itself the most important signal: it
asserts that the configuration is in fact unprotected against the
modeled action. Mitigation-assurance dashboards flag any
`FAULT_NONE` from the interaction scenario as a failed expectation.

---

## 7. Configuration Matrix

The configuration matrix sweeps the 2³ on/off combinations of SMEP,
SMAP, and PAC:

```
i  SMEP  SMAP  PAC
─  ────  ────  ───
0  off   off   off
1  on    off   off
2  off   on    off
3  on    on    off
4  off   off   on
5  on    off   on
6  off   on    on
7  on    on    on
```

Each scenario is run against each row; the per-row telemetry
statistics are emitted side by side. The intended use is to verify
that toggling a mitigation actually *changes* observed fault
counts in the expected direction. A row whose counts do not change
between SMEP-on and SMEP-off is a configuration whose
SMEP-protected paths are not being exercised by the scenario, and
is a signal to extend test coverage.

---

## 8. Driver Architecture (v2)

### 8.1 v1 → v2 — the upgrade

The driver initially shipped as a *minimal* surface: one IOCTL
(`KMTO_IOCTL_HANDSHAKE`) that returned a session token, a build
number, and a banner. The argument was "the driver demonstrates
kernel-mode awareness without taking on attack surface"; in
practice this left the kernel side without any substantive
observation function, and the project's interesting work
(CR4/MSR introspection, fault-classification telemetry) lived
entirely in userland modeling.

**v2 adds the missing kernel-side observation pipeline** while
preserving the defensive scope of v1. Specifically:

- a **per-CPU lockless ring buffer** in NonPagedPool that the
  driver uses to publish observation events,
- a **periodic CR4/MSR sampler** built on `KTIMER` + per-CPU
  `KDPC`s that reads `CR4` and a small fixed set of MSRs on
  every CPU and writes a `KMTO_EVT_CR4_SAMPLE` event into the
  ring,
- a **BugCheck callback** registered via
  `KeRegisterBugCheckCallback` that captures `CR4` + QPC at
  bug-check time into a NonPagedPool scratch buffer recoverable
  from a kernel mini-dump,
- a **five-IOCTL surface** (`GET_CR4_SNAPSHOT`, `GET_EVENTS`,
  `GET_STATS`, `RESET`, `CONFIGURE`) wired through the same
  dispatcher as the handshake.

The protocol-version constant moves from `0x00010000` to
`0x00020000`; the driver accepts v1 clients with degraded
capabilities, so old `kmto_cli` binaries continue to work.

### 8.2 Defensive scope — what v2 still does not do

Every addition in v2 was reviewed against the original
"observation-only" scope of v1. The list of things the driver
**still does not do** is identical:

- No `__writecr4`, no `__writemsr`, no privileged register write
  of any kind.
- No SSDT hook, no MajorFunction redirection on other drivers,
  no inline patching.
- No page-table modification; `MmGetPhysicalAddress` is the only
  paging API touched (handshake session-token entropy).
- No exception-handler injection. The `KeBugCheckCallback` is
  a *passive* sink — receives a notification and writes into a
  pre-allocated buffer; never modifies state.
- No DPC injected into other modules' contexts; the per-CPU
  sampler DPCs are owned by KMTO and target their own arrays.
- All IOCTLs use `METHOD_BUFFERED` (no `METHOD_NEITHER` pointer
  trust); buffer sizes are validated before any access.

The substantive work in v2 lives entirely on the
**read-and-publish** side of the kernel/user boundary.

### 8.3 Per-CPU ring buffer (`driver/event_ring.c`)

One ring per logical CPU, NonPagedPool-allocated at
`DriverEntry`. Each ring holds `KMTO_RING_SIZE = 256` slots of
`kmto_event_t` (56 bytes each, ≈ 14 KB per CPU; on a 32-thread
host ≈ 448 KB total). Access pattern:

- **Producer.** A single per-CPU DPC writes to its CPU's ring.
  Because the same CPU dispatches its own DPCs sequentially,
  the producer is by construction single-threaded *per ring*;
  no spinlock is required between samples.
- **Consumer.** The IOCTL handler runs in the caller thread at
  `PASSIVE_LEVEL`. It snapshots `Head`, walks from `Tail` to
  `Head`, and `InterlockedExchange`s `Tail` to acknowledge the
  drain.

```c
typedef struct _KMTO_PERCPU_RING {
    volatile LONG  Head;              /* producer-only writer */
    volatile LONG  Tail;              /* consumer-only writer */
    ULONG          _Pad0;
    ULONG64        SequenceCounter;
    ULONG64        LostEvents;
    ULONG64        EventsWritten;
    ULONG64        EventsDrained;
    kmto_event_t   Slots[KMTO_RING_SIZE];
} KMTO_PERCPU_RING;
```

Two invariants the implementation maintains:

1. **No overwrite on ring-full.** If
   `(Head + 1) & MASK == Tail`, the producer drops the event and
   increments `LostEvents`. The reader's tail is therefore never
   invalidated mid-drain.
2. **Slot is fully written before `Head` advances.** The
   producer writes the entire `kmto_event_t` into
   `Slots[head]` *and then* `InterlockedExchange`s `Head` to
   `(head + 1) & MASK`. The reader sees a consistent slot
   because it only reads `Slots[tail..head)` from the snapshot.

Lost-event detection on the consumer side: the
`sequence_id` field on `kmto_event_t` is monotonic per CPU. A
gap between `sequence_id` values in consecutive drained slots
means the producer dropped events between those points.

### 8.4 CR4 / MSR sampler (`driver/cr4_observer.c`)

A single `KTIMER` fires on a configurable interval (default
`1000 ms`, range `[50, 60000]`). When its DPC runs, it queues
*one targeted DPC per CPU* using `KeInsertQueueDpc` against an
array of pre-`KeSetTargetProcessorDpc`-affinitized DPCs. Each
per-CPU DPC executes at `DISPATCH_LEVEL` on its target CPU and
reads:

| Source             | API                                |
|--------------------|------------------------------------|
| `CR4`              | `__readcr4()`                      |
| `IA32_EFER`        | `__readmsr(0xC0000080)`            |
| `IA32_FEATURE_CTL` | `__readmsr(0x0000003A)`            |
| `IA32_PAT`         | `__readmsr(0x00000277)`            |
| `IA32_FS_BASE`     | `__readmsr(0xC0000100)`            |
| QPC timestamp      | `KeQueryPerformanceCounter`        |

The five MSR indices are architecturally present on any
x86_64 Windows-capable CPU; the sampler does not probe optional
MSRs (no risk of `#GP`).

A reader on the consumer side now sees, for each CPU, a
time-series of CR4 / MSR values. The `[20] SMEP` and `[21] SMAP`
bits in `CR4`, the `[11] NXE` bit in `IA32_EFER`, and the lock
bit in `IA32_FEATURE_CONTROL` are the operationally important
ones; the others enrich the snapshot for cross-reference work.

The on-demand `KMTO_IOCTL_GET_CR4_SNAPSHOT` IOCTL performs the
same read synchronously in the calling thread (after
`KeRaiseIrql(DISPATCH_LEVEL)` to pin to a stable CPU), so a
user-mode caller does not have to wait for the next sampler
tick to get a fresh value.

### 8.5 BugCheck callback

`KeRegisterBugCheckCallback` is the documented way to run a
notification routine when the system bug-checks. The callback
runs at `HIGH_LEVEL` with most APIs unsafe; KMTO's callback
restricts itself to:

```c
static VOID
KmtopBugCheckCallback(_In_ PVOID Buffer, _In_ ULONG Length)
{
    /* layout: magic / qpc / cr4 / cpu / reserved */
    RtlCopyMemory(scratch + 0, "KMTOBC@@", 8);
    *(ULONG64 *)(scratch + 8)  = KeQueryPerformanceCounter(NULL).QuadPart;
    *(ULONG64 *)(scratch + 16) = __readcr4();
    *(ULONG *)(scratch + 24)   = KeGetCurrentProcessorNumber();
}
```

The 64-byte `BugCheckScratch` buffer is allocated in
NonPagedPool at `DriverEntry` and remains valid for the
lifetime of the driver. If a system mini-dump is configured,
the scratch lives inside the dump and gives forensic context:
*the system bug-checked at this QPC tick with this CR4 value*.

The callback is opt-in (`KMTO_CFG_BUGCHECK_CB` bit of
`IOCTL_CONFIGURE.enable_mask`). It does not run by default —
zero observable overhead until userland explicitly turns it on.

### 8.6 IOCTL surface

```c
#define KMTO_IOCTL_HANDSHAKE         CTL_CODE(_, 0x900, METHOD_BUFFERED, _)
#define KMTO_IOCTL_GET_CR4_SNAPSHOT  CTL_CODE(_, 0x901, METHOD_BUFFERED, _)
#define KMTO_IOCTL_GET_EVENTS        CTL_CODE(_, 0x902, METHOD_BUFFERED, _)
#define KMTO_IOCTL_GET_STATS         CTL_CODE(_, 0x903, METHOD_BUFFERED, _)
#define KMTO_IOCTL_RESET             CTL_CODE(_, 0x904, METHOD_BUFFERED, _)
#define KMTO_IOCTL_CONFIGURE         CTL_CODE(_, 0x905, METHOD_BUFFERED, _)
```

| IOCTL                       | Input                                   | Output                                       |
|-----------------------------|------------------------------------------|----------------------------------------------|
| `HANDSHAKE`                 | `kmto_handshake_request_t`              | `kmto_handshake_response_t`                  |
| `GET_CR4_SNAPSHOT`          | —                                       | `kmto_cr4_snapshot_t`                        |
| `GET_EVENTS`                | `kmto_get_events_request_t` (CPU, max)  | `kmto_get_events_response_t` (variable len)  |
| `GET_STATS`                 | —                                       | `kmto_stats_t`                               |
| `RESET`                     | —                                       | —                                            |
| `CONFIGURE`                 | `kmto_configure_request_t`              | `kmto_configure_response_t`                  |

Every input and output is fixed-width `#pragma pack(push, 1)`
defined in `include/kmto_protocol.h`; the wire format is
shared with userspace so there is no chance of struct-layout
drift between the driver and the CLI.

The handshake (still `0x900`) is unchanged on the wire so v1
clients (`KMTO_PROTOCOL_VERSION 0x00010000`) continue to
authenticate, with the new capability bit
`KMTO_CAP_EVENT_RING (1u << 4)` distinguishing v2-aware
clients.

### 8.7 Source layout

| File                                  | Role                                         |
|---------------------------------------|----------------------------------------------|
| `driver/kmto_driver.c`                | `DriverEntry`, IRP dispatch, IOCTL handlers  |
| `driver/event_ring.c`                 | Per-CPU ring buffer (init/drain/write/reset) |
| `driver/cr4_observer.c`               | Sampler, BugCheck callback, configure logic  |
| `include/kmto_protocol.h`             | Wire-format types + IOCTL codes              |
| `include/kmto_kernel_state.h`         | Kernel-only state (rings, sampler, callback record) — never included from userspace |

### 8.8 What v2 enables for the userland tool

`kmto_cli.exe` (in `src/kmto_cli.c`) replaces the v1 menu's
"scenario text" placeholders with real IOCTL calls:

- **CR4 / MSR snapshot** → `IOCTL_GET_CR4_SNAPSHOT`, decoded
  bit-by-bit (SMEP, SMAP, PKE, CET, PCIDE, VMXE, NXE, LMA,
  feature-control lock).
- **Event ring drain** → `IOCTL_GET_EVENTS` (CPU 0, 64 slots
  per drain), printed as `[seq cpu t] EVT  d0 d1`.
- **Telemetry stats** → `IOCTL_GET_STATS` for cumulative
  counters.
- **Configure: enable / disable observers** →
  `IOCTL_CONFIGURE` with `KMTO_CFG_ALL` / `0`.
- **Reset rings** → `IOCTL_RESET`.

The CLI no longer prints theatrical scenario blurbs; every menu
item produces real, structured output from real kernel reads or
returns a clear "driver offline — simulation mode" notice if
the driver is not loaded.

### 8.9 Why the driver carries no privileged surfaces (revisited)

The threat-model boundary preserved by v2:

- **Reads only.** `__readcr4` and `__readmsr` are the only
  privileged-state operations; both are read paths.
- **Owned DPCs.** The sampler DPCs are owned by KMTO, target
  KMTO's own per-CPU array, and never run anywhere else.
- **METHOD_BUFFERED only.** All IOCTLs use buffered I/O so the
  driver never trusts user-mode pointers.
- **Bounded allocations.** All allocations happen in
  `DriverEntry` / `KmtoObserverInit`; nothing on the dispatch
  hot path allocates. NonPagedPool sized predictably from
  `KeQueryActiveProcessorCount`.
- **Opt-in side effects.** Default state at load: no sampler,
  no callback registered. `IOCTL_CONFIGURE` is required to
  start either. The driver is mute until told otherwise.

In v1 the argument was *"the driver carries no privileged
surfaces because it does almost nothing."* In v2 the argument
upgrades to *"the driver carries no privileged surfaces because
each addition was reviewed against the read-and-publish
boundary, and nothing on either side of that boundary was
allowed to cross it."* That is a sharper claim — and the one a
defender's audit would actually want from a kernel observation
tool.

---

## 9. Reporting

A run produces six files under the output directory:

| File                          | Format     | Audience                                       |
|-------------------------------|------------|------------------------------------------------|
| `interaction_summary.txt`     | text       | Human triage; configuration + fault counts     |
| `summary.md`                  | Markdown   | Report inclusion (PR, ticket)                  |
| `results.json`                | JSON       | CI ingest, dashboard, regression diff          |
| `test_outcomes.txt`           | text       | Per-scenario detailed outcome rows             |
| `control_flow.dot`            | Graphviz   | Static reference diagram for documentation (fixed template, not derived from this run) |
| `memory_access_matrix.txt`    | text       | Static reference source/target domain x access-type cross-table (fixed template, not derived from this run) |

The JSON output is the canonical machine-readable artifact:

```json
{
  "config": { "smep": true, "smap": true, "pac": false },
  "stats":  { "total_faults": 5, "smep_violations": 3, "smap_violations": 2,
              "pac_failures": 0 },
  "outcomes": [
    { "fault_type": 1, "fault_address": "0x00007fff00002000", "pac_verified": false },
    ...
  ]
}
```

A downstream consumer can compare two such records and assert
properties of interest — e.g., "this commit did not change
`smep_violations`" — without needing to re-implement KMTO's
classification logic.

---

## 10. Limitations and Honest Caveats

### 10.1 User-mode introspection is incomplete

CR4 is not readable from user mode on most operating systems. The
detector falls back to CPUID feature reporting, which answers the
*supported* question but not the *enabled* question. The published
configuration is annotated to make the fallback explicit.

### 10.2 Modeled scenarios are not provoked scenarios

Where a real exploit would provoke a fault and observe the
hardware's response, KMTO records the expected response under the
detected configuration. This is sufficient for assurance ("the
configuration would produce this outcome") but not for catching
bugs in the hardware or microcode that cause the configured
behavior to disagree with the actual behavior. Real provocation
requires kernel-mode test scaffolding, which is out of scope for
this release.

### 10.3 PAC observation on ARM64 is HWCAP-limited

Pure user-mode PAC introspection is bounded by what HWCAP exposes;
deeper observation requires either a kernel module or a privileged
helper. KMTO's PAC scenarios run on the user-mode surface and are
explicit about that boundary.

### 10.4 Telemetry has its own overhead

Every event capture is a function call, a counter increment, and a
formatted write to a log file. On high-frequency event paths the
overhead is non-trivial. Production use should sample rather than
log exhaustively; the framework provides hooks for that but does
not implement sampling policy.

---

## 11. Future Surfaces

The framework is designed to absorb new mitigation surfaces without
disrupting existing observers. The next surfaces to add, in
priority order:

| Surface                             | Architecture | Why now                                                      |
|-------------------------------------|--------------|--------------------------------------------------------------|
| CET (Shadow Stack + IBT)            | x86_64       | Recent broad availability; assurance demand from enterprise. |
| KCFI (Kernel CFI for Linux)         | x86_64, ARM64 | Mainline Linux; needs observation tooling.                  |
| FineIBT                             | x86_64       | Replaces coarse IBT; new fault classes.                      |
| MTE (Memory Tagging Extension)      | ARM64        | Tag-mismatch faults are a new classification.                |
| IOMMU isolation observation         | x86_64       | DMA-side mitigations adjacent to the SMEP/SMAP story.        |

Each new surface extends `mitigation_type_t`, adds a detector
helper, declares its fault classifications in `fault_type_t`, and
adds at least one scenario to the test harness. The reporting layer
absorbs the new counters via its existing structure.

---

## 12. Conclusion

KMTO is a defender's instrument. Where an offensive framework's
output is a successful chain, KMTO's output is a structured
*account* — a per-mitigation, per-scenario, per-configuration
record of fault classifications, control-flow outcomes, and timing
distributions. The contribution is not novelty in the underlying
mitigations, all of which are vendor-documented; it is the
*systematic, reproducible* nature of the evidence the framework
produces. That evidence is what turns a configured mitigation stack
from a declared posture into an audited one.

The defensive framing is not decorative. The architecture, the
scenario design, the driver's IOCTL surface, the reporting choices,
and the threat-model boundaries all derive from the same starting
question: *what does a defender need to know about whether the
mitigations are doing their job?* KMTO answers that question; it
does not answer any other.

---

## References

[Intel SDM] Intel Corporation. *Intel® 64 and IA-32 Architectures
  Software Developer's Manual.* Volume 3A: System Programming Guide,
  Chapter 4 (Paging) and Chapter 2 (System Architecture Overview),
  CR4 control register definition, 2024.

[ARM ARM] ARM Limited. *Arm® Architecture Reference Manual for
  A-profile architecture (Armv8-A).* Section D5 (Pointer
  Authentication), 2024.

[Microsoft WDK] Microsoft Corporation. *Windows Driver Kit
  Documentation.* KMDF reference; `IoCreateDevice`,
  `IoCreateSymbolicLink`, `IRP_MJ_DEVICE_CONTROL`, 2024.

[Microsoft VBS] Microsoft Corporation. *Virtualization-Based
  Security (VBS) and the Secure Kernel.* Windows Internals
  documentation, 2024.

[Linux/CET] Linux kernel documentation. *Control-flow Enforcement
  Technology (CET) support.* `Documentation/x86/`, kernel sources.

[KASLR] Edge, J. *Kernel address space layout randomization.* LWN.net,
  2013 — initial mainline merge background and design rationale.

[KPTI] Corbet, J. *Page-table isolation and the KAISER patch set.*
  LWN.net, 2017–2018 — KPTI design and rollout.

[STAC/CLAC] Intel Corporation. *Supervisor Mode Access Prevention.*
  Intel SDM Volume 3A, instruction reference for `STAC` and `CLAC`,
  2024.

[Bletsch et al. 2011] Bletsch, T., Jiang, X., Freeh, V., Liang, Z.
  *Jump-Oriented Programming: A New Class of Code-Reuse Attack.*
  ASIACCS, 2011. (Foundational background for understanding what
  PAC and CFG are configured to defeat.)

[Russinovich et al. 2017/2022] Russinovich, M., Solomon, D.,
  Ionescu, A., Yosifovich, P., Cohen, S. *Windows Internals, 7th
  Edition.* Microsoft Press. (Authoritative reference for the
  Windows mitigation stack, including VBS and HyperGuard.)

---

## Appendix A — Build and run

### A.1 Build (Linux / cross-platform)

```bash
make
./bin/kmto -t all -o output
```

### A.2 Build (Windows CLI + driver)

```powershell
mkdir build; cd build
cmake ..
cmake --build .

cd ..\driver
"C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.com" `
    kmto_driver.vcxproj /Build "Release|x64"
```

The CLI runs without the driver — it surfaces the missing
handshake as a status-panel warning and continues in simulation
mode.

### A.3 Run the configuration matrix

```bash
./bin/kmto -m -o matrix_output
ls matrix_output/
# interaction_summary.txt  results.json  summary.md
# test_outcomes.txt        control_flow.dot  memory_access_matrix.txt
```

---

## Appendix B — Relationship to the portfolio

KMTO sits with the defensive engineering side of the portfolio:

- KMTO observes mitigations; the **BFS 2019** writeup
  catalogues what happens when a target's mitigation posture is
  weak. The two are inverses: the offensive writeup explains the
  failure modes KMTO is configured to catch.
- KMTO records *configuration vs observed behavior*; **EXTp**
  records *formal model vs actual trace*. Both are
  oracle-vs-execution comparisons; one uses a configured policy as
  the oracle, the other uses a machine-checked proof.
- KMTO emits structured evidence for a downstream consumer;
  **operation-utku** records structured evidence for a downstream
  decision. The shape is similar — typed events, deterministic
  outcomes, machine-parseable output — and reflects a consistent
  preference for engineering work that is *legible to
  someone else*.

The defensive posture is, in the portfolio's framing, the
operationally honest one: it is the work that an institution
actually needs done.

---

*KMTO is a research instrument, not a product. It is offered as
an example of defensive-engineering practice for assessment and
classroom use.*
