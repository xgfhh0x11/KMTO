# KMTO — Kernel Mitigation Telemetry Observatory

**KMTO** is a cross-platform observation framework for hardware-assisted
kernel security mitigations. It detects which mitigations are present
on a running system, exercises controlled scenarios that should engage
each mitigation, and produces structured telemetry describing the
fault-classification, control-flow, and memory-access events that
result.

The framework is observation-only. It does not contain exploitation
primitives, privilege-escalation paths, or control-flow-hijack code.
Its purpose is to give a defender or a kernel engineer a reproducible
way to answer the question *"are the mitigations I configured actually
behaving as designed on this build, on this CPU?"*

## Mitigation surfaces observed

| Mitigation | Architecture | Observation                                                            |
|------------|--------------|------------------------------------------------------------------------|
| SMEP       | x86_64       | CR4[20] state; classification of supervisor execute-from-user faults  |
| SMAP       | x86_64       | CR4[21] state; STAC/CLAC bracketed access windows; data-side faults    |
| PAC        | ARM64        | Pointer-authentication success/failure rates per key domain (A / B)    |
| CFG / KCFG | Windows      | Indirect-call validation in user / kernel control flow                 |
| KASLR      | x86_64       | Image base randomization presence                                      |
| KPTI       | x86_64       | Kernel page-table isolation presence                                   |
| VBS        | Windows      | Virtualization-based security presence                                 |
| HyperGuard | Windows      | Hypervisor-enforced kernel-integrity presence                          |

## Capabilities

- **Mitigation detector** — Identifies which mitigations the running
  CPU and kernel support and enable.
- **Telemetry system** — Records control-flow events, memory access
  attempts, fault classifications, PAC authentication outcomes, and
  STAC/CLAC transient-window durations. Output is line-oriented text
  plus structured JSON.
- **Test harness** — Runs scripted scenarios that should engage each
  mitigation; outcomes are deterministic under a fixed configuration.
- **Configuration matrix** — Sweeps the 2³ combinations of SMEP, SMAP,
  and PAC and compares observed fault counts across them.
- **Reporting** — Generates JSON, Markdown, plain-text, and Graphviz
  DOT outputs suitable for inclusion in mitigation-assurance reports.
- **Optional Windows driver + CLI** — A KMDF-style driver
  (`kmto_driver.sys`) and a console front-end (`kmto_cli.exe`)
  demonstrate the same telemetry flow with a real kernel handshake.

## Build

### Makefile (Linux / mingw on Windows)

```bash
make
```

To build the Windows CLI alongside:

```powershell
set OS=Windows_NT
make
```

### CMake (cross-platform)

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

The `kmto_cli` target is produced only on Windows; its binary is
written to `build/bin/kmto_cli.exe`.

## Windows kernel driver (`kmto_driver.sys`)

- Driver sources live in `driver/` and use the KMDF-style entry point
  in `kmto_driver.c`.
- Build via Visual Studio + WDK:

```powershell
cd driver
"C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.com" `
    kmto_driver.vcxproj /Build "Release|x64"
```

Output: `driver\bin\Release\kmto_driver.sys`. The project uses the
`WindowsKernelModeDriver10.0` toolset and the `ntstrsafe.lib`
dependency.

> Driver loading on production Windows requires either test-signing
> mode or a kernel-driver signature. KMTO is intended to run in
> controlled lab environments.

## KMTO CLI

The CLI (`kmto_cli.exe`) opens a handshake with the kernel driver via
`\\.\KMTO` and presents a menu of telemetry actions:

```
  [1] Baseline mitigation telemetry sweep (SMEP/SMAP)
  [2] PAC verification flow observation
  [3] Telemetry stream / debug log
  [4] Configuration matrix comparison
  [5] Session log & driver handshake details
  [6] Exit
```

If the driver is not loaded, the CLI falls back to simulation mode and
surfaces the reason in the status panel.

## Usage

### Default — run all observation tests

```bash
./bin/kmto -t all -o output
```

### Run a single test scenario

```bash
./bin/kmto -t baseline-smep -o output
```

### Run the configuration matrix

```bash
./bin/kmto -m -o matrix_output
```

### CLI options

| Flag                  | Description                                    |
|-----------------------|------------------------------------------------|
| `-c, --config FILE`   | Configuration file path                        |
| `-o, --output DIR`    | Output directory for reports                   |
| `-l, --log FILE`      | Telemetry log file                             |
| `-t, --test TYPE`     | Run a specific test (see below)                |
| `-m, --matrix`        | Sweep all SMEP/SMAP/PAC combinations           |
| `-h, --help`          | Show help                                      |

### Test types

| Test                | Surface observed                                          |
|---------------------|-----------------------------------------------------------|
| `baseline-boundary` | User → kernel boundary; reference path with no faults     |
| `baseline-smep`     | SMEP fault classification under supervisor execute-from-user |
| `baseline-smap`     | SMAP fault classification under supervisor read-from-user |
| `baseline-pac`      | PAC verification success/failure on signed pointers       |
| `pointer-semantics` | Return-address vs function-pointer key domains            |
| `data-code-sep`     | NX / W^X enforcement at supervisor level                  |
| `transient-windows` | STAC/CLAC bracketed access duration measurement           |
| `interaction`       | Multi-mitigation interaction (which guard fires first)    |
| `all`               | Run all of the above                                      |

## Architecture

```
                       Main entry point
                          (main.c)
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
       Config manager   Mitigation       Telemetry
                          detector         system
              │               │               │
              └───────┬───────┴───────────────┘
                      │
                      ▼
                Test harness
                      │
                      ▼
                   Reporting
```

- **Mitigation detector** — Reads CPUID extended-features leaf for
  SMEP/SMAP support, queries HWCAP for ARM64 PAC, and consults
  CR4 / system queries where privileged access is available. Distinguishes
  *supported* from *enabled*.
- **Telemetry system** — Records events with nanosecond timestamps,
  classifies faults, and accumulates per-mitigation counters.
- **Test harness** — Runs observation scenarios; each scenario uses
  only the public, sanctioned kernel-interaction surfaces.
- **Config manager** — Normalizes mitigation configurations and
  generates the comparison matrix.
- **Reporting** — Produces audit-ready outputs in multiple formats.

## File layout

```
KMTO/
├── include/
│   ├── mitigation_types.h     # shared types (faults, domains, configs)
│   ├── mitigation_detector.h
│   ├── telemetry.h
│   ├── test_harness.h
│   ├── config_manager.h
│   ├── reporting.h
│   ├── kmto_protocol.h        # driver/CLI handshake protocol
│   └── kmto_kernel_state.h    # kernel-state snapshot shared with the driver
├── src/
│   ├── main.c                 # CLI entry point for the telemetry tool
│   ├── mitigation_detector.c
│   ├── telemetry.c
│   ├── test_harness.c
│   ├── config_manager.c
│   ├── reporting.c
│   └── kmto_cli.c             # Windows-only handshake console
├── driver/
│   ├── kmto_driver.c          # KMDF-style driver for the handshake demo
│   ├── cr4_observer.c         # CR4 mitigation-bit observation
│   └── event_ring.c           # lock-free event ring for driver telemetry
├── tests/                     # pytest: structure + output-validation
├── .github/workflows/ci.yml   # Linux (gcc/clang) + Windows build/test
├── CMakeLists.txt
├── Makefile
├── config.example
└── README.md
```

## Reports

Each run produces, under the chosen output directory:

| File                          | Format     | Content                                          |
|-------------------------------|------------|--------------------------------------------------|
| `interaction_summary.txt`     | text       | Mitigation configuration + observed fault counts |
| `summary.md`                  | Markdown   | Human-readable summary of the same data          |
| `results.json`                | JSON       | Machine-parseable run record                     |
| `test_outcomes.txt`           | text       | Per-test outcome rows                            |
| `control_flow.dot`            | Graphviz   | Control-flow observation diagram                 |
| `memory_access_matrix.txt`    | text       | Source/target domain × access-type matrix        |

## Platform support

- **Linux** — x86_64 (SMEP, SMAP), ARM64 (PAC) — primary platform.
- **Windows** — x86_64 (SMEP, SMAP, CFG, KASLR, KPTI, VBS, HyperGuard
  detection) — full platform including the driver + CLI handshake demo.

## Threat model and scope

KMTO answers the *defender's* question: *given a configured set of
hardware-assisted kernel mitigations, are they enforcing what they
claim to enforce on this system?*

It does **not**:

- Attempt to bypass any mitigation.
- Carry exploit payloads, weaponized PoCs, or post-exploitation code.
- Modify kernel state outside the documented handshake IOCTL.

It **does**:

- Observe the boundary mechanisms and report fault classifications.
- Time transient access windows (STAC/CLAC duration).
- Compare observed behavior across configurations to validate that
  toggling a mitigation actually changes enforcement.

The framework is suitable for: kernel-engineering regression testing,
mitigation-assurance reviews, compliance evidence collection, and
classroom demonstration of how hardware-assisted kernel mitigations
behave under controlled scenarios.

## Limitations

- User-mode CR4 reads are not authoritative; the detector falls back to
  CPU-feature reporting when CR4 is unreachable.
- Simulation-mode tests model the expected fault behavior; real
  enforcement evidence requires the kernel driver to be loaded.
- PAC observation on ARM64 requires either a kernel module or a
  HWCAP-exposed implementation; pure user-mode PAC introspection is
  limited.
- The telemetry itself adds measurement overhead; high-frequency event
  paths should be sampled rather than logged exhaustively.

## License

MIT (see `LICENSE`). Defensive-use statement included in the license
file.

## Contributing

See `CONTRIBUTING.md`. New observation surfaces (CET shadow stacks,
IBT, KCFI, IOMMU isolation) are welcome contributions; offensive
primitives are out of scope.
