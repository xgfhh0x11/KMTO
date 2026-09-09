# KMTO — Kernel Mitigation Telemetry Observatory — Build & Verification

> *Last updated: 2026-09-09.*

> *This file answers:
> "Is this project buildable, runnable, and behaving as documented?"*

## 1. Build

### 1.1 Primary build path
- **Platform**: Cross-platform C (Linux x86_64 / ARM64 primary; Windows via MinGW or MSVC). Pure user-mode binary; no kernel privileges needed for the main `kmto` executable.
- **Toolchain**: GCC supporting `-std=c11` (GCC 7+ or Clang 6+ recommended). The Makefile invokes `gcc` directly; `CMake >= 3.16` is required for the CMake path. The Windows driver path additionally needs Visual Studio 2022 + WDK 10 (`WindowsKernelModeDriver10.0` toolset).
- **Command** (Linux, Makefile path):
  ```bash
  cd KMTO
  make
  ```
  Cross-platform CMake path:
  ```bash
  cd KMTO
  mkdir build && cd build
  cmake ..
  cmake --build .
  ```
  Windows CLI alongside via Makefile (MinGW):
  ```powershell
  cd KMTO
  $env:OS = "Windows_NT"
  make
  ```
- **Output**:
  - `bin/kmto` (Linux) or `bin/kmto.exe` (Windows MinGW) — main telemetry CLI.
  - `bin/kmto_cli.exe` — Windows-only handshake console (links `user32`, `kernel32`, `ole32`, `advapi32`).
  - `obj/*.o` — intermediate object files.
  - Under CMake: `build/bin/kmto[.exe]` and (on Windows) `build/bin/kmto_cli.exe`.
  - `driver/bin/Release/kmto_driver.sys` — Windows kernel driver (built from `driver/kmto_driver.vcxproj`, committed in this repo).

### 1.2 Alternative build paths
Two parallel build mechanisms ship in the tree:
- **Makefile** (`Makefile`): GNU-make-driven, gates the Windows CLI on `OS=Windows_NT`. Adds `make test` and `make matrix` convenience targets. Linux installs to `/usr/local/bin` via `make install`.
- **CMake** (`CMakeLists.txt`): `cmake_minimum_required(VERSION 3.16)`, C11, builds the `kmto` target everywhere and gates the `kmto_cli` target on `WIN32`. Sets `RUNTIME_OUTPUT_DIRECTORY` to `${CMAKE_BINARY_DIR}/bin`.
- **MSBuild / Visual Studio** (driver only): README documents `devenv.com kmto_driver.vcxproj /Build "Release|x64"`. `driver/kmto_driver.vcxproj` and `driver/kmto_driver.vcxproj.filters` are committed, so this command works from a clean clone.

The two C-level build paths are mutually consistent: both compile the same six source files for `kmto` (`main.c`, `mitigation_detector.c`, `telemetry.c`, `test_harness.c`, `config_manager.c`, `reporting.c`) and the same single source for `kmto_cli` (`src/kmto_cli.c`). The Makefile additionally passes `-Wall -Wextra -O2 -g`; CMake relies on defaults plus `-D__linux__` / `-D_WIN32`.

### 1.3 Dependencies
- **Required**:
  - C11 compiler (`gcc` invoked by default; any C11 compiler works under CMake).
  - GNU `make` for the Makefile path; or `cmake >= 3.16` plus a generator (Ninja, MSBuild, make).
  - libc with `clock_gettime(CLOCK_MONOTONIC)` (Linux) or `QueryPerformanceCounter` (Windows). Both are standard.
  - CPUID intrinsics: `<cpuid.h>` on Linux, `<intrin.h>` on Windows — both ship with the compiler.
  - HWCAP via `<sys/auxv.h>` on Linux (ARM64 PAC detection).
- **Optional**:
  - Visual Studio 2022 Professional + Windows Driver Kit (WDK) 10 — required only for `kmto_driver.sys`. Targets `ntstrsafe.lib`.
  - Test-signing mode enabled on Windows, or a kernel-driver code-signing certificate — required to load the driver in §2.3.
  - Graphviz (`dot`) — only if you want to render `control_flow.dot` to an image; KMTO emits the `.dot` source unconditionally.
  - MinGW-w64 — for the Makefile path on Windows.

## 2. Expected behavior

### 2.1 What this project does
KMTO is an observation-only framework for hardware-assisted kernel security mitigations (SMEP, SMAP, PAC, CFG/KCFG, KASLR, KPTI, VBS, HyperGuard). On launch it (1) introspects the CPU via CPUID leaf 7 / HWCAP / Windows mitigation-policy APIs to determine which mitigations are *supported* and presumed *enabled*; (2) runs scripted scenarios that model what each mitigation should do under the active configuration; (3) records nanosecond-timestamped events (control-flow, memory-access, fault, PAC-auth, timing) through the telemetry subsystem; and (4) emits six artifacts (TXT, MD, JSON, Graphviz DOT) under the chosen output directory. A `-m` matrix mode sweeps the 2³ SMEP/SMAP/PAC on/off combinations and emits per-row outcomes for cross-configuration comparison. An optional Windows kernel-mode component (`kmto_driver.sys`) and console (`kmto_cli.exe`) demonstrate a single `KMTO_IOCTL_HANDSHAKE` exchange over `\\.\KMTO`; the driver carries no privileged surfaces beyond that handshake.

### 2.2 Acceptance criteria
- [ ] `make` (Linux) produces `bin/kmto` with no warnings under `-Wall -Wextra -std=c11 -O2 -g`.
- [ ] `cmake .. && cmake --build .` succeeds on a clean tree and writes `build/bin/kmto[.exe]`.
- [ ] `./bin/kmto -h` prints the eight test-type names listed in README §"Test types".
- [ ] `./bin/kmto -t all -o output` exits 0 and creates **all six** files under `output/`: `interaction_summary.txt`, `summary.md`, `results.json`, `test_outcomes.txt`, `control_flow.dot`, `memory_access_matrix.txt`.
- [ ] `./bin/kmto -m -o matrix_output` exits 0 and emits the same six files, with per-row outcomes for all 2³ SMEP/SMAP/PAC combinations recorded in `results.json`.
- [ ] `results.json` is valid JSON (parses with `python -m json.tool`) and contains top-level keys `config`, `stats`, `outcomes`.
- [ ] Running `-t all` twice on the same machine with the same `config.example` produces *identical* fault classifications (determinism property declared in TECHNICAL_DEEP_DIVE §6).
- [ ] `make clean` removes both `obj/` and `bin/` and leaves the tree in its committed state.
- [ ] On Windows, `kmto_cli.exe` launches and, when no driver is loaded, surfaces the missing handshake as a status-panel warning (fallback to simulation mode per README).

### 2.3 Manual verification
Linux, Makefile path:
```bash
cd KMTO
make
./bin/kmto -h
./bin/kmto -t all -o output
ls output/
python3 -m json.tool output/results.json | head -20
```
Expected console output (representative — exact counters depend on the host's CPUID/HWCAP):
```
=== KMTO — Kernel Mitigation Telemetry Observatory ===

[*] Initializing components...
[*] Detected mitigations:
  SMEP: enabled
  SMAP: enabled
  PAC:  unsupported (x86_64 host)
[*] Telemetry initialized
[*] Test harness initialized
[*] Reporter initialized

[*] Running observation tests...
[*] Running test 1...
[*] Running test 2...
...
[*] Generating reports...
[*] Reports generated in: output

=== Summary ===
Total Control Flow Events: <N>
Total Memory Accesses:     <N>
Total Faults:              <N>
SMEP Violations:           <N>
SMAP Violations:           <N>
PAC Failures:              0
PAC Successes:             0

[+] Observation session complete
```
Expected `ls output/`:
```
control_flow.dot         memory_access_matrix.txt  results.json
interaction_summary.txt  summary.md                test_outcomes.txt
```
Expected representative head of `results.json`:
```json
{
  "config": { "smep": true, "smap": true, "pac": false },
  "stats":  { "total_faults": 5, "smep_violations": 3, ... },
  "outcomes": [ { "fault_type": 1, "fault_address": "0x00007fff00002000", ... } ]
}
```
Matrix mode:
```bash
./bin/kmto -m -o matrix_output
grep -c '"smep"' matrix_output/results.json   # representative: counts per-row config records
```

Windows CLI (without the driver):
```powershell
.\build\bin\kmto_cli.exe
# Status panel should read: "Driver: NOT LOADED — simulation mode"
```

### 2.4 Automated verification
**Present.** A `pytest` suite under `tests/` plus a
GitHub Actions workflow (`.github/workflows/ci.yml`):

- `tests/test_structure.py` — asserts every documented header/source
  exists and that the Makefile's core source list stays in sync with
  `src/` (no source can silently drop out of the build).
- `tests/test_output.py` — runs the built `bin/kmto -t all` and asserts
  it produces output and that every `*.json` it emits parses. This
  upgrades the old `make test` (which only confirmed "did not crash")
  into an output-correctness assertion. Skips cleanly without a build.

CI builds the user-mode tool on Linux with **gcc and clang**, smoke-tests
`-h`, runs the full scenario matrix (`-t all`), runs `pytest`, and
uploads the telemetry output as an artifact; a Windows job builds the
core tool with MSVC and smoke-tests it. Run the tests locally with:

```sh
pip install -r tests/requirements.txt
python -m pytest tests/ -v
```

The Makefile's `make test` / `make matrix` convenience targets remain as
smoke runs.

## 3. Alternatives & improvements

### 3.1 Known fragilities
- **Driver build**: `driver/kmto_driver.vcxproj` and `driver/kmto_driver.vcxproj.filters` are committed alongside `kmto_driver.c`; the documented `devenv.com kmto_driver.vcxproj /Build "Release|x64"` invocation works from a clean clone (not independently re-verified in this environment — no WDK/Visual Studio available here).
- **Detector trusts CPUID over CR4.** `mitigation_detector.c` explicitly comments that CR4 reads are gated out for user-mode safety; the detector falls back to "supported implies presumed enabled." This means the *enablement* dimension is an inference, not an observation, on bare metal where the bootloader could have cleared CR4[20]/CR4[21]. TECHNICAL_DEEP_DIVE §10.1 acknowledges this; reviewers may take it as a limitation.
- **Automated tests exist but are structural/smoke-level only.** `tests/` (pytest) + CI assert structure and that `-t all` produces valid output on every push; a committed expected-output *fixture diff* for full determinism enforcement, and content-level assertions (e.g. that `results.json` keys match the documented shape), are still open follow-ups.
- **`MAX_OUTCOMES = 100` is a hard cap in `main.c`.** The matrix run (`8 configs * 5 tests = 40 outcomes`) fits, and `-t all` produces 8 outcomes, but extending the matrix or adding scenarios without raising this constant will silently truncate.
- **CMake build does not propagate Makefile warning flags.** `-Wall -Wextra` are Makefile-only. A CMake build will compile with default warnings (usually fewer), which can mask issues the Makefile would catch. The CMake path also lacks the explicit Windows libs that the Makefile passes (`-luser32 -lkernel32 -lole32 -ladvapi32`), but it adds `kernel32 user32 advapi32` via `target_link_libraries` — `ole32` is missing on the CMake path, so any CLI code that pulls `ole32` symbols would fail to link there.
- **PAC scenarios produce zero events on x86_64 hosts.** This is by design (HWCAP `paca` is absent), but a reviewer running on Linux x86_64 will see `PAC Failures: 0`, `PAC Successes: 0` and could mistake it for a bug.
- **README and TECHNICAL_DEEP_DIVE drift slightly on file count.** README lists six output files; both documents agree on the names. No conflict observed, but the project has no schema test that asserts the JSON shape.

### 3.2 Fallbacks
- If `make` fails (missing GCC, BSD-make instead of GNU-make), fall back to the CMake path — it is plain CMake with no scripted exotica and works under MSVC, Clang, GCC, and MinGW.
- If CMake fails on Windows because of a missing C compiler, install MinGW-w64 and use the Makefile path with `set OS=Windows_NT` instead.
- If the driver build cannot be reconstructed, the CLI still demonstrates the protocol in simulation mode — point reviewers at `include/kmto_protocol.h` and the handshake structures in `driver/kmto_driver.c`.
- If running on a non-x86_64, non-ARM64 host (e.g. RISC-V CI runner), expect detection to report no mitigations supported; the test harness still runs and emits valid reports with `FAULT_NONE` outcomes — this is the "configuration is unprotected" diagnostic, not a crash.
- If `bin/kmto` produces an empty `results.json`, check that the output directory exists and is writable; the `report_init` path will fail silently if not.

### 3.3 Roadmap
- **Short-term (≤1 day)**: (a) `driver/kmto_driver.vcxproj` is committed. (b) Add a 20-line shell script `scripts/verify.sh` that diffs against a committed expected-output fixture for x86_64. *(Still open — `tests/test_output.py` asserts validity but not a byte-for-byte fixture diff.)* (c) `tests/test_output.py` asserts `-t all` produces output and valid JSON (stronger than the old presence-only `make test` check).
- **Medium-term (≤1 week)**: (a) `tests/` (pytest) is present: structure + output-validation. CUnit/Greatest C-level unit tests for `telemetry_log_*` / `config_manager_create_matrix` remain a worthwhile deepening. (b) `.github/workflows/ci.yml` runs Linux (gcc/clang) build + `-t all` + pytest, and a Windows MSVC build; uploads `ci_output/`. (c) Mirror the Makefile's `-Wall -Wextra` into `CMakeLists.txt` and add `-Werror` to CI builds. *(Still open.)* (d) Add `ole32` to the CMake `kmto_cli` link line for parity with the Makefile. *(Still open.)*
- **Long-term**: (a) Implement the kernel-side fault provocation in the driver so enforcement claims become measurements rather than inferences (TECHNICAL_DEEP_DIVE §10.2). (b) Add a sampling layer for high-frequency event paths (§10.4). (c) Add the future-surface observers listed in TECHNICAL_DEEP_DIVE §11 (CET, KCFI, FineIBT, MTE, IOMMU). (d) Publish a stable JSON schema for `results.json` so downstream consumers can pin to it.

## 4. Sanity check

| Check | Status | Notes |
|-------|--------|-------|
| README documents build | ✅ | README §"Build" gives Makefile, CMake, and Windows-driver commands; usage and all eight test types are listed. |
| Build files present | ✅ | `Makefile` and `CMakeLists.txt` present and consistent. `driver/kmto_driver.vcxproj` and `driver/kmto_driver.vcxproj.filters` are also committed, so the Windows-driver path referenced by the README and TECHNICAL_DEEP_DIVE A.2 is buildable from a clean clone (not independently re-verified in this environment). |
| Build files internally consistent | ✅ | Makefile and CMakeLists list the same six core sources and gate `kmto_cli` on Windows the same way. Minor: CMake link line omits `ole32` that Makefile includes — flagged in §3.1. |
| Source structure matches README | ✅ | All eight headers in `include/` and all seven `.c` files in `src/` match the README's File-layout block (including `kmto_kernel_state.h` and the `driver/cr4_observer.c` / `event_ring.c` sources); enforced by `tests/test_structure.py`. |
| Tests exist | ✅ | `tests/` (pytest): `test_structure.py` (source-tree/Makefile sync), `test_output.py` (`-t all` produces valid JSON output). 19 passed / 3 skipped locally (output rows skip without a build). |
| Test invocation documented | ✅ | README File-layout names `tests/` and `.github/workflows/ci.yml`; §2.4 documents `python -m pytest tests/ -v`. CI runs build + `-t all` + pytest on Linux (gcc/clang) and a build on Windows. |
| Output artifacts named in build files | ✅ | `Makefile` declares `TARGET = $(BIN_DIR)/kmto` and `CLI_TARGET = $(BIN_DIR)/kmto_cli.exe`; `CMakeLists.txt` sets `RUNTIME_OUTPUT_DIRECTORY` to `${CMAKE_BINARY_DIR}/bin` for both targets. Driver output (`driver/bin/Release/kmto_driver.sys`) is named in the README but not produced by any build file in-tree. |
