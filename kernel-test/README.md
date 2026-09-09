# KMTO kernel-test infrastructure

Scripts + runbook for building the KMTO Windows kernel driver
(`kmto_driver.sys`) on the host and exercising it dynamically inside a
**disposable** Hyper-V guest ("WinKDbg") over a kdnet (network) kernel
debug connection. This directory does not connect to any VM, load any
driver, or run any scenario by itself — everything here is a script or
a set of instructions for a human to run deliberately, step by step.

KMTO's own driver is observation-only by design (see
`../driver/kmto_driver.c` header comment: "No SSDT hook, no page-table
write, no privileged register write, no exception-handler injection.
The data flow is one-way (kernel → userland)"). That does not make
loading it risk-free — any kernel-mode code can bugcheck the machine it
runs on, from a bug, a bad build, or an unexpected interaction with the
host's virtualized hardware. Treat every step below accordingly.

## Files in this directory

| File | Runs where | Purpose |
|---|---|---|
| `build.ps1` | **Host** | Builds `kmto_driver.sys` (Release\|x64) with MSBuild + the host WDK. Never touches a VM. Accepts `-TestCertificateThumbprint <SHA1>` if the host cert store has more than one matching test-signing cert. |
| `load.ps1` | **Guest** | `-Arm`-gated: creates + starts the `KMTO` kernel service from a `.sys` already copied into the guest. Dry-run (prints commands) without `-Arm`. |
| `unload.ps1` | **Guest** | Stops + deletes the `KMTO` service. Not gated — it's the recovery action. |
| `smoke-test.ps1` | **Guest** | `-Arm`-gated: exercises the driver's real IOCTLs over `\\.\KMTO` and checks the responses are sane and don't hang. Dry-run without `-Arm`. |
| `kd-triage.txt` | reference | kd.exe command templates: symbol setup, Driver Verifier, live inspection, bugcheck `!analyze -v` triage, recovery. |

**Honesty note:** `build.ps1` builds on the host, where WDK + MSBuild
live per the task context. Nothing in this repo has been dynamically
tested against a running kernel by this change — no driver was loaded,
and no VM was touched, while authoring this directory. The driver
**must build successfully with `build.ps1` first**.

The build itself *was* verified while authoring these scripts, on this
host (VS2022 Community + WDK 10.0.26100.0 already installed here):
`driver/kmto_driver.c`, `event_ring.c`, and `cr4_observer.c` compile
cleanly under `/W4 /WX` (0 warnings, 0 errors) and link into a 13 KB
`kmto_driver.sys`. The one snag: this particular host's certificate
store has several unrelated test-signing certificates, so MSBuild's
auto-selected TestSign step failed with `SignTool error: Multiple
certificates were found` until a specific thumbprint was passed via
the new `-TestCertificateThumbprint` parameter (see below) — that is a
host cert-store ambiguity, not a repo defect, and won't reproduce on a
clean machine with only one test-signing cert (the normal case after
running `driver/Create-KmtoTestCertificate.ps1` once). **Nothing was
dynamically tested beyond this local host build** — no loading, no
kd attach, no IOCTLs — that part is unverified and is exactly what the
rest of this runbook is for. Run `build.ps1` yourself and read its
output before trusting that a `.sys` exists at all; do not assume this
note still holds on a different host.

## Driver identity (from `include/kmto_protocol.h` and `driver/kmto_driver.vcxproj`)

- Binary: `kmto_driver.sys`, built to `driver\bin\Release\kmto_driver.sys`
- Device: `\Device\KMTO`, symbolic link `\DosDevices\KMTO` → user-mode
  path `\\.\KMTO`
- Service name used by these scripts: `KMTO` (arbitrary — the device
  name above is what actually matters for `\\.\KMTO` to resolve, but
  keeping the service name aligned avoids confusion)
- IOCTLs (function codes `0x900`-`0x905`, `METHOD_BUFFERED`):
  `KMTO_IOCTL_HANDSHAKE`, `KMTO_IOCTL_GET_CR4_SNAPSHOT`,
  `KMTO_IOCTL_GET_EVENTS`, `KMTO_IOCTL_GET_STATS`, `KMTO_IOCTL_RESET`,
  `KMTO_IOCTL_CONFIGURE` — see `smoke-test.ps1` for exact wire structs,
  mirrored from `src/kmto_cli.c`'s own `DeviceIoControl` calls.

## Prerequisites

### Host

- Visual Studio 2022 with the "Desktop development with C++" workload
  and the WDK (`WindowsKernelModeDriver10.0` platform toolset)
  integrated, matching `WindowsTargetPlatformVersion` `10.0.26100.0` in
  `driver/kmto_driver.vcxproj` (override via `/p:WDKRoot=...
  /p:WDKVersion=...` if your box has a different WDK version installed).
- `kd.exe` / `kdnet.exe` (from the WDK's Debugging Tools for Windows, or
  a standalone Debugging Tools for Windows install) on the PATH.
- A test-signing certificate for the driver — either run
  `driver/Create-KmtoTestCertificate.ps1` first (writes
  `driver/kmto_driver_signing.props`, not committed — already in
  `.gitignore`) or build without it, in which case
  `kmto_driver.vcxproj`'s `GenerateTestCertificate=true` fallback
  self-signs at build time. If the host's cert store already has more
  than one test-signing certificate that matches (common on a dev box
  that's been used for other test-signed drivers), MSBuild's auto
  TestSign step fails with `SignTool error: Multiple certificates were
  found` — pass `build.ps1 -TestCertificateThumbprint <SHA1>` to pick
  one explicitly (`Get-ChildItem Cert:\CurrentUser\My` lists candidates
  and their thumbprints).

### Guest ("WinKDbg", disposable Hyper-V VM)

1. **Test-signing mode.** Inside the guest, elevated:

   ```
   bcdedit /set testsigning on
   ```

   Then reboot the guest. Confirm it took:

   ```
   bcdedit /enum | findstr testsigning
   ```

2. **kdnet debug settings.** Still inside the guest, elevated, find (or
   set) the network debug port/key:

   ```
   bcdedit /dbgsettings
   ```

   If it isn't already configured for network debugging, set it (pick a
   free UDP port, e.g. 50000, and let kdnet generate a key, or supply
   your own):

   ```
   bcdedit /dbgsettings net hostip:<HOST_IP> port:50000
   bcdedit /set debug on
   ```

   `bcdedit /dbgsettings` (no arguments) then prints the `key=` value to
   use on the host side. Reboot the guest for debug settings to take
   effect if you just changed them.

3. **A Hyper-V checkpoint of the guest, taken FIRST**, before any driver
   ever gets loaded in this session. From an elevated **host**
   PowerShell (Hyper-V module):

   ```
   Checkpoint-VM -Name WinKDbg -SnapshotName "pre-kmto-$(Get-Date -Format yyyyMMdd-HHmmss)"
   ```

   The task context says a safety checkpoint already exists — verify it
   with `Get-VMCheckpoint -VMName WinKDbg` before proceeding, and take a
   fresh one per test session if the guest state has moved on since.

## Workflow

1. **Host:** `.\kernel-test\build.ps1`
   Builds `kmto_driver.sys`. Prints the output path on success, or the
   real MSBuild errors and a non-zero exit code on failure. Do not
   proceed past a failed build.

2. **Host → Guest:** copy the built `.sys` into the guest (e.g. to
   `C:\kmto-test\kmto_driver.sys`) using whatever the environment
   provides — Hyper-V guest file copy (`Copy-VMFile`, requires guest
   services enabled), a shared/mapped drive, or a manual copy through
   the console. This runbook does not automate that step.

3. **Host:** confirm the checkpoint from the Prerequisites section
   exists and is current.

4. **Host:** attach kd over the network:

   ```
   kd -k net:port=<PORT>,key=<KEY>
   ```

   e.g. `kd -k net:port=50000,key=1a2b3c4d.5e6f...` using the values
   from `bcdedit /dbgsettings` in the guest. Confirm you get a `kd>`
   prompt and `lm` shows the guest's loaded modules before continuing.
   See `kd-triage.txt` for what to do once attached.

5. **Guest:** (optional but recommended — see `kd-triage.txt` §2)
   enable Driver Verifier on the driver before loading it:

   ```
   verifier /standard /driver kmto_driver.sys
   ```

   then reboot the guest, re-attach kd, and re-copy the `.sys` if the
   reboot reset anything.

6. **Guest:** dry-run the loader first, then arm it:

   ```
   .\kernel-test\load.ps1                                    # dry run
   .\kernel-test\load.ps1 -Arm -SysPath C:\kmto-test\kmto_driver.sys
   ```

   Watch the kd session — a bugcheck here is possible and is why you
   checkpointed first.

7. **Guest:** dry-run then arm the smoke test:

   ```
   .\kernel-test\smoke-test.ps1                # dry run, prints the IOCTL plan
   .\kernel-test\smoke-test.ps1 -Arm            # read-only IOCTLs
   .\kernel-test\smoke-test.ps1 -Arm -IncludeMutating   # + CONFIGURE(off) + RESET
   ```

8. **Guest:** when done, always unload:

   ```
   .\kernel-test\unload.ps1
   ```

9. **Host:** if anything went sideways — bugcheck, hang that didn't
   recover, service stuck — revert the guest to the checkpoint rather
   than trying to hand-repair it:

   ```
   Restore-VMCheckpoint -VMName WinKDbg -Name "<checkpoint-name>" -Confirm:$false
   Start-VM -Name WinKDbg
   ```

## Safety

- **Driver loads can bugcheck the guest.** This is expected, and only
  safe to run into because of the checkpoint. Never load an unfamiliar
  or freshly-changed build without a current checkpoint to fall back to.
- **Always checkpoint before the first load of a given build**, and
  again after any significant change (new driver revision, changed
  guest config). A checkpoint from yesterday against today's `.sys` is
  not "already checkpointed."
- **Revert on crash.** Do not attempt to "reboot past" a bugchecked
  guest and keep testing the same session — revert to the checkpoint,
  restart the guest cleanly, re-attach kd, and start the workflow over
  from step 4.
- **`load.ps1` and `smoke-test.ps1` never act without `-Arm`.** Treat
  the absence of `-Arm` output as the expected default when scripting
  or calling these from anything automated — nothing here is meant to
  run unattended.
- **This is a disposable guest, not the host.** None of these scripts
  should ever run against a machine you care about keeping. `load.ps1`
  prints a warning and a 5-second delay if it detects it is being run
  with `-Arm` at all, as a last-ditch (not foolproof) speed bump — the
  real safety boundary is the operator only running it inside WinKDbg.
- **Driver Verifier is your friend here**, not optional polish — see
  `kd-triage.txt` §2. It turns silent memory corruption into an
  immediate, diagnosable bugcheck, which is exactly what you want while
  dynamically testing an unreviewed kernel binary.
