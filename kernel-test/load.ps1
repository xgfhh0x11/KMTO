<#
.SYNOPSIS
  SAFETY-GATED loader for the KMTO kernel driver. Meant to run INSIDE the
  disposable Hyper-V "WinKDbg" guest (console or a session reached over the
  kd.exe network debug connection) - never on the host.

.DESCRIPTION
  Without -Arm, this is a dry run: it prints the exact sc.exe commands it
  WOULD run and exits 0 without touching the service control manager or the
  filesystem. Pass -Arm to actually copy the driver into the guest and
  create+start the service. This script never auto-arms itself.

  BEFORE running with -Arm:
    1. Take a Hyper-V checkpoint of the guest (Checkpoint-VM on the HOST,
       from an elevated host PowerShell - this script cannot do it from
       inside the guest). See ..\README.md "Safety" section.
    2. Confirm the guest has test-signing enabled:
         bcdedit /enum | findstr testsigning
       If not: bcdedit /set testsigning on ; then reboot the guest.
    3. Confirm the .sys was actually built (kernel-test\build.ps1 on the
       host, run from the repo, against the host's WDK) and copied into
       the guest.

  Loading a kernel driver can bugcheck (BSOD) the guest. That is expected
  and recoverable ONLY because you checkpointed first. If the guest does
  not come back cleanly, revert to the checkpoint from the host:
       Restore-VMCheckpoint -VMName WinKDbg -Name <checkpoint> -Confirm:$false

.PARAMETER SysPath
  Path (inside the guest) to kmto_driver.sys. Default assumes the driver
  was copied to C:\kmto-test\kmto_driver.sys.

.PARAMETER ServiceName
  Name to register the service under. Default: KMTO (matches the driver's
  own \Device\KMTO / \DosDevices\KMTO symbolic link, so \\.\KMTO resolves
  once loaded regardless of the service name - but keeping them aligned
  avoids confusion).

.PARAMETER Arm
  Required to actually execute anything. Omit for a dry run (default).

.EXAMPLE
  # Dry run - just shows what would happen
  .\load.ps1

.EXAMPLE
  # Actually load it (run this INSIDE the guest, elevated, AFTER checkpointing)
  .\load.ps1 -Arm -SysPath C:\kmto-test\kmto_driver.sys
#>
[CmdletBinding()]
param(
    [string]$SysPath = 'C:\kmto-test\kmto_driver.sys',
    [string]$ServiceName = 'KMTO',
    [switch]$Arm
)

$ErrorActionPreference = 'Stop'

Write-Host "=== KMTO driver load ($(if ($Arm) {'ARMED'} else {'DRY RUN'})) ===" -ForegroundColor Cyan
Write-Host "Service name : $ServiceName"
Write-Host "Driver path  : $SysPath"
Write-Host ""

if (-not $Arm) {
    Write-Host "DRY RUN - no changes will be made. Pass -Arm to actually load the driver." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This script assumes it is running INSIDE the disposable guest ('WinKDbg')," -ForegroundColor Yellow
    Write-Host "AFTER you have taken a Hyper-V checkpoint from the HOST and enabled" -ForegroundColor Yellow
    Write-Host "test-signing in the guest. See kernel-test\README.md." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Commands that WOULD run:" -ForegroundColor Cyan
    Write-Host "  sc.exe create $ServiceName type= kernel binPath= `"$SysPath`" start= demand"
    Write-Host "  sc.exe start $ServiceName"
    Write-Host ""
    Write-Host "(To actually run these: .\load.ps1 -Arm -SysPath `"$SysPath`" -ServiceName $ServiceName)"
    exit 0
}

# ---- ARMED path ----------------------------------------------------------

# Refuse to arm on what looks like the host, as a last-ditch guard rail.
# This is a heuristic, not a hard guarantee - the real safety boundary is
# the human running this only inside the guest after checkpointing.
$computerName = $env:COMPUTERNAME
Write-Warning "Running ARMED on host '$computerName'. This script does not verify it is running inside the guest - confirm you are on WinKDbg, not the host, before continuing."
Write-Host "Continuing in 5 seconds... (Ctrl+C to abort)" -ForegroundColor Yellow
Start-Sleep -Seconds 5

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Loading a kernel driver requires an elevated (Administrator) PowerShell session."
    exit 1
}

if (-not (Test-Path $SysPath)) {
    Write-Error "Driver not found at $SysPath. Build it on the host with kernel-test\build.ps1 and copy driver\bin\Release\kmto_driver.sys into the guest first."
    exit 1
}

Write-Host "Checking for existing service '$ServiceName'..."
$existing = sc.exe query $ServiceName 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Warning "Service '$ServiceName' already exists. Stopping and deleting it first (use unload.ps1 normally, but doing it inline here for a clean re-load)."
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "Creating service '$ServiceName' -> $SysPath ..."
$createOutput = sc.exe create $ServiceName type= kernel binPath= "$SysPath" start= demand 2>&1
Write-Host $createOutput
if ($LASTEXITCODE -ne 0) {
    Write-Error "sc.exe create failed (exit $LASTEXITCODE). Not attempting start."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Starting service '$ServiceName'..." -ForegroundColor Cyan
Write-Host "(A bugcheck here is possible and recoverable ONLY if you checkpointed the guest first.)" -ForegroundColor Yellow
$startOutput = sc.exe start $ServiceName 2>&1
Write-Host $startOutput
if ($LASTEXITCODE -ne 0) {
    Write-Error "sc.exe start failed (exit $LASTEXITCODE). Service was created but did not start; check the System event log and kd for driver load errors. Run unload.ps1 to clean up the service entry."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=== Service '$ServiceName' started ===" -ForegroundColor Green
Write-Host "Verify from a debugger or user-mode client that \\\\.\\KMTO is reachable (device name is fixed by the driver regardless of service name), e.g. via the repo's kmto_cli.exe, or kernel-test\smoke-test.ps1 -Arm."
Write-Host "To remove: kernel-test\unload.ps1 -ServiceName $ServiceName"
