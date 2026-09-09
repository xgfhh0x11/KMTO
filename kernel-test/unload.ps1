<#
.SYNOPSIS
  Stops and removes the KMTO kernel driver service. Meant to run INSIDE
  the disposable Hyper-V "WinKDbg" guest.

.DESCRIPTION
  Plain sc.exe stop + sc.exe delete. This is intentionally NOT -Arm-gated
  like load.ps1 and smoke-test.ps1: unloading is the recovery action, and
  gating it behind an extra switch only makes cleanup slower after
  something has already gone wrong. It still requires elevation, and it
  is safe to run even if the service does not exist (reports and exits 0).

.PARAMETER ServiceName
  Service name to remove. Default: KMTO (see load.ps1).

.EXAMPLE
  .\unload.ps1
  .\unload.ps1 -ServiceName KMTO
#>
[CmdletBinding()]
param(
    [string]$ServiceName = 'KMTO'
)

$ErrorActionPreference = 'Continue'

Write-Host "=== KMTO driver unload ===" -ForegroundColor Cyan
Write-Host "Service name : $ServiceName"
Write-Host ""

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Stopping/deleting a kernel-mode service requires an elevated (Administrator) PowerShell session."
    exit 1
}

$queryOutput = sc.exe query $ServiceName 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Service '$ServiceName' does not exist (or is already removed). Nothing to do." -ForegroundColor Yellow
    exit 0
}
Write-Host $queryOutput

Write-Host ""
Write-Host "Stopping '$ServiceName'..."
$stopOutput = sc.exe stop $ServiceName 2>&1
Write-Host $stopOutput
# sc stop returns non-zero if the service was already stopped (1062) - not fatal here.

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Deleting '$ServiceName'..."
$deleteOutput = sc.exe delete $ServiceName 2>&1
Write-Host $deleteOutput

if ($LASTEXITCODE -ne 0) {
    Write-Warning "sc.exe delete returned non-zero. If the driver is stuck loaded, a reboot (or reverting the Hyper-V checkpoint) will clear it."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=== '$ServiceName' removed ===" -ForegroundColor Green
