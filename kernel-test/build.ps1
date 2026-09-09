<#
.SYNOPSIS
  Builds the KMTO Windows kernel driver (kmto_driver.sys) Release|x64 using
  the host's WDK-integrated MSBuild toolchain. Does NOT touch any VM.

.DESCRIPTION
  Locates driver\kmto_driver.vcxproj (there is no .sln in this repo - the
  project builds standalone), invokes MSBuild for Release|x64, and prints
  the resulting .sys path on success.

  If the build fails for any reason (missing WDK, missing MSBuild, compile
  errors, link errors), this script prints MSBuild's actual output and exits
  non-zero. It never claims success it did not observe: presence of a stale
  .sys from a previous build is not treated as evidence of a successful
  build in this run.

.PARAMETER Configuration
  Build configuration. Default: Release.

.PARAMETER Platform
  Build platform. Default: x64. (The driver is WDM/x64 only in this repo.)

.PARAMETER TestCertificateThumbprint
  Optional. If the host's certificate store has more than one code-signing
  test certificate whose subject/criteria match, MSBuild's auto TestSign
  step fails with "SignTool error: Multiple certificates were found" instead
  of picking one. Pass the SHA1 thumbprint of the specific certificate to
  use (e.g. the one written to driver\kmto_driver_signing.props by
  driver\Create-KmtoTestCertificate.ps1) to disambiguate. This is forwarded
  as /p:TestCertificate=<thumbprint> to MSBuild.

.EXAMPLE
  .\build.ps1
  .\build.ps1 -Configuration Debug
  .\build.ps1 -TestCertificateThumbprint AA30F23DAABE6F52330C3B662A4504AF082F0FF3
#>
[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')]
    [string]$Configuration = 'Release',

    [ValidateSet('x64')]
    [string]$Platform = 'x64',

    [string]$TestCertificateThumbprint
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$driverDir  = Join-Path $repoRoot 'driver'
$vcxproj    = Join-Path $driverDir 'kmto_driver.vcxproj'

Write-Host "=== KMTO driver build ===" -ForegroundColor Cyan
Write-Host "Repo root : $repoRoot"
Write-Host "Project   : $vcxproj"
Write-Host "Config    : $Configuration|$Platform"
Write-Host ""

if (-not (Test-Path $vcxproj)) {
    Write-Error "Cannot find driver\kmto_driver.vcxproj under $driverDir. Did the repo layout change?"
    exit 1
}

# --- Locate MSBuild -----------------------------------------------------
# Prefer vswhere (installed with any VS2017+ instance); fall back to PATH.
function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * `
            -requires Microsoft.Component.MSBuild -property installationPath 2>$null
        if ($installPath) {
            $candidate = Join-Path $installPath 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $candidate) { return $candidate }
            $candidate = Join-Path $installPath 'MSBuild\15.0\Bin\MSBuild.exe'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    $onPath = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$msbuild = Find-MSBuild
if (-not $msbuild) {
    Write-Error @"
MSBuild not found. This driver needs Visual Studio (with the "Desktop
development with C++" workload) plus the WDK build tools integrated into
MSBuild (WindowsKernelModeDriver10.0 platform toolset). Install both on the
host, or run this from a "Developer PowerShell for VS" prompt.
"@
    exit 1
}
Write-Host "MSBuild   : $msbuild"

# --- Sanity-check the WDK is actually present ---------------------------
# kmto_driver.vcxproj hardcodes WDKRoot="C:\Program Files (x86)\Windows Kits\10"
# and WDKVersion=10.0.26100.0 unless overridden via /p:.
$wdkRoot    = $env:WDKRoot
if (-not $wdkRoot) { $wdkRoot = 'C:\Program Files (x86)\Windows Kits\10' }
$wdkVersion = $env:WDKVersion
if (-not $wdkVersion) { $wdkVersion = '10.0.26100.0' }
$kmHeader = Join-Path $wdkRoot "Include\$wdkVersion\km\ntddk.h"
if (-not (Test-Path $kmHeader)) {
    Write-Warning "Could not find $kmHeader - the WDK for $wdkVersion may not be installed. Build will likely fail; continuing anyway so MSBuild reports the real error."
}

# --- Build ----------------------------------------------------------------
$logFile = Join-Path $PSScriptRoot "build-$Configuration-$Platform.log"
Write-Host ""
Write-Host "Building... (log: $logFile)"

$msbuildArgs = @(
    "`"$vcxproj`""
    "/p:Configuration=$Configuration"
    "/p:Platform=$Platform"
    "/nologo"
    "/verbosity:normal"
    "/fileLogger"
    "/fileLoggerParameters:LogFile=$logFile;Verbosity=detailed"
)
if ($TestCertificateThumbprint) {
    $msbuildArgs += "/p:TestCertificate=$TestCertificateThumbprint"
    Write-Host "Using test-signing certificate thumbprint: $TestCertificateThumbprint"
}

& $msbuild @msbuildArgs
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "=== BUILD FAILED (MSBuild exit code $exitCode) ===" -ForegroundColor Red
    Write-Host "--- Errors from $logFile ---" -ForegroundColor Red
    if (Test-Path $logFile) {
        Select-String -Path $logFile -Pattern 'error' -SimpleMatch:$false | ForEach-Object { $_.Line }
    }
    Write-Host ""
    if ((Test-Path $logFile) -and (Select-String -Path $logFile -Pattern 'Multiple certificates were found' -Quiet)) {
        Write-Host "HINT: multiple matching test-signing certificates exist in this host's cert store." -ForegroundColor Yellow
        Write-Host "Re-run with -TestCertificateThumbprint <SHA1> to pick one (see driver\Create-KmtoTestCertificate.ps1" -ForegroundColor Yellow
        Write-Host "or driver\kmto_driver_signing.props for a thumbprint already associated with this repo)." -ForegroundColor Yellow
        Write-Host ""
    }
    Write-Host "Full log: $logFile" -ForegroundColor Red
    exit $exitCode
}

# --- Verify the output actually exists (don't trust exit code alone) ----
$sysPath = Join-Path $driverDir "bin\$Configuration\kmto_driver.sys"
if (-not (Test-Path $sysPath)) {
    Write-Error "MSBuild reported success (exit 0) but $sysPath was not produced. Treating this as a build failure - check $logFile."
    exit 1
}

$sysItem = Get-Item $sysPath
Write-Host ""
Write-Host "=== BUILD OK ===" -ForegroundColor Green
Write-Host "Driver    : $($sysItem.FullName)"
Write-Host "Size      : $($sysItem.Length) bytes"
Write-Host "Modified  : $($sysItem.LastWriteTime)"
Write-Host ""
Write-Host "NOTE: this .sys is test-signed only if driver\kmto_driver_signing.props" -ForegroundColor Yellow
Write-Host "exists (see driver\Create-KmtoTestCertificate.ps1). Verify test-signing" -ForegroundColor Yellow
Write-Host "before attempting to load it in the guest (bcdedit /set testsigning on)." -ForegroundColor Yellow

exit 0
