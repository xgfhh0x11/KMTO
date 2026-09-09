<#
.SYNOPSIS
  SAFETY-GATED smoke test of the loaded KMTO driver's real IOCTL surface.
  Meant to run INSIDE the disposable Hyper-V "WinKDbg" guest, AFTER
  load.ps1 -Arm has successfully started the service.

.DESCRIPTION
  Exercises the six IOCTLs defined in include\kmto_protocol.h against
  \\.\KMTO, the exact device path the driver creates
  (KMTO_USER_DEVICE_PATH), and checks the responses are structurally sane
  (right byte counts, expected status codes, non-garbage values) and that
  no call hangs.

  Read-only IOCTLs (run by default once -Arm is given):
    KMTO_IOCTL_HANDSHAKE          0x900  version/capability exchange
    KMTO_IOCTL_GET_CR4_SNAPSHOT   0x901  synchronous CR4/MSR read
    KMTO_IOCTL_GET_STATS          0x903  aggregate counters
    KMTO_IOCTL_GET_EVENTS         0x902  drain CPU 0's event ring

  Mutating IOCTLs (only with -Arm -IncludeMutating):
    KMTO_IOCTL_CONFIGURE          0x905  called with enable_mask=0 to
                                          explicitly leave the sampler and
                                          bugcheck callback OFF (a safe,
                                          known state) rather than to turn
                                          anything on.
    KMTO_IOCTL_RESET              0x904  clears event rings + counters

  Without -Arm this is a dry run: it prints the IOCTL plan and exits 0
  without opening the device.

  Hang detection: the actual DeviceIoControl sequence runs inside a
  background job (a separate process), bounded by -TimeoutSec. If the
  job does not finish in time, the job (and, with it, any IOCTL blocked
  in the driver) is forcibly stopped and this script reports a timeout
  and exits non-zero, instead of hanging the caller.

.PARAMETER Arm
  Required to actually open the device and issue IOCTLs. Omit for a dry run.

.PARAMETER IncludeMutating
  Also issue KMTO_IOCTL_CONFIGURE (enable_mask=0) and KMTO_IOCTL_RESET.
  Only meaningful with -Arm.

.PARAMETER TimeoutSec
  Wall-clock budget for the entire IOCTL sequence. Default 60.

.EXAMPLE
  .\smoke-test.ps1                       # dry run, shows the plan
  .\smoke-test.ps1 -Arm                  # read-only IOCTLs only
  .\smoke-test.ps1 -Arm -IncludeMutating # also CONFIGURE(0) + RESET
#>
[CmdletBinding()]
param(
    [switch]$Arm,
    [switch]$IncludeMutating,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'Stop'

$plan = @(
    [pscustomobject]@{ Name='HANDSHAKE';        Code='0x900'; Mutating=$false; Desc='version/capability exchange' }
    [pscustomobject]@{ Name='GET_CR4_SNAPSHOT';  Code='0x901'; Mutating=$false; Desc='synchronous CR4/MSR read' }
    [pscustomobject]@{ Name='GET_STATS';         Code='0x903'; Mutating=$false; Desc='aggregate counters' }
    [pscustomobject]@{ Name='GET_EVENTS(cpu=0)'; Code='0x902'; Mutating=$false; Desc='drain up to 8 events from CPU 0 ring' }
    [pscustomobject]@{ Name='CONFIGURE(0,0)';    Code='0x905'; Mutating=$true;  Desc='force sampler+bugcheck-cb OFF (safe state)' }
    [pscustomobject]@{ Name='RESET';             Code='0x904'; Mutating=$true;  Desc='clear event rings + counters' }
)

Write-Host "=== KMTO driver smoke test ($(if ($Arm) {'ARMED'} else {'DRY RUN'})) ===" -ForegroundColor Cyan
Write-Host "Device: \\.\KMTO"
Write-Host ""
Write-Host "IOCTL plan:" -ForegroundColor Cyan
$plan | Where-Object { -not $_.Mutating -or $IncludeMutating } | Format-Table Name, Code, Mutating, Desc -AutoSize | Out-String | Write-Host

if (-not $Arm) {
    Write-Host "DRY RUN - no device was opened, no IOCTLs were sent." -ForegroundColor Yellow
    Write-Host "Pass -Arm to run the read-only IOCTLs above against a loaded driver."
    Write-Host "Add -IncludeMutating to also run CONFIGURE(0,0) and RESET."
    exit 0
}

# The actual work runs in a background job (separate process) so a hung
# DeviceIoControl call can be killed on timeout instead of hanging this
# script forever.
$jobScript = {
    param([bool]$IncludeMutating)

    $ErrorActionPreference = 'Stop'

    Add-Type -Namespace Kmto -Name Native -MemberDefinition @'
using System;
using System.Runtime.InteropServices;

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
public static extern IntPtr CreateFileA(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool DeviceIoControl(
    IntPtr hDevice, uint dwIoControlCode,
    byte[] lpInBuffer, uint nInBufferSize,
    byte[] lpOutBuffer, uint nOutBufferSize,
    out uint lpBytesReturned, IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
'@

    function New-CtlCode([uint32]$Function) {
        # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, Function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
        return (0x22 -shl 16) -bor (0 -shl 14) -bor ($Function -shl 2) -bor 0
    }

    $IOCTL_HANDSHAKE        = New-CtlCode 0x900
    $IOCTL_GET_CR4_SNAPSHOT = New-CtlCode 0x901
    $IOCTL_GET_EVENTS       = New-CtlCode 0x902
    $IOCTL_GET_STATS        = New-CtlCode 0x903
    $IOCTL_RESET            = New-CtlCode 0x904
    $IOCTL_CONFIGURE        = New-CtlCode 0x905

    $GENERIC_READ  = 0x80000000
    $GENERIC_WRITE = 0x40000000
    $OPEN_EXISTING = 3
    $FILE_ATTRIBUTE_NORMAL = 0x80
    $INVALID_HANDLE_VALUE = [IntPtr]::new(-1)

    $results = New-Object System.Collections.Generic.List[object]
    function Add-Result($name, $ok, $bytes, $elapsedMs, $notes) {
        $results.Add([pscustomobject]@{
            Name = $name; Ok = $ok; Bytes = $bytes; ElapsedMs = $elapsedMs; Notes = $notes
        }) | Out-Null
    }

    $sw = [System.Diagnostics.Stopwatch]::new()

    $sw.Restart()
    $h = [Kmto.Native]::CreateFileA('\\.\KMTO', ($GENERIC_READ -bor $GENERIC_WRITE), 0,
                                     [IntPtr]::Zero, $OPEN_EXISTING, $FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    $sw.Stop()
    if ($h -eq $INVALID_HANDLE_VALUE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-Result 'OPEN \\.\KMTO' $false 0 $sw.ElapsedMilliseconds "CreateFileA failed, Win32 error $err (is the KMTO service started? see load.ps1)"
        return $results
    }
    Add-Result 'OPEN \\.\KMTO' $true 0 $sw.ElapsedMilliseconds 'handle opened'

    try {
        # --- HANDSHAKE: 48-byte request, 112-byte response ---
        $req = New-Object byte[] 48
        [BitConverter]::GetBytes([uint32]0x00020000).CopyTo($req, 0)   # version = KMTO_PROTOCOL_VERSION
        [BitConverter]::GetBytes([uint32]0x1F).CopyTo($req, 4)          # capabilities = all 5 KMTO_CAP_* bits
        [BitConverter]::GetBytes([uint64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000).CopyTo($req, 8)
        $name = [Text.Encoding]::ASCII.GetBytes('kernel-test-smoke')
        [Array]::Copy($name, 0, $req, 16, [Math]::Min($name.Length, 31))

        $resp = New-Object byte[] 112
        $bytesReturned = 0
        $sw.Restart()
        $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_HANDSHAKE, $req, $req.Length, $resp, $resp.Length, [ref]$bytesReturned, [IntPtr]::Zero)
        $sw.Stop()
        if ($ok -and $bytesReturned -eq 112) {
            $status = [BitConverter]::ToUInt32($resp, 0)
            $driverBuild = [BitConverter]::ToUInt32($resp, 4)
            $author = [Text.Encoding]::ASCII.GetString($resp, 16, 32).TrimEnd([char]0)
            $banner = [Text.Encoding]::ASCII.GetString($resp, 48, 64).TrimEnd([char]0)
            $sane = ($status -eq 0)
            Add-Result 'HANDSHAKE' $sane $bytesReturned $sw.ElapsedMilliseconds "status=$status build=0x$($driverBuild.ToString('X8')) author='$author' banner='$banner'"
        } else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Add-Result 'HANDSHAKE' $false $bytesReturned $sw.ElapsedMilliseconds "DeviceIoControl failed/short, Win32 error $err"
        }

        # --- GET_CR4_SNAPSHOT: no input, 64-byte response ---
        $resp = New-Object byte[] 64
        $bytesReturned = 0
        $sw.Restart()
        $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_GET_CR4_SNAPSHOT, $null, 0, $resp, $resp.Length, [ref]$bytesReturned, [IntPtr]::Zero)
        $sw.Stop()
        if ($ok -and $bytesReturned -eq 64) {
            $cr4 = [BitConverter]::ToUInt64($resp, 0)
            $cpu = [BitConverter]::ToUInt32($resp, 56)
            # CR4 bit 0 (VME) is effectively always set on modern x86-64 Windows; a literal
            # all-zero CR4 would indicate the read didn't actually happen.
            $sane = ($cr4 -ne 0)
            Add-Result 'GET_CR4_SNAPSHOT' $sane $bytesReturned $sw.ElapsedMilliseconds "cr4=0x$($cr4.ToString('X')) cpu=$cpu"
        } else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Add-Result 'GET_CR4_SNAPSHOT' $false $bytesReturned $sw.ElapsedMilliseconds "DeviceIoControl failed/short, Win32 error $err"
        }

        # --- GET_STATS: no input, 72-byte response ---
        $resp = New-Object byte[] 72
        $bytesReturned = 0
        $sw.Restart()
        $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_GET_STATS, $null, 0, $resp, $resp.Length, [ref]$bytesReturned, [IntPtr]::Zero)
        $sw.Stop()
        if ($ok -and $bytesReturned -eq 72) {
            $activeCpus = [BitConverter]::ToUInt32($resp, 48)
            $uptimeMs = [BitConverter]::ToUInt64($resp, 56)
            $sane = ($activeCpus -gt 0)
            Add-Result 'GET_STATS' $sane $bytesReturned $sw.ElapsedMilliseconds "active_cpus=$activeCpus uptime_ms=$uptimeMs"
        } else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Add-Result 'GET_STATS' $false $bytesReturned $sw.ElapsedMilliseconds "DeviceIoControl failed/short, Win32 error $err"
        }

        # --- GET_EVENTS(cpu=0, max_events=8): 8-byte request, up to 8+8*64=520-byte response ---
        $req = New-Object byte[] 8
        [BitConverter]::GetBytes([uint32]0).CopyTo($req, 0)  # cpu_number = 0
        [BitConverter]::GetBytes([uint32]8).CopyTo($req, 4)  # max_events = 8
        $resp = New-Object byte[] (8 + 8 * 64)
        $bytesReturned = 0
        $sw.Restart()
        $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_GET_EVENTS, $req, $req.Length, $resp, $resp.Length, [ref]$bytesReturned, [IntPtr]::Zero)
        $sw.Stop()
        if ($ok -and $bytesReturned -ge 8) {
            $eventCount = [BitConverter]::ToUInt32($resp, 0)
            $lostEvents = [BitConverter]::ToUInt32($resp, 4)
            $sane = ($eventCount -le 8) -and ($bytesReturned -eq 8 + $eventCount * 64)
            Add-Result 'GET_EVENTS(cpu=0)' $sane $bytesReturned $sw.ElapsedMilliseconds "event_count=$eventCount lost_events=$lostEvents"
        } else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Add-Result 'GET_EVENTS(cpu=0)' $false $bytesReturned $sw.ElapsedMilliseconds "DeviceIoControl failed/short, Win32 error $err"
        }

        if ($IncludeMutating) {
            # --- CONFIGURE(enable_mask=0, interval=0): force sampler+bugcheck-cb OFF ---
            $req = New-Object byte[] 8
            [BitConverter]::GetBytes([uint32]0).CopyTo($req, 0)  # enable_mask = 0 (both off)
            [BitConverter]::GetBytes([uint32]0).CopyTo($req, 4)  # sampling_interval_ms = 0 (leave unchanged)
            $resp = New-Object byte[] 8
            $bytesReturned = 0
            $sw.Restart()
            $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_CONFIGURE, $req, $req.Length, $resp, $resp.Length, [ref]$bytesReturned, [IntPtr]::Zero)
            $sw.Stop()
            if ($ok -and $bytesReturned -eq 8) {
                $activeMask = [BitConverter]::ToUInt32($resp, 0)
                $sane = ($activeMask -eq 0)
                Add-Result 'CONFIGURE(0,0)' $sane $bytesReturned $sw.ElapsedMilliseconds "active_mask=$activeMask (expected 0)"
            } else {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Add-Result 'CONFIGURE(0,0)' $false $bytesReturned $sw.ElapsedMilliseconds "DeviceIoControl failed/short, Win32 error $err"
            }

            # --- RESET: no input/output ---
            $bytesReturned = 0
            $sw.Restart()
            $ok = [Kmto.Native]::DeviceIoControl($h, $IOCTL_RESET, $null, 0, $null, 0, [ref]$bytesReturned, [IntPtr]::Zero)
            $sw.Stop()
            Add-Result 'RESET' $ok $bytesReturned $sw.ElapsedMilliseconds $(if ($ok) { 'rings + counters cleared' } else { "Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" })
        }
    } finally {
        [Kmto.Native]::CloseHandle($h) | Out-Null
    }

    return $results
}

$job = Start-Job -ScriptBlock $jobScript -ArgumentList $IncludeMutating.IsPresent
$completed = Wait-Job -Job $job -Timeout $TimeoutSec

if (-not $completed) {
    Write-Host ""
    Write-Host "=== TIMEOUT after ${TimeoutSec}s - possible hang in the driver or the smoke-test client ===" -ForegroundColor Red
    Stop-Job -Job $job | Out-Null
    Remove-Job -Job $job -Force | Out-Null
    Write-Host "The background job was forcibly stopped. If a real IOCTL is stuck in the" -ForegroundColor Red
    Write-Host "kernel, the driver/guest may need attention (kd break-in, !process 0 0," -ForegroundColor Red
    Write-Host "see kd-triage.txt) or the guest may need to be reverted to its checkpoint." -ForegroundColor Red
    exit 1
}

$results = Receive-Job -Job $job
Remove-Job -Job $job -Force | Out-Null

Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
$results | Format-Table Name, Ok, Bytes, ElapsedMs, Notes -AutoSize | Out-String | Write-Host

$failed = @($results | Where-Object { -not $_.Ok })
$slow   = @($results | Where-Object { $_.ElapsedMs -gt 3000 })

if ($slow) {
    Write-Warning "One or more IOCTLs took > 3000ms - possible sluggishness (not a hard failure, but worth investigating with kd if it recurs):"
    $slow | ForEach-Object { Write-Warning "  $($_.Name): $($_.ElapsedMs) ms" }
}

if ($failed) {
    Write-Host ""
    Write-Host "=== SMOKE TEST FAILED ($($failed.Count) of $($results.Count) checks) ===" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== SMOKE TEST OK - all IOCTLs returned sane responses ===" -ForegroundColor Green
exit 0
