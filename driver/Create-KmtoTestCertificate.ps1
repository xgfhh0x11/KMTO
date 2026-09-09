<#
.SYNOPSIS
  KMTO surucusu icin tek bir kod-imzalama test sertifikasi olusturur ve MSBuild'in kullanacagi kmto_driver_signing.props yazar.

.NOTES
  - Sertifika CurrentUser\My altinda olusturulur (yonetici gerekmez).
  - TrustedPublisher eklemek icin betigi "Yonetici olarak calistir" ile yeniden calistirin (istege bagli).
  - Test suruculeri: bcdedit /set testsigning on  ve yeniden baslatma.
#>
$ErrorActionPreference = 'Stop'
$driverDir = $PSScriptRoot
$propsPath = Join-Path $driverDir 'kmto_driver_signing.props'
$subject = 'CN=KMTO Kernel Mode Test Signing'

Write-Host "Konum: $driverDir"

$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject }
if ($existing) {
    $cert = $existing[0]
    Write-Host "Mevcut sertifika kullaniliyor: $($cert.Thumbprint)"
} else {
    $cert = New-SelfSignedCertificate `
        -Subject $subject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Type CodeSigningCert `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(10)
    Write-Host "Yeni sertifika olusturuldu: $($cert.Thumbprint)"
}

$sha1 = $cert.Thumbprint

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- Bu dosya Create-KmtoTestCertificate.ps1 tarafindan uretilir; git'e eklenmez. -->
  <PropertyGroup>
    <TestCertificate>$sha1</TestCertificate>
  </PropertyGroup>
</Project>
"@
Set-Content -Path $propsPath -Value $xml -Encoding UTF8
Write-Host "Yazildi: $propsPath"

$published = Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $sha1 }
if (-not $published) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine')
        $store.Open('ReadWrite')
        try {
            $store.Add($cert)
        } finally {
            $store.Close()
        }
        Write-Host "Sertifika LocalMachine\TrustedPublisher magazasina eklendi."
    } catch {
        Write-Warning "TrustedPublisher'a eklenemedi (genelde yonetici gerekir): $($_.Exception.Message)"
        Write-Host "Test imza modu aciksa (bcdedit testsigning on) surucu yine yuklenebilir."
    }
} else {
    Write-Host "Sertifika zaten TrustedPublisher'da."
}

Write-Host ""
Write-Host "Sonraki adimlar:"
Write-Host "  1) bcdedit /set testsigning on"
Write-Host "  2) Yeniden baslat"
Write-Host "  3) Surucuyu Release|x64 ile derle"
