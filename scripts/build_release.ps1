$ErrorActionPreference = "Stop"

param(
    [string]$Version = "v0.1"
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host "Building AuditOS release from AuditOS.spec..."

python -m pip install pyinstaller
pyinstaller --noconfirm AuditOS.spec

$Platform = if ($env:OS -eq "Windows_NT") { "Windows" } else { "macOS" }
$OutputDir = Join-Path $ProjectRoot "dist"
$ArchiveName = "AuditOS_${Platform}_Beta_${Version}.zip"
$ArchivePath = Join-Path $ProjectRoot $ArchiveName

if (Test-Path $ArchivePath) {
    Remove-Item $ArchivePath -Force
}

if ($env:OS -eq "Windows_NT") {
    Compress-Archive -Path (Join-Path $OutputDir "AuditOS\*") -DestinationPath $ArchivePath
} else {
    Compress-Archive -Path (Join-Path $OutputDir "AuditOS.app") -DestinationPath $ArchivePath
}

Write-Host "Build complete: $ArchivePath"
