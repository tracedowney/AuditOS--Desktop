param(
    [string]$Version = "v0.1"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

Write-Host "Building AuditOS release from AuditOS.spec..."

python -m pip install pyinstaller
pyinstaller --noconfirm AuditOS.spec

$Platform = if ($env:OS -eq "Windows_NT") { "Windows" } else { "macOS" }
$OutputDir = Join-Path $ProjectRoot "dist"
$ArchiveName = "AuditOS_${Platform}_Beta_${Version}.zip"
$ArchivePath = Join-Path $ProjectRoot $ArchiveName
$WindowsFolderPath = Join-Path $OutputDir "AuditOS"
$WindowsExePath = Join-Path $OutputDir "AuditOS.exe"
$MacAppPath = Join-Path $OutputDir "AuditOS.app"

if (Test-Path $ArchivePath) {
    Remove-Item $ArchivePath -Force
}

if ($env:OS -eq "Windows_NT") {
    if (Test-Path $WindowsFolderPath) {
        Compress-Archive -Path (Join-Path $WindowsFolderPath "*") -DestinationPath $ArchivePath
    } elseif (Test-Path $WindowsExePath) {
        Compress-Archive -Path $WindowsExePath -DestinationPath $ArchivePath
    } else {
        throw "Expected Windows build output at '$WindowsFolderPath' or '$WindowsExePath'."
    }
} else {
    if (Test-Path $MacAppPath) {
        if (Get-Command ditto -ErrorAction SilentlyContinue) {
            ditto -c -k --sequesterRsrc --keepParent $MacAppPath $ArchivePath
        } else {
            Compress-Archive -Path $MacAppPath -DestinationPath $ArchivePath
        }
    } else {
        throw "Expected macOS app bundle at '$MacAppPath'."
    }
}

Write-Host "Build complete: $ArchivePath"
