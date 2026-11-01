param(
    [string]$TargetDir = "target-nmake"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $projectRoot "$TargetDir\release\kafa-ui-tool.exe"
$readmePath = Join-Path $projectRoot "README.md"
$distDir = Join-Path $projectRoot "dist"
$packageDir = Join-Path $distDir "kafa-ui-tool"
$zipPath = Join-Path $distDir "kafa-ui-tool.zip"

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Khong tim thay executable release: $exePath"
}

New-Item -ItemType Directory -Force -Path $packageDir, $distDir | Out-Null
Copy-Item -LiteralPath $exePath -Destination (Join-Path $packageDir "kafa-ui-tool.exe") -Force
Copy-Item -LiteralPath $readmePath -Destination (Join-Path $packageDir "README.md") -Force
Compress-Archive -Path $packageDir -DestinationPath $zipPath -Force
Write-Host "Da tao: $zipPath"
