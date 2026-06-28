# Build script for SUCI-SUPI Tool
# Builds for multiple platforms

$VERSION = "2.3.0"
$APP_NAME = "suci-supi-tool"

Write-Host "Building $APP_NAME version $VERSION..." -ForegroundColor Green
Write-Host ""

# Ensure we're in the project root (one level up from scripts/)
Set-Location (Split-Path $PSScriptRoot -Parent)

# Clean previous builds
if (Test-Path ".\build") {
    Remove-Item -Recurse -Force .\build
}
New-Item -ItemType Directory -Force -Path .\build | Out-Null

# Build for Windows (amd64)
Write-Host "Building for Windows (amd64)..." -ForegroundColor Cyan
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o ".\build\$APP_NAME-windows-amd64.exe" ./cmd/suci-tool
if ($LASTEXITCODE -eq 0) {
    Write-Host "Windows build successful" -ForegroundColor Green
} else {
    Write-Host "Windows build failed" -ForegroundColor Red
    exit 1
}

# Build for Linux (amd64)
Write-Host "Building for Linux (amd64)..." -ForegroundColor Cyan
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o ".\build\$APP_NAME-linux-amd64" ./cmd/suci-tool
if ($LASTEXITCODE -eq 0) {
    Write-Host "Linux build successful" -ForegroundColor Green
} else {
    Write-Host "Linux build failed" -ForegroundColor Red
    exit 1
}

# Build for macOS (amd64)
Write-Host "Building for macOS (amd64)..." -ForegroundColor Cyan
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o ".\build\$APP_NAME-darwin-amd64" ./cmd/suci-tool
if ($LASTEXITCODE -eq 0) {
    Write-Host "macOS (Intel) build successful" -ForegroundColor Green
} else {
    Write-Host "macOS build failed" -ForegroundColor Red
    exit 1
}

# Reset environment variables to defaults
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Green
Write-Host "---------------------------------------------"
Get-ChildItem .\build | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 2)
    Write-Host "$($_.Name) - $size MB" -ForegroundColor White
}

Write-Host ""
Write-Host "All builds completed successfully!" -ForegroundColor Green
Write-Host "Binaries are available in: .\build" -ForegroundColor Yellow
