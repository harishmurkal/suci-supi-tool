# Test script for SUCI-SUPI Tool
# Ensures clean environment before running tests

Write-Host "Running SUCI-SUPI Tool Tests..." -ForegroundColor Green
Write-Host ""

# Ensure we're in the project root (one level up from scripts/)
Set-Location (Split-Path $PSScriptRoot -Parent)

# Clear any lingering environment variables from cross-compilation
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue

# Run tests with coverage
Write-Host "Running unit tests with coverage..." -ForegroundColor Cyan
go test -v -cover ./...

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "All tests passed successfully!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Some tests failed!" -ForegroundColor Red
    exit 1
}

# Run benchmarks
Write-Host ""
Write-Host "Running benchmarks..." -ForegroundColor Cyan
go test ./pkg/suci -bench=. -benchmem

Write-Host ""
Write-Host "Test run complete!" -ForegroundColor Green
