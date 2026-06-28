# Regression Test Suite for SUCI-SUPI Tool
# Usage: .\regression_tests.ps1 [-Category <category>]
# Categories: sanity, functional, error, cli, keygen, conceal, unit (go test pkg/keys,suci,suciutil), all (default)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("sanity", "functional", "error", "cli", "keygen", "conceal", "unit", "all")]
    [string]$Category = "all"
)

# Ensure we're in the project root (one level up from scripts/)
Set-Location (Split-Path $PSScriptRoot -Parent)

$BinaryPath = ".\build\suci-supi-tool-windows-amd64.exe"
$Passed = 0
$Failed = 0
$Total = 0
$TestKeyDir = ".\test-keys-regression"
$ProfileGSubscriberKeyID = if ($env:PROFILE_G_SUBSCRIBER_KEY_ID) { $env:PROFILE_G_SUBSCRIBER_KEY_ID } else { "0011223344" }

function Write-Pass { Write-Host "[PASS]" -ForegroundColor Green }
function Write-Fail { param($msg) Write-Host "[FAIL] - $msg" -ForegroundColor Red }
function Write-TestName { param($name) Write-Host -NoNewline "  $name... " }
function Write-Header { param($msg) Write-Host "`n$msg" -ForegroundColor Cyan }

# Check binary exists
if (-not (Test-Path $BinaryPath)) {
    Write-Host "Error: Binary not found. Run .\\scripts\\build.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================================"
Write-Host "    SUCI-SUPI Tool - Regression Test Suite" -ForegroundColor Cyan
Write-Host "========================================================"
Write-Host "Binary: $BinaryPath"
Write-Host "Category: $Category`n"

# SANITY TESTS
if ($Category -in "sanity", "all") {
    Write-Header "[SANITY TESTS]"
    
    # Test: Version command
    Write-TestName "Version command"
    $Total++
    $result = & $BinaryPath version
    if ($LASTEXITCODE -eq 0 -and $result -match "Version") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Exit: $LASTEXITCODE"
        $Failed++
    }
    
    # Test: Help command  
    Write-TestName "Help command"
    $Total++
    $result = & $BinaryPath help
    if ($LASTEXITCODE -eq 0 -and $result -match "USAGE") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Exit: $LASTEXITCODE"
        $Failed++
    }
    
    # Test: No arguments
    Write-TestName "No arguments (shows help)"
    $Total++
    $result = & $BinaryPath 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "USAGE") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Exit: $LASTEXITCODE"
        $Failed++
    }
    
    # Test: NULL-SCHEME deconceal
    Write-TestName "NULL-SCHEME deconceal"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-123-45-012-0-0-1032547698"
    if ($LASTEXITCODE -eq 0 -and $result -match "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
}

# CLI TESTS
if ($Category -in "cli", "all") {
    Write-Header "[CLI TESTS]"
    
    Write-TestName 'Help flag (--help)'
    $Total++
    $result = & $BinaryPath --help
    if ($LASTEXITCODE -eq 0 -and $result -match "USAGE") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Exit: $LASTEXITCODE"
        $Failed++
    }
    
    Write-TestName 'Version flag (--version)'
    $Total++
    $result = & $BinaryPath --version
    if ($LASTEXITCODE -eq 0 -and $result -match "Version") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Exit: $LASTEXITCODE"
        $Failed++
    }
    
    Write-TestName "Invalid command"
    $Total++
    $result = & $BinaryPath invalid-command 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "Unknown command") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should fail with error"
        $Failed++
    }
    
    Write-TestName 'Deconceal without --suci'
    $Total++
    $result = & $BinaryPath deconceal 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "required") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should fail"
        $Failed++
    }
}

# FUNCTIONAL TESTS
if ($Category -in "functional", "all") {
    Write-Header "[FUNCTIONAL TESTS]"
    
    Write-TestName "NULL-SCHEME: Valid IMSI"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-123-45-012-0-0-1032547698"
    if ($LASTEXITCODE -eq 0 -and $result -eq "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
    
    Write-TestName "NULL-SCHEME: 15-digit MSIN"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-001-01-000-0-0-10325476981032f4" 2>&1
    # This should actually fail because 20-digit IMSI (001+01+15 digits) exceeds max length
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0206") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should reject >15 digit IMSI"
        $Failed++
    }
    
    Write-TestName "NULL-SCHEME: MCC 310 (USA)"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-310-410-000-0-0-21436587f9"
    if ($LASTEXITCODE -eq 0 -and $result -eq "imsi-310410123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
    
    Write-TestName "NULL-SCHEME: 3-digit MNC"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-001-001-000-0-0-21436587f9"
    if ($LASTEXITCODE -eq 0 -and $result -eq "imsi-001001123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
}

# ERROR TESTS
if ($Category -in "error", "all") {
    Write-Header "[ERROR HANDLING TESTS]"
    
    Write-TestName "Invalid SUCI format"
    $Total++
    $result = & $BinaryPath deconceal --suci "invalid-suci" 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0101") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should return error-0101"
        $Failed++
    }
    
    Write-TestName "SUCI without prefix"
    $Total++
    $result = & $BinaryPath deconceal --suci "0-123-45-012-0-0-1032547698" 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0101") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should return error-0101"
        $Failed++
    }
    
    Write-TestName "Invalid scheme ID (treated as NULL)"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-123-45-012-0-99-1032547698" 2>&1
    # Tool currently treats unknown scheme IDs as NULL-SCHEME
    if ($LASTEXITCODE -eq 0 -and $result -match "imsi-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Tool treats invalid schemes as NULL"
        $Failed++
    }
    
    Write-TestName "Profile A with short cryptogram"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-123-45-012-0-1-0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20" 2>&1
    # Tool returns error-0205 (MSIN decode error) or error-0204 (too short)
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should return error"
        $Failed++
    }
    
    Write-TestName "Profile B with short cryptogram"
    $Total++
    $result = & $BinaryPath deconceal --suci "suci-0-123-45-012-0-2-0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20" 2>&1
    # Tool returns error-0205 (MSIN decode error) or error-0204 (too short)
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should return error"
        $Failed++
    }
}

# KEYGEN TESTS
if ($Category -in "keygen", "all") {
    Write-Header "[KEYGEN TESTS]"
    
    # Cleanup test directory
    if (Test-Path $TestKeyDir) {
        Remove-Item -Path $TestKeyDir -Recurse -Force
    }
    
    Write-TestName "Keygen: Single key pair (Profile A+B)"
    $Total++
    $result = & $BinaryPath keygen --start-id 1 --output-dir $TestKeyDir 2>&1
    $keyFileA = Join-Path $TestKeyDir "hn-key-1-profile-a.pem"
    $keyFileB = Join-Path $TestKeyDir "hn-key-1-profile-b.pem"
    if ($LASTEXITCODE -eq 0 -and (Test-Path $keyFileA) -and (Test-Path $keyFileB)) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Keys not generated"
        $Failed++
    }
    
    Write-TestName "Keygen: Range 0-5 (12 keys)"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-5 --output-dir $TestKeyDir 2>&1
    $keyCount = (Get-ChildItem $TestKeyDir -Filter "*.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $keyCount -eq 12) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 12 keys, got $keyCount"
        $Failed++
    }
    
    Write-TestName "Keygen: Profile A only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile a --output-dir $TestKeyDir 2>&1
    $profileACount = (Get-ChildItem $TestKeyDir -Filter "*profile-a.pem" -ErrorAction SilentlyContinue).Count
    $profileBCount = (Get-ChildItem $TestKeyDir -Filter "*profile-b.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileACount -eq 3 -and $profileBCount -eq 0) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 Profile A, 0 Profile B. Got $profileACount A, $profileBCount B"
        $Failed++
    }
    
    Write-TestName "Keygen: Profile B only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile b --output-dir $TestKeyDir 2>&1
    $profileACount = (Get-ChildItem $TestKeyDir -Filter "*profile-a.pem" -ErrorAction SilentlyContinue).Count
    $profileBCount = (Get-ChildItem $TestKeyDir -Filter "*profile-b.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileACount -eq 0 -and $profileBCount -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 0 Profile A, 3 Profile B. Got $profileACount A, $profileBCount B"
        $Failed++
    }
    
    Write-TestName "Keygen: Save public keys"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --start-id 0 --save-public --output-dir $TestKeyDir 2>&1
    $pubCount = (Get-ChildItem $TestKeyDir -Filter "*.pub.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $pubCount -eq 2) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 2 public keys, got $pubCount"
        $Failed++
    }
    
    Write-TestName "Keygen: Profile C only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile c --output-dir $TestKeyDir 2>&1
    $profileCCount = (Get-ChildItem $TestKeyDir -Filter "*profile-c.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileCCount -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 Profile C keys, got $profileCCount"
        $Failed++
    }

    Write-TestName "Keygen: Profile D only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile d --output-dir $TestKeyDir 2>&1
    $profileDmlkemCount = (Get-ChildItem $TestKeyDir -Filter "*profile-d-mlkem.pem" -ErrorAction SilentlyContinue).Count
    $profileDx25519Count = (Get-ChildItem $TestKeyDir -Filter "*profile-d-x25519.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileDmlkemCount -eq 3 -and $profileDx25519Count -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 MLKEM and 3 X25519 Profile D files, got $profileDmlkemCount MLKEM, $profileDx25519Count X25519"
        $Failed++
    }

    Write-TestName "Keygen: Profile E only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile e --output-dir $TestKeyDir 2>&1
    $profileEmlkemCount = (Get-ChildItem $TestKeyDir -Filter "*profile-e-mlkem.pem" -ErrorAction SilentlyContinue).Count
    $profileEx25519Count = (Get-ChildItem $TestKeyDir -Filter "*profile-e-x25519.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileEmlkemCount -eq 3 -and $profileEx25519Count -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 MLKEM and 3 X25519 Profile E files, got $profileEmlkemCount MLKEM, $profileEx25519Count X25519"
        $Failed++
    }

    Write-TestName "Keygen: Profile F only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile f --output-dir $TestKeyDir 2>&1
    $profileFmlkemCount = (Get-ChildItem $TestKeyDir -Filter "*profile-f-mlkem.pem" -ErrorAction SilentlyContinue).Count
    $profileFx25519Count = (Get-ChildItem $TestKeyDir -Filter "*profile-f-x25519.pem" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileFmlkemCount -eq 3 -and $profileFx25519Count -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 MLKEM and 3 X25519 Profile F files, got $profileFmlkemCount MLKEM, $profileFx25519Count X25519"
        $Failed++
    }

    Write-TestName "Keygen: Profile G only"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile g --output-dir $TestKeyDir 2>&1
    $profileGMainCount = (Get-ChildItem $TestKeyDir -Filter "*profile-g.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*subscribers*" }).Count
    $profileGSubsCount = (Get-ChildItem $TestKeyDir -Filter "*profile-g-subscribers.json" -ErrorAction SilentlyContinue).Count
    if ($LASTEXITCODE -eq 0 -and $profileGMainCount -eq 3 -and $profileGSubsCount -eq 3) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected 3 Profile G main and 3 subscriber files, got $profileGMainCount main, $profileGSubsCount subscriber"
        $Failed++
    }

    Write-TestName "Inspect: Profile D/E/F/G grouping"
    $Total++
    Remove-Item -Path $TestKeyDir -Recurse -Force -ErrorAction SilentlyContinue
    $result = & $BinaryPath keygen --range 0-2 --profile all --save-public --output-dir $TestKeyDir 2>&1
    $keygenEc = $LASTEXITCODE

    if ($keygenEc -ne 0) {
        Write-Fail "Keygen precondition failed: $result"
        $Failed++
    } else {
        $inspectOutput = & $BinaryPath inspect --key-dir $TestKeyDir --show-public --show-private 2>&1
        $inspectEc = $LASTEXITCODE

        $hasDGroup = $inspectOutput -match "Profile D Keys \(Hybrid ML-KEM-768 \+ X25519\)"
        $hasEGroup = $inspectOutput -match "Profile E Keys \(Nested Hybrid ML-KEM-768 \+ X25519\)"
        $hasFGroup = $inspectOutput -match "Profile F Keys \(Wrapper Hybrid ML-KEM-768 \+ X25519\)"
        $hasGGroup = $inspectOutput -match "Profile G Keys \(Symmetric SUCI\)"
        $hasUnexpectedNA = $inspectOutput -match "profile-[def]-.*\bN/A\b"

        if ($inspectEc -eq 0 -and $hasDGroup -and $hasEGroup -and $hasFGroup -and $hasGGroup -and -not $hasUnexpectedNA) {
            Write-Pass
            $Passed++
        } else {
            Write-Fail "Inspect grouping check failed (exit=$inspectEc, D=$hasDGroup, E=$hasEGroup, F=$hasFGroup, G=$hasGGroup, unexpectedNA=$hasUnexpectedNA)"
            $Failed++
        }
    }
    
    # Cleanup
    if (Test-Path $TestKeyDir) {
        Remove-Item -Path $TestKeyDir -Recurse -Force
    }
}

# UNIT TESTS (Go package unit/integration tests)
if ($Category -in "unit", "all") {
    Write-Header "[UNIT TESTS]"

    Write-TestName "Go tests: pkg/keys"
    $Total++
    $goResult = & go test -v ./pkg/keys 2>&1
    $ec = $LASTEXITCODE
    if ($ec -eq 0) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "pkg/keys tests failed`n$goResult"
        $Failed++
    }

    Write-TestName "Go tests: pkg/suci"
    $Total++
    $goResult = & go test -v ./pkg/suci 2>&1
    $ec = $LASTEXITCODE
    if ($ec -eq 0) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "pkg/suci tests failed`n$goResult"
        $Failed++
    }

    Write-TestName "Go tests: pkg/suciutil"
    $Total++
    $goResult = & go test -v ./pkg/suciutil 2>&1
    $ec = $LASTEXITCODE
    if ($ec -eq 0) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "pkg/suciutil tests failed`n$goResult"
        $Failed++
    }
}

# CONCEAL TESTS
if ($Category -in "conceal", "all") {
    Write-Header "[CONCEAL TESTS]"
    
    # Setup test keys
    $ConcealKeyDir = ".\test-keys-conceal"
    if (Test-Path $ConcealKeyDir) {
        Remove-Item -Path $ConcealKeyDir -Recurse -Force
    }
    & $BinaryPath keygen --start-id 0 --output-dir $ConcealKeyDir 2>&1 | Out-Null
    # Also generate Profile C-G keys for conceal/deconceal tests
    & $BinaryPath keygen --start-id 10 --profile c --output-dir $ConcealKeyDir 2>&1 | Out-Null
    & $BinaryPath keygen --start-id 11 --profile d --output-dir $ConcealKeyDir 2>&1 | Out-Null
    & $BinaryPath keygen --start-id 12 --profile e --output-dir $ConcealKeyDir 2>&1 | Out-Null
    & $BinaryPath keygen --start-id 13 --profile f --output-dir $ConcealKeyDir 2>&1 | Out-Null
    & $BinaryPath keygen --start-id 14 --profile g --output-dir $ConcealKeyDir 2>&1 | Out-Null
    
    Write-TestName "Conceal: NULL-SCHEME"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme null 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
    
    Write-TestName "Conceal: Profile A"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme a --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-310-260-0000-1-0") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
    
    Write-TestName "Conceal: Profile B"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-999991234567890" --scheme b --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-999-991-0000-2-0") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }
    
    Write-TestName "Round-trip: NULL-SCHEME"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme null 2>&1
    $supi = & $BinaryPath deconceal --suci $suci 2>&1
    if ($supi -eq "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $supi"
        $Failed++
    }
    
    Write-TestName "Round-trip: Profile A"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme a --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-310260987654321") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-310260987654321, got: $supi"
        $Failed++
    }
    
    Write-TestName "Round-trip: Profile B"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-999991234567890" --scheme b --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-999991234567890") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-999991234567890, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile C"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme c --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile C"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme c --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-123450123456789, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile D"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile D"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-123450123456789, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile D add17"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir --add-17 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile D add17"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme d --key-dir $ConcealKeyDir --add-17 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-310260987654321") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-310260987654321, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile D add19"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir --add-19 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile D add19"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-999991234567890" --scheme d --key-dir $ConcealKeyDir --add-19 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-999991234567890") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-999991234567890, got: $supi"
        $Failed++
    }

    Write-TestName "Round-trip: Profile D variant cross-check (add17 vs add19 produce different SUCI)"
    $Total++
    $suci17 = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir --add-17 2>&1
    $suci19 = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme d --key-dir $ConcealKeyDir --add-19 2>&1
    if ($suci17 -ne $suci19) {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "add17 and add19 should produce different scheme outputs"
        $Failed++
    }
    
    Write-TestName "Conceal: Invalid SUPI format"
    $Total++
    $result = & $BinaryPath conceal --supi "invalid-format" --scheme null 2>&1
    if ($LASTEXITCODE -eq 1 -and $result -match "error-0102") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Should return error-0102"
        $Failed++
    }
    
    Write-TestName "Conceal: Custom routing indicator"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme null --routing-ind "1234" 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-1234-0-0") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Conceal: Profile E"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme e --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-123-450-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile E"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-123450123456789" --scheme e --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-123450123456789") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-123450123456789, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile F"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme f --key-dir $ConcealKeyDir 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-310-260-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile F"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme f --key-dir $ConcealKeyDir 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-310260987654321") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-310260987654321, got: $supi"
        $Failed++
    }

    Write-TestName "Conceal: Profile G"
    $Total++
    $result = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme g --key-id 14 --key-dir $ConcealKeyDir --subscriber-key-id $ProfileGSubscriberKeyID 2>&1
    if ($LASTEXITCODE -eq 0 -and $result -match "suci-0-310-260-") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Got: $result"
        $Failed++
    }

    Write-TestName "Round-trip: Profile G"
    $Total++
    $suci = & $BinaryPath conceal --supi "imsi-310260987654321" --scheme g --key-id 14 --key-dir $ConcealKeyDir --subscriber-key-id $ProfileGSubscriberKeyID 2>&1
    $supi = & $BinaryPath deconceal --suci $suci --key-dir $ConcealKeyDir 2>&1
    if ($supi -eq "imsi-310260987654321") {
        Write-Pass
        $Passed++
    } else {
        Write-Fail "Expected imsi-310260987654321, got: $supi"
        $Failed++
    }
    
    # Cleanup conceal keys
    if (Test-Path $ConcealKeyDir) {
        Remove-Item -Path $ConcealKeyDir -Recurse -Force
    }
}

# SUMMARY
Write-Host "`n========================================================"
Write-Host "Test Summary:" -ForegroundColor Blue
Write-Host "  Total: $Total"
Write-Host "  Passed: $Passed" -ForegroundColor Green
Write-Host "  Failed: $Failed" -ForegroundColor $(if ($Failed -gt 0) { "Red" } else { "Green" })
$passRate = if ($Total -gt 0) { [math]::Round(($Passed / $Total) * 100, 2) } else { 0 }
Write-Host "  Pass Rate: ${passRate}%"
Write-Host "========================================================`n"

if ($Failed -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed." -ForegroundColor Red
    exit 1
}
