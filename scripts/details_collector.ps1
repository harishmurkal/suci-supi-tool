# details_collector.ps1 - Windows counterpart to scripts/details_collector.sh
# Runs keygen, inspect, conceal/deconceal (NULL, A-C, D baseline/add-17/add-19, E, F, G),
# loadgen (27 runs: each scheme × 3 modes; Profile D = baseline + add-17 + add-19 as separate rows — no duplicate CLI lines),
# and Go benchmarks (pkg/suci, pkg/suciutil).
# For unit/regression tests use: go test ./...  and .\scripts\regression_tests.ps1 (this script does not run them).
#
# Usage:
#   .\scripts\details_collector.ps1 -Supi imsi-123450123456789
#   .\scripts\details_collector.ps1 -Supi imsi-... -SecurityLevel 5
#   .\scripts\details_collector.ps1 -Supi imsi-... -LoadgenN 5000 -LoadgenWarmup 100 -LoadgenConcurrency 2
#   $env:SUPI = 'imsi-310260987654321'; .\scripts\details_collector.ps1
#   .\scripts\details_collector.ps1 -Help   # or positional: .\scripts\details_collector.ps1 help
#
# Environment (optional):
#   SUPI, KEY_DIR (default .\keys), EXTRA_SUPI_F (default imsi-310260987654321), GOROOT
#   LOADGEN_N, LOADGEN_WARMUP, LOADGEN_CONCURRENCY - used when matching parameters omitted
#   DETAILS_LOADGEN_N, DETAILS_LOADGEN_WARMUP - legacy env aliases for N / warmup
#   SECURITY_LEVEL (or DETAILS_SECURITY_LEVEL) - security level for profiles C-G: 3 (default) or 5
#   PROFILE_G_SUBSCRIBER_KEY_ID - subscriber key ID for Profile-G conceal/loadgen (default 0011223344)
#
# Precedence per loadgen setting: parameter > LOADGEN_* (or DETAILS_* for N/warmup) > default.
#
# Coverage: this script is integration / CLI smoke + perf capture — not a replacement for `go test ./...`.
# Loadgen runs 27 unique (scheme × Profile D wire variant × mode) invocations; Profile D baseline and
# add-17/add-19 are distinct workloads (no duplicate command lines).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $Supi = "",

    [Parameter(Mandatory = $false)]
    [string] $LoadgenN = "",

    [Parameter(Mandatory = $false)]
    [string] $LoadgenWarmup = "",

    [Parameter(Mandatory = $false)]
    [string] $LoadgenConcurrency = "",

    [Parameter(Mandatory = $false)]
    [string] $SecurityLevel = "",

    [Parameter(Mandatory = $false)]
    [switch] $Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Show-Usage {
    @"
USAGE
    .\scripts\details_collector.ps1 [-Supi <imsi-...>]
        [-LoadgenN <n>] [-LoadgenWarmup <n>] [-LoadgenConcurrency <n>]
        [-SecurityLevel <3|5>] [-Help]
    .\scripts\details_collector.ps1 help
        (positional "help" / -h / --help / -help / /? also show this text)

DESCRIPTION
    Same coverage as details_collector.sh: logs all command output to a timestamped file.
    SUPI may be passed as -Supi or environment variable SUPI (-Supi wins).

PARAMETERS
    -LoadgenN            loadgen -n (default 100000 if not set via parameter or env)
    -LoadgenWarmup       loadgen -warmup (default 1000)
    -LoadgenConcurrency  loadgen -concurrency (default 1)
    -SecurityLevel        For profiles C-G: 3 (default) or 5

    Precedence for each loadgen value: parameter, then environment, then default.
    Precedence for security level: -SecurityLevel, then SECURITY_LEVEL or DETAILS_SECURITY_LEVEL, then 3.

ENVIRONMENT
    KEY_DIR       Key directory (default: .\keys)
    EXTRA_SUPI_F  Alternate SUPI for extra Profile F round-trip
    GOROOT        Prepended to PATH for `go` if GOROOT\bin\go.exe exists
    LOADGEN_N, LOADGEN_WARMUP, LOADGEN_CONCURRENCY
                  Used when -LoadgenN / -LoadgenWarmup / -LoadgenConcurrency are omitted
    DETAILS_LOADGEN_N, DETAILS_LOADGEN_WARMUP
                  Legacy aliases for N / warmup when LOADGEN_N / LOADGEN_WARMUP are not set
    SECURITY_LEVEL, DETAILS_SECURITY_LEVEL
                  security level for keygen/conceal/loadgen on C-G (3 or 5) when -SecurityLevel omitted
    PROFILE_G_SUBSCRIBER_KEY_ID
                  subscriber key ID for Profile-G conceal/loadgen (default: 0011223344)

NOTE
    Loadgen: 9 scheme rows × 3 modes = 27 invocations (a–c, d baseline, d+add-17, d+add-19, e–g).
    That is not a duplicate of the same command: Profile D appears three times with different wire variants.
    Loadgen runs the binary directly (no Linux run_time_with_rss.sh).

    Tool output is UTF-8 (Unicode borders). This script captures it correctly; use Windows
    Terminal (or chcp 65001) so the console can display those characters. The log file is UTF-8.
"@
}

if ($Help -or $Supi -in @("help", "-h", "--help", "-help", "/?")) {
    Show-Usage
    exit 0
}

Set-Location (Split-Path $PSScriptRoot -Parent)

# Go prints UTF-8 box-drawing; Windows PowerShell 5.1 often decodes native stdout as ANSI → mojibake (e.g. Γòö).
# Capture via temp files + UTF-8 read is reliable. chcp/Console encoding helps consoles and PS 7+.
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding $false
try { chcp 65001 | Out-Null } catch { }
try {
    [Console]::OutputEncoding = $script:Utf8NoBom
    [Console]::InputEncoding = $script:Utf8NoBom
} catch { }
$OutputEncoding = $script:Utf8NoBom

$BinaryPath = Join-Path (Get-Location) "build\suci-supi-tool-windows-amd64.exe"
$KeyDir = if ($env:KEY_DIR) { $env:KEY_DIR } else { ".\keys" }
$ExtraSupiF = if ($env:EXTRA_SUPI_F) { $env:EXTRA_SUPI_F } else { "imsi-310260987654321" }
$ProfileGSubscriberKeyID = if ($env:PROFILE_G_SUBSCRIBER_KEY_ID) { $env:PROFILE_G_SUBSCRIBER_KEY_ID } else { "0011223344" }

if (-not [string]::IsNullOrWhiteSpace($LoadgenN)) {
    $loadgenN = [int]$LoadgenN
} elseif (-not [string]::IsNullOrWhiteSpace($env:LOADGEN_N)) {
    $loadgenN = [int]$env:LOADGEN_N
} elseif (-not [string]::IsNullOrWhiteSpace($env:DETAILS_LOADGEN_N)) {
    $loadgenN = [int]$env:DETAILS_LOADGEN_N
} else {
    $loadgenN = 100000
}

if (-not [string]::IsNullOrWhiteSpace($LoadgenWarmup)) {
    $loadgenWarmup = [int]$LoadgenWarmup
} elseif (-not [string]::IsNullOrWhiteSpace($env:LOADGEN_WARMUP)) {
    $loadgenWarmup = [int]$env:LOADGEN_WARMUP
} elseif (-not [string]::IsNullOrWhiteSpace($env:DETAILS_LOADGEN_WARMUP)) {
    $loadgenWarmup = [int]$env:DETAILS_LOADGEN_WARMUP
} else {
    $loadgenWarmup = 1000
}

if (-not [string]::IsNullOrWhiteSpace($LoadgenConcurrency)) {
    $loadgenConc = [int]$LoadgenConcurrency
} elseif (-not [string]::IsNullOrWhiteSpace($env:LOADGEN_CONCURRENCY)) {
    $loadgenConc = [int]$env:LOADGEN_CONCURRENCY
} else {
    $loadgenConc = 1
}

if (-not [string]::IsNullOrWhiteSpace($SecurityLevel)) {
    $secLevel = $SecurityLevel.Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:SECURITY_LEVEL)) {
    $secLevel = $env:SECURITY_LEVEL.Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:DETAILS_SECURITY_LEVEL)) {
    $secLevel = $env:DETAILS_SECURITY_LEVEL.Trim()
} else {
    $secLevel = "3"
}
if ($secLevel -ne "3" -and $secLevel -ne "5") {
    Write-Host "ERROR: -SecurityLevel / SECURITY_LEVEL must be 3 or 5, got: $secLevel" -ForegroundColor Red
    Show-Usage
    exit 1
}

$supiValue = $Supi
if (-not $supiValue) { $supiValue = $env:SUPI }
if (-not $supiValue) {
    Write-Host "ERROR: SUPI is required. Use -Supi or set `$env:SUPI" -ForegroundColor Red
    Show-Usage
    exit 1
}

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    Write-Host "ERROR: Binary not found: $BinaryPath" -ForegroundColor Red
    Write-Host "       Build with: go build -o build\suci-supi-tool-windows-amd64.exe .\cmd\suci-tool"
    exit 1
}

if ($env:GOROOT -and (Test-Path (Join-Path $env:GOROOT "bin\go.exe"))) {
    $env:PATH = "$(Join-Path $env:GOROOT 'bin');$env:PATH"
}

Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue

$goExe = $null
if (Get-Command go -ErrorAction SilentlyContinue) {
    $goExe = (Get-Command go).Source
}

$ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$LogPath = Join-Path (Get-Location) "details_collector_$ts.log"

function Write-LogAppend {
    param([string] $Message)
    [System.IO.File]::AppendAllText($LogPath, $Message + [Environment]::NewLine, $script:Utf8NoBom)
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Exe,
        [string[]] $Arguments = @()
    )
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $code = 0
        if ($null -ne $proc.ExitCode) { $code = $proc.ExitCode }
        $stdout = ""
        if ((Get-Item -LiteralPath $outFile).Length -gt 0) {
            $stdout = [System.IO.File]::ReadAllText($outFile, $script:Utf8NoBom)
        }
        $stderr = ""
        if ((Get-Item -LiteralPath $errFile).Length -gt 0) {
            $stderr = [System.IO.File]::ReadAllText($errFile, $script:Utf8NoBom)
        }
        $merged = if ($stderr) { "$stdout`n$stderr" } else { $stdout }
        return [pscustomobject]@{ ExitCode = $code; Text = $merged }
    } finally {
        Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
    }
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Exe,
        [string[]] $Arguments = @()
    )
    $display = "$Exe $($Arguments -join ' ')"
    Write-LogAppend ""
    Write-LogAppend ">>> $display"
    Write-Host ">>> $display"
    $result = Invoke-ExternalCommand -Exe $Exe -Arguments $Arguments
    $code = $result.ExitCode
    $text = $result.Text
    if ($text) {
        Write-LogAppend $text
        Write-Host $text
    }
    if ($code -ne 0) {
        Write-LogAppend "<<< EXIT:$code for: $display"
        Write-Host "<<< EXIT:$code for: $display" -ForegroundColor Red
    } else {
        Write-LogAppend "<<< OK: $display"
        Write-Host "<<< OK: $display" -ForegroundColor Green
    }
    return $code
}

function Invoke-ConcealAndDeconceal {
    param([string[]] $ConcealArgs)

    $display = "$BinaryPath $($ConcealArgs -join ' ')"
    Write-LogAppend ""
    Write-LogAppend ">>> $display"
    Write-Host ">>> $display"
    $result = Invoke-ExternalCommand -Exe $BinaryPath -Arguments $ConcealArgs
    $code = $result.ExitCode
    $text = $result.Text
    if ($text) {
        Write-LogAppend $text
        Write-Host $text
    }

    if ($code -ne 0) {
        Write-LogAppend "<<< EXIT:$code for: $display"
        Write-Host "<<< EXIT:$code for: $display" -ForegroundColor Red
        return
    }
    Write-LogAppend "<<< OK: $display"
    Write-Host "<<< OK: $display" -ForegroundColor Green

    $m = [regex]::Match($text, 'SUCI:\s*(suci-\S+)')
    if (-not $m.Success) {
        Write-LogAppend "  No SUCI extracted for: $display"
        Write-Host "  No SUCI extracted for: $display" -ForegroundColor Yellow
        return
    }
    $suci = $m.Groups[1].Value
    Write-LogAppend "  Extracted SUCI: $suci"
    Write-Host "  Extracted SUCI: $suci"
    [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @(
        "deconceal", "-verbose", "-security-level", $secLevel, "-key-dir", $KeyDir, "-suci", $suci
    ))
}

Write-Host "Starting details collection" -ForegroundColor Green
Write-Host "  SUPI:         $supiValue"
Write-Host "  EXTRA_SUPI_F: $ExtraSupiF"
Write-Host "  KEY_DIR:      $KeyDir"
Write-Host "  LOADGEN_N:            $loadgenN"
Write-Host "  LOADGEN_WARMUP:       $loadgenWarmup"
Write-Host "  LOADGEN_CONCURRENCY:  $loadgenConc"
Write-Host "  SECURITY_LEVEL (C-G): $secLevel"
Write-Host "  PROFILE_G_SUBSCRIBER_KEY_ID: $ProfileGSubscriberKeyID"
Write-Host "  Binary:       $BinaryPath"
Write-Host "  Log:          $LogPath"
if ($goExe) { Write-Host "  Go:           $goExe" } else { Write-Host "  Go:           (not found; benchmarks skipped)" -ForegroundColor Yellow }
Write-Host ""

# [1/6] Keygen
Write-Host "[1/6] Key generation (profiles a-g, IDs 1-10)..." -ForegroundColor Cyan
foreach ($profileName in @("a", "b", "c", "d", "e", "f", "g")) {
    [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @(
        "keygen", "-profile", $profileName, "-range", "1-10", "-save-public", "-output-dir", $KeyDir, "-security-level", $secLevel, "-verbose"
    ))
}

# [2/6] Inspect
Write-Host "`n[2/6] Key inspection..." -ForegroundColor Cyan
[void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-dir", $KeyDir, "-show-public", "-show-private"))

foreach ($profileName in @("a", "b", "c")) {
    $priv = Join-Path $KeyDir "hn-key-10-profile-$profileName.pem"
    $pub = Join-Path $KeyDir "hn-key-10-profile-$profileName.pub.pem"
    [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", $priv, "-show-public", "-show-private"))
    [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", $pub, "-show-public", "-show-private"))
}

foreach ($profileName in @("d", "e", "f")) {
    foreach ($comp in @("mlkem", "x25519")) {
        $priv = Join-Path $KeyDir "hn-key-10-profile-$profileName-$comp.pem"
        $pub = Join-Path $KeyDir "hn-key-10-profile-$profileName-$comp.pub.pem"
        [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", $priv, "-show-public", "-show-private"))
        [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", $pub, "-show-public", "-show-private"))
    }
}
[void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", (Join-Path $KeyDir "hn-key-10-profile-g.json"), "-show-private"))
[void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments @("inspect", "-key-file", (Join-Path $KeyDir "hn-key-10-profile-g-subscribers.json"), "-show-private"))

# [3/6] Conceal / deconceal
Write-Host "`n[3/6] Conceal/deconceal round-trips..." -ForegroundColor Cyan

Write-LogAppend "`n--- NULL-SCHEME (TBCD) ---"
Write-Host "`n--- NULL-SCHEME (TBCD) ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @("conceal", "-supi", $supiValue, "-scheme", "null", "-verbose")

Write-LogAppend "`n--- Profile A / B / C ---"
Write-Host "`n--- Profile A / B / C ---" -ForegroundColor Yellow
foreach ($scheme in @("a", "b", "c")) {
    $cargs = @(
        "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", $scheme, "-supi", $supiValue
    )
    if ($scheme -eq "c") {
        $cargs += @("-security-level", $secLevel)
    }
    $cargs += "-verbose"
    Invoke-ConcealAndDeconceal -ConcealArgs $cargs
}

Write-LogAppend "`n--- Profile D baseline ---"
Write-Host "`n--- Profile D baseline ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "d", "-supi", $supiValue, "-security-level", $secLevel, "-verbose"
)

Write-LogAppend "`n--- Profile D add-17 ---"
Write-Host "`n--- Profile D add-17 ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "d", "-supi", $supiValue, "-security-level", $secLevel, "-verbose", "--add-17"
)

Write-LogAppend "`n--- Profile D add-19 ---"
Write-Host "`n--- Profile D add-19 ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "d", "-supi", $supiValue, "-security-level", $secLevel, "-verbose", "--add-19"
)

Write-LogAppend "`n--- Profile E ---"
Write-Host "`n--- Profile E ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "e", "-supi", $supiValue, "-security-level", $secLevel, "-verbose"
)

Write-LogAppend "`n--- Profile F ---"
Write-Host "`n--- Profile F ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "f", "-supi", $supiValue, "-security-level", $secLevel, "-verbose"
)

Write-LogAppend "`n--- Profile F (alternate SUPI) ---"
Write-Host "`n--- Profile F (alternate SUPI) ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "f", "-supi", $ExtraSupiF, "-security-level", $secLevel, "-verbose"
)

Write-LogAppend "`n--- Profile G ---"
Write-Host "`n--- Profile G ---" -ForegroundColor Yellow
Invoke-ConcealAndDeconceal -ConcealArgs @(
    "conceal", "-key-dir", $KeyDir, "-key-id", "1", "-routing-ind", "0000", "-scheme", "g", "-supi", $supiValue, "-subscriber-key-id", $ProfileGSubscriberKeyID, "-security-level", $secLevel, "-verbose"
)

# [4/6] Loadgen (no run_time_with_rss on Windows)
# 9 rows × 3 modes = 27 runs; Profile D baseline + add-17 + add-19 are distinct (not duplicates).
Write-Host "`n[4/6] Loadgen..." -ForegroundColor Cyan
Write-LogAppend "`n--- Loadgen (schemes × modes; Profile D = baseline, add-17, add-19) ---"

$loadgenCases = @(
    @{ Scheme = "a"; DExtra = @() },
    @{ Scheme = "b"; DExtra = @() },
    @{ Scheme = "c"; DExtra = @() },
    @{ Scheme = "d"; DExtra = @() },
    @{ Scheme = "d"; DExtra = @("--add-17") },
    @{ Scheme = "d"; DExtra = @("--add-19") },
    @{ Scheme = "e"; DExtra = @() },
    @{ Scheme = "f"; DExtra = @() },
    @{ Scheme = "g"; DExtra = @() }
)

foreach ($case in $loadgenCases) {
    foreach ($mode in @("parse-only", "decrypt-only", "end-to-end")) {
        $args = @(
            "loadgen",
            "-concurrency", "$loadgenConc",
            "-n", "$loadgenN",
            "-warmup", "$loadgenWarmup",
            "-scheme", $case.Scheme
        )
        if ($case.DExtra.Count -gt 0) {
            $args += $case.DExtra
        }
        $args += @("-mode", $mode)
        if ($case.Scheme -eq "g") {
            $args += @("-subscriber-key-id", $ProfileGSubscriberKeyID)
        }
        $args += @("-security-level", $secLevel)
        [void](Invoke-LoggedCommand -Exe $BinaryPath -Arguments $args)
    }
}

# [5/6] Go benchmarks
Write-Host "`n[5/6] Go package benchmarks..." -ForegroundColor Cyan
if ($goExe) {
    [void](Invoke-LoggedCommand -Exe $goExe -Arguments @("test", "./pkg/suci", "-run", "^$", "-bench", ".", "-benchmem"))
    [void](Invoke-LoggedCommand -Exe $goExe -Arguments @("test", "./pkg/suciutil", "-run", "^$", "-bench", ".", "-benchmem"))
} else {
    Write-LogAppend "  Skipped: go not found."
    Write-Host "  Skipped: go not found." -ForegroundColor Yellow
}

Write-Host "`n[6/6] Done" -ForegroundColor Cyan
Write-Host "Completed. Full log: $LogPath" -ForegroundColor Green
