#!/usr/bin/env bash
# Regression Test Suite for SUCI-SUPI Tool (Linux/Bash; use WSL or Git Bash on Windows)
#
#   ./scripts/regression_tests.sh --help

set -u

# Ensure we're in the project root (one level up from scripts/)
cd "$(dirname "$0")/.."

# If a custom GOROOT is provided and contains a go binary, prefer it.
if [ -n "${GOROOT:-}" ] && [ -x "${GOROOT}/bin/go" ]; then
  export PATH="${GOROOT}/bin:$PATH"
fi

GREEN="\e[32m"
RED="\e[31m"
CYAN="\e[36m"
BLUE="\e[34m"
YELLOW="\e[33m"
RESET="\e[0m"

usage() {
  cat <<'EOF'
SUCI-SUPI Tool — regression test suite

Usage:
  regression_tests.sh [CATEGORY]
  regression_tests.sh --help | -h

Categories (default: all):
  all         Run every category below
  sanity      version/help and basic deconceal smoke tests
  cli         --help, --version, invalid command, missing flags
  functional  NULL-scheme IMSI / MCC-MNC cases
  error       invalid SUCI, short cryptograms, error codes
  keygen      hn key generation + inspect D/E/F/G grouping (creates ./test-keys-regression)
  conceal     conceal + round-trip (creates ./test-keys-conceal)
  unit        go test ./pkg/keys ./pkg/suci ./pkg/suciutil (needs go in PATH)

Environment:
  BINARY_PATH   Path to the suci-supi-tool binary (must be executable)
                Default: ./build/suci-supi-tool-linux-amd64
  PROFILE_G_SUBSCRIBER_KEY_ID
                Subscriber key ID used for Profile G conceal tests
                Default: 0011223344
  GOROOT        If set and GOROOT/bin/go exists, that go is prepended to PATH

Prerequisites:
  Build a Linux binary first, then run this script on Linux or WSL.
  Example (from repo root):  make build-linux   # or your project’s build target

Examples:
  ./scripts/regression_tests.sh
  ./scripts/regression_tests.sh sanity
  BINARY_PATH=./build/my-tool ./scripts/regression_tests.sh cli
EOF
}

VALID_CATEGORIES=(all sanity functional error cli keygen conceal unit)

category_is_valid() {
  local c="$1"
  local v
  for v in "${VALID_CATEGORIES[@]}"; do
    [[ "$c" == "$v" ]] && return 0
  done
  return 1
}

case "${1-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

CATEGORY=${1:-all}
if ! category_is_valid "$CATEGORY"; then
  echo -e "${RED}Unknown category:${RESET} ${YELLOW}$CATEGORY${RESET}" >&2
  echo -e "Valid: ${CYAN}${VALID_CATEGORIES[*]}${RESET}" >&2
  echo "Run: regression_tests.sh --help" >&2
  exit 2
fi

BINARY_PATH=${BINARY_PATH:-"./build/suci-supi-tool-linux-amd64"}
PROFILE_G_SUBSCRIBER_KEY_ID=${PROFILE_G_SUBSCRIBER_KEY_ID:-0011223344}

PASSED=0
FAILED=0
TOTAL=0
TEST_KEY_DIR="./test-keys-regression"

write_pass() { echo -e "${GREEN}[PASS]${RESET}"; }
write_fail() { echo -e "${RED}[FAIL] - $1${RESET}"; }
write_testname() { printf "  %s... " "$1"; }
write_header() { echo -e "\n${CYAN}$1${RESET}"; }

if [ ! -f "$BINARY_PATH" ]; then
  echo -e "${RED}Error:${RESET} Binary not found: ${YELLOW}$BINARY_PATH${RESET}"
  echo "Build the Linux binary, or set BINARY_PATH. See: ./scripts/regression_tests.sh --help"
  exit 1
fi
if [ ! -x "$BINARY_PATH" ]; then
  echo -e "${RED}Error:${RESET} Binary is not executable: ${YELLOW}$BINARY_PATH${RESET}"
  echo "chmod +x \"$BINARY_PATH\"  or build from a Linux/WSL environment."
  exit 1
fi

echo -e "\n========================================================"
echo -e "    SUCI-SUPI Tool - Regression Test Suite"
echo -e "========================================================"
echo "Binary: $BINARY_PATH"
echo "Category: $CATEGORY\n"

run_cmd() {
  local out
  out=$("$@" 2>&1)
  local ec=$?
  printf "%s" "$out"
  return $ec
}

# SANITY TESTS
if [[ "$CATEGORY" == "sanity" || "$CATEGORY" == "all" ]]; then
  write_header "[SANITY TESTS]"

  write_testname "Version command"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" version)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ Version ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Exit: $ec"; FAILED=$((FAILED+1))
  fi

  write_testname "Help command"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" help)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ USAGE ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Exit: $ec"; FAILED=$((FAILED+1))
  fi

  write_testname "No arguments (shows help)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ USAGE ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Exit: $ec"; FAILED=$((FAILED+1))
  fi

  write_testname "NULL-SCHEME deconceal"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-123-45-012-0-0-1032547698")
  ec=$?
  if [[ $ec -eq 0 && "$result" == *imsi-123450123456789* ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi
fi

# CLI TESTS
if [[ "$CATEGORY" == "cli" || "$CATEGORY" == "all" ]]; then
  write_header "[CLI TESTS]"

  write_testname "Help flag (--help)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" --help)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ USAGE ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Exit: $ec"; FAILED=$((FAILED+1))
  fi

  write_testname "Version flag (--version)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" --version)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ Version ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Exit: $ec"; FAILED=$((FAILED+1))
  fi

  write_testname "Invalid command"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" invalid-command)
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ "Unknown command" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should fail with error"; FAILED=$((FAILED+1))
  fi

  write_testname "Deconceal without --suci"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal)
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ required ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should fail"; FAILED=$((FAILED+1))
  fi
fi

# FUNCTIONAL TESTS
if [[ "$CATEGORY" == "functional" || "$CATEGORY" == "all" ]]; then
  write_header "[FUNCTIONAL TESTS]"

  write_testname "NULL-SCHEME: Valid IMSI"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-123-45-012-0-0-1032547698")
  ec=$?
  if [[ $ec -eq 0 && "$result" == "imsi-123450123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "NULL-SCHEME: 15-digit MSIN"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-001-01-000-0-0-10325476981032f4")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0206 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should reject >15 digit IMSI"; FAILED=$((FAILED+1))
  fi

  write_testname "NULL-SCHEME: MCC 310 (USA)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-310-410-000-0-0-21436587f9")
  ec=$?
  if [[ $ec -eq 0 && "$result" == "imsi-310410123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "NULL-SCHEME: 3-digit MNC"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-001-001-000-0-0-21436587f9")
  ec=$?
  if [[ $ec -eq 0 && "$result" == "imsi-001001123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi
fi

# ERROR TESTS
if [[ "$CATEGORY" == "error" || "$CATEGORY" == "all" ]]; then
  write_header "[ERROR HANDLING TESTS]"

  write_testname "Invalid SUCI format"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "invalid-suci")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0101 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should return error-0101"; FAILED=$((FAILED+1))
  fi

  write_testname "SUCI without prefix"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "0-123-45-012-0-0-1032547698")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0101 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should return error-0101"; FAILED=$((FAILED+1))
  fi

  write_testname "Invalid scheme ID (treated as NULL)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-123-45-012-0-99-1032547698")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ imsi- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Tool treats invalid schemes as NULL"; FAILED=$((FAILED+1))
  fi

  write_testname "Profile A with short cryptogram"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-123-45-012-0-1-0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should return error"; FAILED=$((FAILED+1))
  fi

  write_testname "Profile B with short cryptogram"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" deconceal --suci "suci-0-123-45-012-0-2-0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should return error"; FAILED=$((FAILED+1))
  fi
fi

# KEYGEN TESTS
if [[ "$CATEGORY" == "keygen" || "$CATEGORY" == "all" ]]; then
  write_header "[KEYGEN TESTS]"

  rm -rf "$TEST_KEY_DIR"

  write_testname "Keygen: Single key pair (Profile A+B)"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" keygen --start-id 1 --output-dir "$TEST_KEY_DIR")
  ec=$?
  keyFileA="$TEST_KEY_DIR/hn-key-1-profile-a.pem"
  keyFileB="$TEST_KEY_DIR/hn-key-1-profile-b.pem"
  if [[ $ec -eq 0 && -f "$keyFileA" && -f "$keyFileB" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Keys not generated"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Range 0-5 (12 keys)"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-5 --output-dir "$TEST_KEY_DIR")
  ec=$?
  keyCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $keyCount -eq 12 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 12 keys, got $keyCount"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile A only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile a --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileACount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-a.pem" 2>/dev/null | wc -l)
  profileBCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-b.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileACount -eq 3 && $profileBCount -eq 0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 Profile A, 0 Profile B. Got $profileACount A, $profileBCount B"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile B only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile b --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileACount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-a.pem" 2>/dev/null | wc -l)
  profileBCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-b.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileACount -eq 0 && $profileBCount -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 0 Profile A, 3 Profile B. Got $profileACount A, $profileBCount B"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Save public keys"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --start-id 0 --save-public --output-dir "$TEST_KEY_DIR")
  ec=$?
  pubCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*.pub.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $pubCount -eq 2 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 2 public keys, got $pubCount"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile C only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile c --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileCCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-c.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileCCount -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 Profile C keys, got $profileCCount"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile D only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile d --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileDmlkemCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-d-mlkem.pem" 2>/dev/null | wc -l)
  profileDx25519Count=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-d-x25519.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileDmlkemCount -eq 3 && $profileDx25519Count -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 MLKEM and 3 X25519 Profile D files, got $profileDmlkemCount MLKEM, $profileDx25519Count X25519"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile E only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile e --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileEmlkemCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-e-mlkem.pem" 2>/dev/null | wc -l)
  profileEx25519Count=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-e-x25519.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileEmlkemCount -eq 3 && $profileEx25519Count -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 MLKEM and 3 X25519 Profile E files, got $profileEmlkemCount MLKEM, $profileEx25519Count X25519"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile F only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile f --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileFmlkemCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-f-mlkem.pem" 2>/dev/null | wc -l)
  profileFx25519Count=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-f-x25519.pem" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileFmlkemCount -eq 3 && $profileFx25519Count -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 MLKEM and 3 X25519 Profile F files, got $profileFmlkemCount MLKEM, $profileFx25519Count X25519"; FAILED=$((FAILED+1))
  fi

  write_testname "Keygen: Profile G only"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile g --output-dir "$TEST_KEY_DIR")
  ec=$?
  profileGMainCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-g.json" ! -name "*subscribers*" 2>/dev/null | wc -l)
  profileGSubsCount=$(find "$TEST_KEY_DIR" -maxdepth 1 -type f -name "*profile-g-subscribers.json" 2>/dev/null | wc -l)
  if [[ $ec -eq 0 && $profileGMainCount -eq 3 && $profileGSubsCount -eq 3 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected 3 Profile G main and 3 subscriber files, got $profileGMainCount main, $profileGSubsCount subscriber"; FAILED=$((FAILED+1))
  fi

  # Matches regression_tests.ps1: keygen profile all + inspect D/E/F/G grouping.
  write_testname "Inspect: Profile D/E/F/G grouping"
  TOTAL=$((TOTAL+1))
  rm -rf "$TEST_KEY_DIR"
  result=$(run_cmd "$BINARY_PATH" keygen --range 0-2 --profile all --save-public --output-dir "$TEST_KEY_DIR")
  ec=$?
  if [[ $ec -ne 0 ]]; then
    write_fail "Keygen precondition failed: $result"
    FAILED=$((FAILED+1))
  else
    inspect_output=$(run_cmd "$BINARY_PATH" inspect --key-dir "$TEST_KEY_DIR" --show-public --show-private)
    inspect_ec=$?
    if [[ $inspect_ec -eq 0 ]] \
      && echo "$inspect_output" | grep -qF "Profile D Keys (Hybrid ML-KEM-768 + X25519)" \
      && echo "$inspect_output" | grep -qF "Profile E Keys (Nested Hybrid ML-KEM-768 + X25519)" \
      && echo "$inspect_output" | grep -qF "Profile F Keys (Wrapper Hybrid ML-KEM-768 + X25519)" \
      && echo "$inspect_output" | grep -qF "Profile G Keys (Symmetric SUCI)" \
      && ! echo "$inspect_output" | grep -qE 'profile-[def]-.*N/A'; then
      write_pass; PASSED=$((PASSED+1))
    else
      write_fail "Inspect grouping check failed (inspect exit=$inspect_ec)"
      FAILED=$((FAILED+1))
    fi
  fi

  rm -rf "$TEST_KEY_DIR"
fi

# UNIT TESTS (Go package unit/integration tests)
if [[ "$CATEGORY" == "unit" || "$CATEGORY" == "all" ]]; then
  write_header "[UNIT TESTS]"

  if ! command -v go >/dev/null 2>&1; then
    echo -e "  ${RED}Skipping unit tests: 'go' not found in PATH. Set GOROOT or install Go.${RESET}"
  else
    write_testname "Go tests: pkg/keys"
    TOTAL=$((TOTAL+1))
    result=$(go test -v ./pkg/keys 2>&1)
    ec=$?
    if [[ $ec -eq 0 ]]; then
      write_pass; PASSED=$((PASSED+1))
    else
      write_fail "pkg/keys tests failed: $result"; FAILED=$((FAILED+1))
    fi

    write_testname "Go tests: pkg/suci"
    TOTAL=$((TOTAL+1))
    result=$(go test -v ./pkg/suci 2>&1)
    ec=$?
    if [[ $ec -eq 0 ]]; then
      write_pass; PASSED=$((PASSED+1))
    else
      write_fail "pkg/suci tests failed: $result"; FAILED=$((FAILED+1))
    fi

    write_testname "Go tests: pkg/suciutil"
    TOTAL=$((TOTAL+1))
    result=$(go test -v ./pkg/suciutil 2>&1)
    ec=$?
    if [[ $ec -eq 0 ]]; then
      write_pass; PASSED=$((PASSED+1))
    else
      write_fail "pkg/suciutil tests failed: $result"; FAILED=$((FAILED+1))
    fi
  fi
fi

# CONCEAL TESTS
if [[ "$CATEGORY" == "conceal" || "$CATEGORY" == "all" ]]; then
  write_header "[CONCEAL TESTS]"

  CONCEAL_KEY_DIR="./test-keys-conceal"
  rm -rf "$CONCEAL_KEY_DIR"
  "$BINARY_PATH" keygen --start-id 0 --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1
  # Also generate Profile C-G keys for conceal/deconceal tests
  "$BINARY_PATH" keygen --start-id 10 --profile c --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1
  "$BINARY_PATH" keygen --start-id 11 --profile d --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1
  "$BINARY_PATH" keygen --start-id 12 --profile e --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1
  "$BINARY_PATH" keygen --start-id 13 --profile f --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1
  "$BINARY_PATH" keygen --start-id 14 --profile g --output-dir "$CONCEAL_KEY_DIR" >/dev/null 2>&1

  write_testname "Conceal: NULL-SCHEME"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme null)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile A"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme a --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-310-260-0000-1-0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile B"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-999991234567890" --scheme b --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-999-991-0000-2-0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: NULL-SCHEME"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme null 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-123450123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile A"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme a --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-310260987654321" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-310260987654321, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile B"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-999991234567890" --scheme b --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-999991234567890" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-999991234567890, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile C"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme c --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile C"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme c --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-123450123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-123450123456789, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile D"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile D"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-123450123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-123450123456789, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile D add17"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-17)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile D add17"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-17 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-310260987654321" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-310260987654321, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile D add19"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-19)
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile D add19"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-999991234567890" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-19 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-999991234567890" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-999991234567890, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile D variant cross-check (add17 vs add19 produce different SUCI)"
  TOTAL=$((TOTAL+1))
  suci17=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-17 2>&1)
  suci17=$(printf "%s" "$suci17" | tr -d '\r\n')
  suci19=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme d --key-dir "$CONCEAL_KEY_DIR" --add-19 2>&1)
  suci19=$(printf "%s" "$suci19" | tr -d '\r\n')
  if [[ "$suci17" != "$suci19" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "add17 and add19 should produce different scheme outputs"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Invalid SUPI format"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "invalid-format" --scheme null)
  ec=$?
  if [[ $ec -eq 1 && "$result" =~ error-0102 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Should return error-0102"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Custom routing indicator"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme null --routing-ind "1234")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450-1234-0-0 ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile E"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme e --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-123-450- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile E"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-123450123456789" --scheme e --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-123450123456789" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-123450123456789, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile F"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme f --key-dir "$CONCEAL_KEY_DIR")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-310-260- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile F"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme f --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-310260987654321" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-310260987654321, got: $supi"; FAILED=$((FAILED+1))
  fi

  write_testname "Conceal: Profile G"
  TOTAL=$((TOTAL+1))
  result=$(run_cmd "$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme g --key-id 14 --key-dir "$CONCEAL_KEY_DIR" --subscriber-key-id "$PROFILE_G_SUBSCRIBER_KEY_ID")
  ec=$?
  if [[ $ec -eq 0 && "$result" =~ suci-0-310-260- ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Got: $result"; FAILED=$((FAILED+1))
  fi

  write_testname "Round-trip: Profile G"
  TOTAL=$((TOTAL+1))
  suci=$("$BINARY_PATH" conceal --supi "imsi-310260987654321" --scheme g --key-id 14 --key-dir "$CONCEAL_KEY_DIR" --subscriber-key-id "$PROFILE_G_SUBSCRIBER_KEY_ID" 2>&1)
  suci=$(printf "%s" "$suci" | tr -d '\r\n')
  supi=$("$BINARY_PATH" deconceal --suci "$suci" --key-dir "$CONCEAL_KEY_DIR" 2>&1)
  supi=$(printf "%s" "$supi" | tr -d '\r\n')
  if [[ "$supi" == "imsi-310260987654321" ]]; then
    write_pass; PASSED=$((PASSED+1))
  else
    write_fail "Expected imsi-310260987654321, got: $supi"; FAILED=$((FAILED+1))
  fi

  rm -rf "$CONCEAL_KEY_DIR"
fi

# SUMMARY
echo -e "\n========================================================"
echo -e "Test Summary:" "${BLUE}"
echo "  Total: $TOTAL"
echo -e "  Passed: ${GREEN}$PASSED${RESET}"
echo -e "  Failed: ${FAILED}" "${RESET}"
if [ $TOTAL -gt 0 ]; then
  passRate=$(awk "BEGIN { printf \"%.2f\", ($PASSED/$TOTAL)*100 }")
else
  passRate=0
fi
echo "  Pass Rate: ${passRate}%"
echo -e "========================================================\n"

if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${RESET}"
  exit 0
else
  echo -e "${RED}Some tests failed.${RESET}"
  exit 1
fi
