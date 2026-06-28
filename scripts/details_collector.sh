#!/usr/bin/env bash
set -u

# details_collector.sh
# Runs a comprehensive sequence of suci-supi-tool commands and logs output.
# Covers:
#   - keygen / inspect (profiles A–G, including hybrid two-file D/E/F keys and JSON Profile G)
#   - conceal + deconceal: NULL (TBCD), A/B/C, Profile D baseline + --add-17 + --add-19, E, F, G
#   - optional second Profile F round-trip with an alternate SUPI (see EXTRA_SUPI_F)
#   - loadgen: 27 runs (9 scheme/variant rows × 3 modes). Profile D = baseline + -add-17 + -add-19
#     (distinct wire formats; no duplicate CLI lines — same structure as details_collector.ps1).
#   - Go benchmarks: pkg/suci and pkg/suciutil
#
# This script is integration / CLI smoke + perf capture — not a replacement for `go test ./...`
# or ./scripts/regression_tests.sh.
#
# Security level for profiles C–G: --security-level 3 (default) or 5;
# same as suci-tool -security-level (see also SECURITY_LEVEL / DETAILS_SECURITY_LEVEL).

cd "$(dirname "$0")/.."

BINARY="./build/suci-supi-tool-linux-amd64"
KEY_DIR="${KEY_DIR:-./keys}"
# Second SUPI used only for an extra Profile F conceal/deconceal sample (regression-style IMSI).
EXTRA_SUPI_F="${EXTRA_SUPI_F:-imsi-310260987654321}"
PROFILE_G_SUBSCRIBER_KEY_ID="${PROFILE_G_SUBSCRIBER_KEY_ID:-0011223344}"

GREEN="\e[32m"
CYAN="\e[36m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

usage() {
    cat <<'EOF'
USAGE
    ./scripts/details_collector.sh [OPTIONS]

DESCRIPTION
    Runs a comprehensive sequence of suci-supi-tool commands (keygen, inspect,
    conceal/deconceal, loadgen, benchmarks) and writes all output to a
    timestamped log file.

    A SUPI value is required for most conceal/deconceal round-trip tests.
    The script also runs NULL-SCHEME with the same SUPI and an extra Profile F
    round-trip with EXTRA_SUPI_F (default imsi-310260987654321).

    Profile D: baseline, Solution #17 (--add-17), and Solution #19 (--add-19).
    Profiles E (nested hybrid) and F (wrapper hybrid) are exercised the same
    way as in regression_tests.sh / regression_tests.ps1.

OPTIONS
    --supi <value>           SUPI to use for conceal tests (e.g. imsi-123450123456789)
    --loadgen-n <n>         loadgen -n (default: 100000 if not set via env)
    --loadgen-warmup <n>     loadgen -warmup (default: 1000)
    --loadgen-concurrency <n>
                             loadgen -concurrency (default: 1)
    --security-level <3|5>  security level for profiles C–G: 3 (default) or 5
    --help, -h               Show this help message and exit

    Precedence for each loadgen setting: command-line option, then environment
    variable, then default.
    Precedence for security level: --security-level, then SECURITY_LEVEL or
    DETAILS_SECURITY_LEVEL, then 3.

ENVIRONMENT
    SUPI             Alternative to --supi. --supi wins when both are set.
    KEY_DIR          Key output directory for keygen/conceal/deconceal (default: ./keys)
    EXTRA_SUPI_F     Alternate SUPI for an extra Profile F round-trip
                     (default: imsi-310260987654321)
    PROFILE_G_SUBSCRIBER_KEY_ID
                     Subscriber key ID used for Profile G conceal/loadgen
                     (default: 0011223344)
    GOROOT           Path to Go installation (used for benchmark step).
                     If not set, the script tries to find 'go' in PATH.
    LOADGEN_N        loadgen -n when --loadgen-n is omitted (default: 100000)
    LOADGEN_WARMUP   loadgen -warmup when --loadgen-warmup is omitted (default: 1000)
    LOADGEN_CONCURRENCY
                     loadgen -concurrency when --loadgen-concurrency is omitted (default: 1)
    SECURITY_LEVEL, DETAILS_SECURITY_LEVEL
                     security level for keygen/conceal/loadgen on C–G (3 or 5) when
                     --security-level is omitted

EXAMPLES
    # Pass SUPI as a flag
    ./scripts/details_collector.sh --supi imsi-123450123456789

    # Pass SUPI via environment variable
    export SUPI='imsi-310260987654321'
    ./scripts/details_collector.sh

    # Show this help
    ./scripts/details_collector.sh --help

    # Faster loadgen via flags (recommended)
    ./scripts/details_collector.sh --supi imsi-123450123456789 \
        --loadgen-n 5000 --loadgen-warmup 100 --loadgen-concurrency 2

    # ML-KEM-1024 (security level 5) for PQC / hybrid profiles
    ./scripts/details_collector.sh --supi imsi-123450123456789 --security-level 5

    # Same via environment (used only for options you omit on the command line)
    export LOADGEN_N=5000 LOADGEN_WARMUP=100 LOADGEN_CONCURRENCY=2
    ./scripts/details_collector.sh --supi imsi-123450123456789
EOF
}

# --- Parse arguments ---
while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h|help)
            usage
            exit 0
            ;;
        --supi)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}ERROR: --supi requires a value.${RESET}"
                usage
                exit 1
            fi
            SUPI="$2"
            shift 2
            ;;
        --loadgen-n)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}ERROR: --loadgen-n requires a value.${RESET}"
                usage
                exit 1
            fi
            OPT_LOADGEN_N="$2"
            shift 2
            ;;
        --loadgen-warmup)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}ERROR: --loadgen-warmup requires a value.${RESET}"
                usage
                exit 1
            fi
            OPT_LOADGEN_WARMUP="$2"
            shift 2
            ;;
        --loadgen-concurrency)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}ERROR: --loadgen-concurrency requires a value.${RESET}"
                usage
                exit 1
            fi
            OPT_LOADGEN_CONCURRENCY="$2"
            shift 2
            ;;
        --security-level)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}ERROR: --security-level requires a value (3 or 5).${RESET}"
                usage
                exit 1
            fi
            OPT_SECURITY_LEVEL="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${RESET}"
            usage
            exit 1
            ;;
    esac
done

# loadgen: CLI overrides environment; defaults 100000 / 1000 / 1
LOADGEN_N="${OPT_LOADGEN_N:-${LOADGEN_N:-100000}}"
LOADGEN_WARMUP="${OPT_LOADGEN_WARMUP:-${LOADGEN_WARMUP:-1000}}"
LOADGEN_CONCURRENCY="${OPT_LOADGEN_CONCURRENCY:-${LOADGEN_CONCURRENCY:-1}}"

# Security level for profiles C–G (matches suci-tool -security-level)
SECURITY_LEVEL="${OPT_SECURITY_LEVEL:-${SECURITY_LEVEL:-${DETAILS_SECURITY_LEVEL:-3}}}"
case "$SECURITY_LEVEL" in
    3|5) ;;
    *)
        echo -e "${RED}ERROR: --security-level / SECURITY_LEVEL must be 3 or 5, got: ${SECURITY_LEVEL}${RESET}"
        exit 1
        ;;
esac

# --- Validate prerequisites ---
if [ ! -x "$BINARY" ]; then
    echo -e "${RED}ERROR: Binary not found or not executable: ${BINARY}${RESET}"
    echo "       Run ./scripts/build.sh first."
    exit 1
fi

if [ -z "${SUPI:-}" ]; then
    echo -e "${RED}ERROR: SUPI is required but was not provided.${RESET}"
    echo ""
    echo "  Provide it as a flag:       ./scripts/details_collector.sh --supi imsi-123450123456789"
    echo "  Or as an environment var:    export SUPI='imsi-123450123456789' && ./scripts/details_collector.sh"
    echo ""
    echo "  Run ./scripts/details_collector.sh --help for full usage."
    exit 1
fi

# --- Go toolchain discovery (for benchmark step) ---
if [ -n "${GOROOT:-}" ] && [ -x "${GOROOT}/bin/go" ]; then
    export PATH="${GOROOT}/bin:$PATH"
fi
GO_BIN=""
if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
fi

LOG="details_collector_$(date -u +%Y%m%dT%H%M%SZ).log"

echo -e "${GREEN}Starting details collection${RESET}"
echo "  SUPI:         $SUPI"
echo "  EXTRA_SUPI_F: $EXTRA_SUPI_F"
echo "  KEY_DIR:      $KEY_DIR"
echo "  LOADGEN_N:            $LOADGEN_N"
echo "  LOADGEN_WARMUP:       $LOADGEN_WARMUP"
echo "  LOADGEN_CONCURRENCY:  $LOADGEN_CONCURRENCY"
echo "  SECURITY_LEVEL (C–G): $SECURITY_LEVEL"
echo "  PROFILE_G_SUBSCRIBER_KEY_ID: $PROFILE_G_SUBSCRIBER_KEY_ID"
echo "  Binary:       $BINARY"
echo "  Log:          $LOG"
[ -n "$GO_BIN" ] && echo "  Go:     $GO_BIN" || echo -e "  Go:     ${YELLOW}not found (benchmark step will be skipped)${RESET}"
echo ""

run_cmd() {
    printf "\n>>> %s\n" "$*" | tee -a "$LOG"
    "$@" >>"$LOG" 2>&1
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo -e "${RED}<<< EXIT:$rc for: $*${RESET}" | tee -a "$LOG"
    else
        echo -e "${GREEN}<<< OK: $*${RESET}" | tee -a "$LOG"
    fi
}

conceal_and_deconceal() {
    printf "\n>>> %s\n" "$*" | tee -a "$LOG"

    local output
    output=$("$@" 2>&1)
    local rc=$?

    printf "%s\n" "$output" >>"$LOG"

    if [ $rc -ne 0 ]; then
        echo -e "${RED}<<< EXIT:$rc for: $*${RESET}" | tee -a "$LOG"
    else
        echo -e "${GREEN}<<< OK: $*${RESET}" | tee -a "$LOG"
    fi

    local suci
    suci=$(printf "%s\n" "$output" | sed -n 's/.*SUCI:[[:space:]]*\(suci[^[:space:]]*\).*/\1/p' | head -n1)

    if [ -n "$suci" ]; then
        echo "  Extracted SUCI: $suci" | tee -a "$LOG"
        run_cmd "$BINARY" deconceal -verbose -security-level "$SECURITY_LEVEL" -key-dir "$KEY_DIR" -suci "$suci"
    else
        echo -e "  ${YELLOW}No SUCI extracted for: $*${RESET}" | tee -a "$LOG"
    fi
}

# ========================================================================
# 1. KEYGEN — generate keys for all profiles
# ========================================================================
echo -e "${CYAN}[1/6] Key generation (profiles a-g, IDs 1-10)...${RESET}"
for profile in a b c d e f g; do
    run_cmd "$BINARY" keygen -profile "$profile" -range 1-10 -save-public -output-dir "$KEY_DIR" -security-level "$SECURITY_LEVEL" -verbose
done

# ========================================================================
# 2. INSPECT — directory-level + individual key files
# ========================================================================
echo -e "\n${CYAN}[2/6] Key inspection...${RESET}"
run_cmd "$BINARY" inspect -key-dir "$KEY_DIR" -show-public -show-private

for profile in a b c; do
    run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-${profile}.pem" -show-public -show-private
    run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-${profile}.pub.pem" -show-public -show-private
done

for profile in d e f; do
    for comp in mlkem x25519; do
        run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-${profile}-${comp}.pem" -show-public -show-private
        run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-${profile}-${comp}.pub.pem" -show-public -show-private
    done
done

run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-g.json" -show-private
run_cmd "$BINARY" inspect -key-file "${KEY_DIR}/hn-key-10-profile-g-subscribers.json" -show-private

# ========================================================================
# 3. CONCEAL + DECONCEAL round-trips (NULL, A–C, D baseline + add-17 + add-19, E, F, G)
# ========================================================================
echo -e "\n${CYAN}[3/6] Conceal/deconceal round-trips...${RESET}"

echo -e "\n${YELLOW}--- NULL-SCHEME (TBCD MSIN in scheme output, no encryption) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -supi "$SUPI" -scheme null -verbose

echo -e "\n${YELLOW}--- Profile A / B / C (ECIES + PQC Profile C) ---${RESET}" | tee -a "$LOG"
for scheme in a b c; do
    if [ "$scheme" = c ]; then
        conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme "$scheme" -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose
    else
        conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme "$scheme" -supi "$SUPI" -verbose
    fi
done

echo -e "\n${YELLOW}--- Profile D: baseline (KEM || X25519 || CTR|| KMAC) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme d -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose

echo -e "\n${YELLOW}--- Profile D: add-17 (variant 0x01, 16-byte nonce, KMAC) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme d -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose --add-17

echo -e "\n${YELLOW}--- Profile D: add-19 (variant 0x02, 12-byte nonce, AES-GCM + 16-byte tag) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme d -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose --add-19

echo -e "\n${YELLOW}--- Profile E (nested hybrid ML-KEM + X25519) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme e -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose

echo -e "\n${YELLOW}--- Profile F (wrapper hybrid ML-KEM + X25519) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme f -supi "$SUPI" -security-level "$SECURITY_LEVEL" -verbose

echo -e "\n${YELLOW}--- Profile F (alternate SUPI: ${EXTRA_SUPI_F}) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme f -supi "$EXTRA_SUPI_F" -security-level "$SECURITY_LEVEL" -verbose

echo -e "\n${YELLOW}--- Profile G (symmetric) ---${RESET}" | tee -a "$LOG"
conceal_and_deconceal "$BINARY" conceal -key-dir "$KEY_DIR" -key-id 1 -routing-ind 0000 -scheme g -supi "$SUPI" -subscriber-key-id "$PROFILE_G_SUBSCRIBER_KEY_ID" -security-level "$SECURITY_LEVEL" -verbose

# ========================================================================
# 4. LOADGEN — 9 cases × 3 modes = 27 runs (Profile D baseline + add-17 + add-19 explicit)
# ========================================================================
echo -e "\n${CYAN}[4/6] Loadgen benchmarks...${RESET}"
echo -e "\n${YELLOW}--- Loadgen (schemes × modes; Profile D = baseline, add-17, add-19) ---${RESET}" | tee -a "$LOG"

run_loadgen_case() {
    local scheme=$1
    shift
    for mode in parse-only decrypt-only end-to-end; do
        if [ "$scheme" = "g" ]; then
            run_cmd ./scripts/run_time_with_rss.sh "$BINARY" loadgen \
                -concurrency "$LOADGEN_CONCURRENCY" -n "$LOADGEN_N" -warmup "$LOADGEN_WARMUP" \
                -scheme "$scheme" "$@" -mode "$mode" -subscriber-key-id "$PROFILE_G_SUBSCRIBER_KEY_ID" -security-level "$SECURITY_LEVEL"
        else
            run_cmd ./scripts/run_time_with_rss.sh "$BINARY" loadgen \
                -concurrency "$LOADGEN_CONCURRENCY" -n "$LOADGEN_N" -warmup "$LOADGEN_WARMUP" \
                -scheme "$scheme" "$@" -mode "$mode" -security-level "$SECURITY_LEVEL"
        fi
    done
}

run_loadgen_case a
run_loadgen_case b
run_loadgen_case c
run_loadgen_case d
run_loadgen_case d --add-17
run_loadgen_case d --add-19
run_loadgen_case e
run_loadgen_case f
run_loadgen_case g

# ========================================================================
# 5. GO BENCHMARKS
# ========================================================================
echo -e "\n${CYAN}[5/6] Go package benchmarks...${RESET}"

if [ -n "$GO_BIN" ]; then
    run_cmd "$GO_BIN" test ./pkg/suci -run '^$' -bench . -benchmem
    run_cmd "$GO_BIN" test ./pkg/suciutil -run '^$' -bench . -benchmem
else
    echo -e "  ${YELLOW}Skipped: 'go' not found. Set GOROOT or install Go.${RESET}" | tee -a "$LOG"
fi

# ========================================================================
# 6. SUMMARY
# ========================================================================
echo -e "\n${CYAN}[6/6] Done${RESET}"
echo -e "${GREEN}Completed. Full log: $LOG${RESET}"
