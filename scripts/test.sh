#!/usr/bin/env bash
# Run unit tests and benchmarks for SUCI-SUPI Tool (Linux/macOS/WSL).
# Parity with scripts/test.ps1 on Windows: clean GOOS/GOARCH, then:
#   go test -v -cover ./...  &&  go test ./pkg/suci -bench=. -benchmem
# Usage: ./scripts/test.sh

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

GREEN="\e[32m"
CYAN="\e[36m"
RED="\e[31m"
RESET="\e[0m"

echo -e "${GREEN}Running SUCI-SUPI Tool Tests...${RESET}\n"

# Clear any lingering environment variables from cross-compilation
unset GOOS || true
unset GOARCH || true

# If a custom GOROOT is provided and contains a go binary, prefer it.
if [ -n "${GOROOT:-}" ] && [ -x "${GOROOT}/bin/go" ]; then
  export PATH="${GOROOT}/bin:$PATH"
  echo -e "${CYAN}Using go from GOROOT: ${GOROOT}${RESET}"
fi

# Show helpful Go-related env vars when set
for v in GOROOT GOPROXY GONOSUMDB GOPATH; do
  if [ -n "${!v:-}" ]; then
    echo -e "${CYAN}$v=${!v}${RESET}"
  fi
done

run_go() {
  # Run `go` with passed arguments. If `go` not available, fall back to Docker golang image.
  if command -v go >/dev/null 2>&1; then
    go "$@"
    return $?
  fi

  if command -v docker >/dev/null 2>&1; then
    echo -e "${CYAN}go not found in PATH — running inside golang Docker image${RESET}"
    docker run --rm -v "$DIR":/src -w /src golang:1.20 bash -lc "unset GOOS GOARCH; go $*"
    return $?
  fi

  if command -v podman >/dev/null 2>&1; then
    echo -e "${CYAN}go not found in PATH — running inside golang container via podman${RESET}"
    PODMAN_TMP=$(mktemp -d /tmp/podman-xdg-XXXXXX)
    export XDG_RUNTIME_DIR="$PODMAN_TMP"
    mkdir -p "$XDG_RUNTIME_DIR" || true
    # try running with rootless-friendly flags
    podman run --rm --userns=keep-id --security-opt label=disable -v "$DIR":/src -w /src --env XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" docker.io/library/golang:1.20 bash -lc "unset GOOS GOARCH; go $*"
    ec=$?
    rm -rf "$PODMAN_TMP" || true
    if [ $ec -ne 0 ]; then
      echo -e "${RED}Podman run failed (exit $ec). If you're running rootless podman, ensure it's configured or install Go locally.${RESET}"
    fi
    return $ec
  fi

  # Try downloading a temporary Go toolchain to run tests locally (no install)
  install_go_local
  if command -v go >/dev/null 2>&1; then
    go "$@"
    return $?
  fi

  echo -e "${RED}Error: 'go' is not installed, no container runtime available, and automatic Go download failed. Install Go (https://golang.org/dl/) or enable Docker/Podman.${RESET}"
  return 127
}


install_go_local() {
  # Download and use a temporary local Go toolchain in a temp dir.
  if [ -n "${GO_FORCE_LOCAL:-}" ]; then
    :
  fi
  if command -v go >/dev/null 2>&1; then
    return 0
  fi
  echo -e "${CYAN}Attempting to download temporary Go toolchain...${RESET}"
  GO_VERSION=${GO_VERSION:-1.20.13}
  UNAME=$(uname -s)
  if [ "$UNAME" != "Linux" ]; then
    echo -e "${RED}Local downloader only supports Linux hosts.${RESET}"
    return 1
  fi
  MACHINE=$(uname -m)
  case "$MACHINE" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo -e "${RED}Unsupported architecture: $MACHINE${RESET}"; return 1 ;;
  esac

  TARFILE="go${GO_VERSION}.linux-${ARCH}.tar.gz"
  URL="https://dl.google.com/go/${TARFILE}"
  TMPDIR=$(mktemp -d /tmp/go-download-XXXXXX)
  GOTAR="$TMPDIR/$TARFILE"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$GOTAR" || { echo -e "${RED}Failed to download $URL${RESET}"; rm -rf "$TMPDIR"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$GOTAR" "$URL" || { echo -e "${RED}Failed to download $URL${RESET}"; rm -rf "$TMPDIR"; return 1; }
  else
    echo -e "${RED}Neither curl nor wget available to download Go.${RESET}"
    rm -rf "$TMPDIR"
    return 1
  fi

  tar -C "$TMPDIR" -xzf "$GOTAR" || { echo -e "${RED}Failed to extract Go tarball${RESET}"; rm -rf "$TMPDIR"; return 1; }
  export PATH="$TMPDIR/go/bin:$PATH"
  # Verify
  if command -v go >/dev/null 2>&1; then
    echo -e "${CYAN}Using temporary Go from $TMPDIR/go${RESET}"
    # ensure cleanup on exit
    _GOTMP_CLEANUP="$TMPDIR"
    trap 'rm -rf "${_GOTMP_CLEANUP:-}" 2>/dev/null || true' EXIT
    return 0
  fi
  rm -rf "$TMPDIR"
  return 1
}

echo -e "${CYAN}Running unit tests with coverage...${RESET}"
if run_go test -v -cover ./...; then
  echo -e "\n${GREEN}All tests passed successfully!${RESET}"
else
  echo -e "\n${RED}Some tests failed!${RESET}"
  exit 1
fi

echo -e "\n${CYAN}Running benchmarks...${RESET}"
# Matches test.ps1: benchmarks are informational; do not fail the script if they error.
run_go test ./pkg/suci -bench=. -benchmem || true

echo -e "\n${GREEN}Test run complete!${RESET}"
