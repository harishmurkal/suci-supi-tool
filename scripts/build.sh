#!/bin/bash
# Build script for SUCI-SUPI Tool
# Builds for multiple platforms

VERSION="2.3.0"
APP_NAME="suci-supi-tool"

echo "Building $APP_NAME version $VERSION..."
echo ""

# Ensure we're in the project root (one level up from scripts/)
cd "$(dirname "$0")/.."

# Clean previous builds
rm -rf ./build
mkdir -p ./build

# Build for Windows (amd64)
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o "./build/$APP_NAME-windows-amd64.exe" ./cmd/suci-tool
if [ $? -eq 0 ]; then
    echo "✓ Windows build successful"
else
    echo "✗ Windows build failed"
    exit 1
fi

# Build for Linux (amd64)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o "./build/$APP_NAME-linux-amd64" ./cmd/suci-tool
if [ $? -eq 0 ]; then
    echo "✓ Linux build successful"
else
    echo "✗ Linux build failed"
    exit 1
fi

# Build for macOS (amd64)
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o "./build/$APP_NAME-darwin-amd64" ./cmd/suci-tool
if [ $? -eq 0 ]; then
    echo "✓ macOS (Intel) build successful"
else
    echo "✗ macOS build failed"
    exit 1
fi

echo ""
echo "Build Summary:"
echo "─────────────────────────────────────────"
ls -lh ./build | awk '{if(NR>1) print $9, "-", $5}'

echo ""
echo "All builds completed successfully!"
echo "Binaries are available in: ./build/"
