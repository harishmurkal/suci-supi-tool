.PHONY: all build test clean run install help

APP_NAME := suci-supi-tool
VERSION := 2.3.0
BUILD_DIR := build
CMD_DIR := ./cmd/suci-tool
GO_FILES := $(shell find . -name '*.go' -type f)

# Colors for output
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m
COLOR_CYAN := \033[36m

all: clean test build

help:
	@echo "$(COLOR_CYAN)SUCI-SUPI Tool - Makefile Commands$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)─────────────────────────────────────────$(COLOR_RESET)"
	@echo "  $(COLOR_GREEN)make build$(COLOR_RESET)        - Build the application"
	@echo "  $(COLOR_GREEN)make test$(COLOR_RESET)         - Run tests"
	@echo "  $(COLOR_GREEN)make test-coverage$(COLOR_RESET) - Run tests with coverage"
	@echo "  $(COLOR_GREEN)make run$(COLOR_RESET)          - Run the application"
	@echo "  $(COLOR_GREEN)make install$(COLOR_RESET)      - Install to GOPATH/bin"
	@echo "  $(COLOR_GREEN)make clean$(COLOR_RESET)        - Clean build artifacts"
	@echo "  $(COLOR_GREEN)make deps$(COLOR_RESET)         - Download dependencies"
	@echo "  $(COLOR_GREEN)make build-all$(COLOR_RESET)    - Build for all platforms"
	@echo "  $(COLOR_GREEN)make help$(COLOR_RESET)         - Show this help message"

build:
	@echo "$(COLOR_CYAN)Building $(APP_NAME)...$(COLOR_RESET)"
	@go build -o $(APP_NAME) $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Build complete: ./$(APP_NAME)$(COLOR_RESET)"

build-all:
	@echo "$(COLOR_CYAN)Building for all platforms...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Windows (amd64)$(COLOR_RESET)"
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Linux (amd64)$(COLOR_RESET)"
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ macOS (amd64)$(COLOR_RESET)"
	@GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ macOS (arm64)$(COLOR_RESET)"
	@echo "$(COLOR_CYAN)Build artifacts in: $(BUILD_DIR)/$(COLOR_RESET)"

test:
	@echo "$(COLOR_CYAN)Running tests...$(COLOR_RESET)"
	@go test -v ./...
	@echo "$(COLOR_GREEN)✓ All tests passed$(COLOR_RESET)"

test-coverage:
	@echo "$(COLOR_CYAN)Running tests with coverage...$(COLOR_RESET)"
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_GREEN)✓ Coverage report generated: coverage.html$(COLOR_RESET)"

test-bench:
	@echo "$(COLOR_CYAN)Running benchmarks...$(COLOR_RESET)"
	@go test -bench=. -benchmem ./...

run:
	@go run $(CMD_DIR) help

install:
	@echo "$(COLOR_CYAN)Installing $(APP_NAME)...$(COLOR_RESET)"
	@go install $(CMD_DIR)
	@echo "$(COLOR_GREEN)✓ Installed to GOPATH/bin$(COLOR_RESET)"

clean:
	@echo "$(COLOR_CYAN)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -f $(APP_NAME)
	@rm -f $(APP_NAME).exe
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@echo "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)"

deps:
	@echo "$(COLOR_CYAN)Downloading dependencies...$(COLOR_RESET)"
	@go mod download
	@go mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies ready$(COLOR_RESET)"

tidy:
	@echo "$(COLOR_CYAN)Tidying go.mod...$(COLOR_RESET)"
	@go mod tidy
	@echo "$(COLOR_GREEN)✓ go.mod is tidy$(COLOR_RESET)"

fmt:
	@echo "$(COLOR_CYAN)Formatting code...$(COLOR_RESET)"
	@go fmt ./...
	@echo "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)"

vet:
	@echo "$(COLOR_CYAN)Running go vet...$(COLOR_RESET)"
	@go vet ./...
	@echo "$(COLOR_GREEN)✓ No issues found$(COLOR_RESET)"

lint: fmt vet

# Example test cases
test-null-scheme:
	@echo "$(COLOR_CYAN)Testing NULL-SCHEME...$(COLOR_RESET)"
	@./$(APP_NAME) deconceal --suci "suci-0-123-45-012-0-0-1032547698" --verbose

test-invalid:
	@echo "$(COLOR_CYAN)Testing invalid SUCI...$(COLOR_RESET)"
	@./$(APP_NAME) deconceal --suci "invalid-suci-format" || true

version:
	@./$(APP_NAME) version
