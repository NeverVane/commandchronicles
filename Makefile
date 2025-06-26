# CommandChronicles CLI Makefile
# Cross-platform build automation for ccr binary

# Project metadata
BINARY_NAME := ccr
PACKAGE := github.com/NeverVane/commandchronicles-cli
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE) -s -w"
GCFLAGS := -gcflags "all=-trimpath=$(PWD)"
ASMFLAGS := -asmflags "all=-trimpath=$(PWD)"

# Directories
BUILD_DIR := build
DIST_DIR := dist
SCRIPTS_DIR := scripts

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet

# Platform targets
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	freebsd/amd64 \
	openbsd/amd64 \
	netbsd/amd64

# Default target
.PHONY: all
all: clean deps build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Build for all supported platforms
.PHONY: build-all
build-all: clean
	@echo "Building $(BINARY_NAME) for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		echo "Building for $$platform..."; \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then \
			OUTPUT_NAME=$$OUTPUT_NAME.exe; \
		fi; \
		env GOOS=$$GOOS GOARCH=$$GOARCH \
		$(GOBUILD) $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) -o $$OUTPUT_NAME . || exit 1; \
	done
	@echo "All builds completed successfully!"

# Create release archives
.PHONY: release
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(DIST_DIR)/archives
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		BINARY_PATH=$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then \
			BINARY_PATH=$$BINARY_PATH.exe; \
		fi; \
		ARCHIVE_NAME=$(BINARY_NAME)-$(VERSION)-$$GOOS-$$GOARCH; \
		if [ -f "$$BINARY_PATH" ]; then \
			echo "Creating archive for $$GOOS/$$GOARCH..."; \
			if [ "$$GOOS" = "windows" ]; then \
				cd $(DIST_DIR) && zip archives/$$ARCHIVE_NAME.zip $$(basename $$BINARY_PATH) && cd ..; \
			else \
				cd $(DIST_DIR) && tar -czf archives/$$ARCHIVE_NAME.tar.gz $$(basename $$BINARY_PATH) && cd ..; \
			fi; \
		fi; \
	done
	@echo "Release archives created in $(DIST_DIR)/archives/"

# Development build with debug info
.PHONY: build-dev
build-dev:
	@echo "Building development version..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -race -o $(BUILD_DIR)/$(BINARY_NAME)-dev .

# Install binary to system
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to system..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(BINARY_NAME) installed successfully!"

# Uninstall binary from system
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME) from system..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(BINARY_NAME) uninstalled successfully!"

# Install to user bin directory
.PHONY: install-user
install-user: build
	@echo "Installing $(BINARY_NAME) to user bin..."
	@mkdir -p $$HOME/.local/bin
	@cp $(BUILD_DIR)/$(BINARY_NAME) $$HOME/.local/bin/
	@echo "$(BINARY_NAME) installed to $$HOME/.local/bin/"
	@echo "Make sure $$HOME/.local/bin is in your PATH"

# Dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Update dependencies
.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u all
	$(GOMOD) tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Code formatting
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Code linting
.PHONY: vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Static analysis with golangci-lint
.PHONY: lint
lint:
	@echo "Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Security scan with gosec
.PHONY: security
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Run all quality checks
.PHONY: check
check: fmt vet lint test

# Generate shell completion scripts
.PHONY: completion
completion: build
	@echo "Generating shell completion scripts..."
	@mkdir -p $(BUILD_DIR)/completion
	@$(BUILD_DIR)/$(BINARY_NAME) completion bash > $(BUILD_DIR)/completion/$(BINARY_NAME).bash
	@$(BUILD_DIR)/$(BINARY_NAME) completion zsh > $(BUILD_DIR)/completion/$(BINARY_NAME).zsh
	@$(BUILD_DIR)/$(BINARY_NAME) completion fish > $(BUILD_DIR)/completion/$(BINARY_NAME).fish
	@echo "Completion scripts generated in $(BUILD_DIR)/completion/"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DIST_DIR)
	@rm -f coverage.out coverage.html

# Docker build
.PHONY: docker
docker:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker build -t $(BINARY_NAME):latest .

# Show build info
.PHONY: info
info:
	@echo "Build Information:"
	@echo "  Binary Name: $(BINARY_NAME)"
	@echo "  Package:     $(PACKAGE)"
	@echo "  Version:     $(VERSION)"
	@echo "  Commit:      $(COMMIT)"
	@echo "  Build Date:  $(BUILD_DATE)"
	@echo "  Platforms:   $(PLATFORMS)"

# Development setup
.PHONY: dev-setup
dev-setup: deps
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi
	@echo "Development environment setup complete!"

# Watch for changes and rebuild (requires entr)
.PHONY: watch
watch:
	@echo "Watching for changes... (requires 'entr' to be installed)"
	@find . -name "*.go" | entr -r make build-dev

# Quick development cycle
.PHONY: dev
dev: build-dev test

# Help target
.PHONY: help
help:
	@echo "CommandChronicles CLI Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build for current platform"
	@echo "  build-all      Build for all supported platforms"
	@echo "  build-dev      Build development version with debug info"
	@echo "  release        Create release archives for all platforms"
	@echo "  install        Install binary to /usr/local/bin (requires sudo)"
	@echo "  install-user   Install binary to ~/.local/bin"
	@echo "  uninstall      Remove binary from /usr/local/bin (requires sudo)"
	@echo "  deps           Download and tidy dependencies"
	@echo "  deps-update    Update all dependencies"
	@echo "  test           Run tests"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  bench          Run benchmarks"
	@echo "  fmt            Format code"
	@echo "  vet            Run go vet"
	@echo "  lint           Run golangci-lint"
	@echo "  security       Run security scan with gosec"
	@echo "  check          Run all quality checks"
	@echo "  completion     Generate shell completion scripts"
	@echo "  clean          Clean build artifacts"
	@echo "  docker         Build Docker image"
	@echo "  info           Show build information"
	@echo "  dev-setup      Set up development environment"
	@echo "  watch          Watch for changes and rebuild (requires entr)"
	@echo "  dev            Quick development cycle (build-dev + test)"
	@echo "  help           Show this help message"