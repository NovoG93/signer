GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOPATH ?= $(shell go env GOPATH)

# --- Detect Target OS ---
ifeq ($(GOOS),windows)
    TARGET_OS := windows
else ifeq ($(OS),Windows_NT)
    TARGET_OS := windows
else
    TARGET_OS := unix
endif

# --- Output Variables ---
BIN_NAME = signer
SRC_DIR = src

ifeq ($(TARGET_OS),windows)
    EXT := .exe
else
    EXT :=
endif
OUT_PATH = $(CURDIR)/$(BIN_NAME)/$(BIN_NAME)$(EXT)

.PHONY: all build clean test coverage docker envtest

# Envtest binaries path (auto-detected if setup-envtest is available)
ENVTEST_ASSETS ?= $(shell $(GOPATH)/bin/setup-envtest use -p path 2>/dev/null || echo "")

all: build

build:
	@echo "Building for GOOS=$(GOOS) GOARCH=$(GOARCH) (Defaulting to host if empty)"
	@mkdir -p $(dir $(OUT_PATH))
	cd $(SRC_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUT_PATH) .

test:
	cd $(SRC_DIR) && KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS)" go test -v ./...

envtest: ## Install envtest binaries
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
	$(GOPATH)/bin/setup-envtest use

coverage:
	cd $(SRC_DIR) && go test -v -coverprofile=../coverage.out ./...
	cd $(SRC_DIR) && go tool cover -html=../coverage.out


docker:
	docker build --build-arg AARCH=$(GOARCH) -t novog93/signer:latest .

# Cleanup must handle both Unix and Windows executables
clean:
	@echo "Cleaning artifacts..."
	-rm -f $(OUT_PATH)
	-rm -f coverage.out