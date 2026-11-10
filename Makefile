GO ?= go
GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck
PYTHON ?= python3
GO_LICENSES ?= go-licenses

APP_NAME := xcertm
BUILD_DIR ?= dist
VERSION ?= dev
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOARCH)
GOARM ?= 7
ARCH_LABEL := $(if $(filter arm,$(GOARCH)),armv$(GOARM),$(GOARCH))
PACKAGE_NAME := $(APP_NAME)_$(patsubst v%,%,$(VERSION))_$(GOOS)_$(ARCH_LABEL)

.PHONY: all fmt-check vet lint test race vulncheck ci build package releases clean version linux-amd64 linux-386 linux-arm linux-arm64

all: build

fmt-check:
	@files="$$($(GOFMT) -l .)" || exit $$?; if [ -n "$$files" ]; then echo "$$files"; exit 1; fi

vet:
	$(GO) vet -mod=readonly ./...

lint:
	$(GOLANGCI_LINT) run --timeout=5m

test:
	$(GO) test -mod=readonly -count=1 -coverprofile=coverage.out ./...

race:
	CGO_ENABLED=1 $(GO) test -mod=readonly -race -count=1 ./...

vulncheck:
	$(GOVULNCHECK) ./...

ci: fmt-check vet lint test race

build:
	@mkdir -p "$(BUILD_DIR)/$(PACKAGE_NAME)"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) $(GO) build -mod=readonly -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o "$(BUILD_DIR)/$(PACKAGE_NAME)/$(APP_NAME)" ./cmd/xcertm

package: build
	$(PYTHON) scripts/package_licenses.py --go "$(GO)" --scanner "$(GO_LICENSES)" --output "$(BUILD_DIR)/$(PACKAGE_NAME)"
	cp -Rf README.md docs examples "$(BUILD_DIR)/$(PACKAGE_NAME)/"
	tar -czf "$(BUILD_DIR)/$(PACKAGE_NAME).tar.gz" -C "$(BUILD_DIR)/$(PACKAGE_NAME)" "$(APP_NAME)" LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt README.md docs examples

# Local convenience only: CI never calls this multiarchitecture target.
releases:
	@set -e; for arch in amd64 386 arm arm64; do $(MAKE) package GOOS=linux GOARCH=$$arch GOARM=7; done

linux-amd64 linux-386 linux-arm linux-arm64:
	$(MAKE) build GOOS=linux GOARCH=$(patsubst linux-%,%,$@) GOARM=7

clean:
	rm -rf -- "$(BUILD_DIR)"

version:
	@echo "Version: $(VERSION)"
