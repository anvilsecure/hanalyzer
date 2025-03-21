# Output directory
OUTPUT_DIR = build

# Name of output binary
NAME = "hanalyzer"

# List of target OS and architecture combinations
TARGETS = \
    linux/amd64 \
    linux/arm64 \
    darwin/amd64 \
    darwin/arm64 \
    freebsd/amd64 \
    windows/amd64 \

GO=go
GO_MAJOR = $(shell $(GO) version | awk '{print $$3}' | cut -c 3- | cut -d '.' -f1)
GO_MINOR = $(shell $(GO) version | awk '{print $$3}' | cut -c 3- | cut -d '.' -f2)
MAJOR_SUPPORTED = 1
MINOR_SUPPORTED = 23
DEFAULT_TARGET = $(shell go version | awk '{print $$4}')

all: has_minimum_go create_output_dir
	$(MAKE) build/$(DEFAULT_TARGET)

# Default target
everything: has_minimum_go create_output_dir
ifeq ($(target),)
	$(foreach t,$(TARGETS),$(MAKE) build/$(t);)
else
	$(MAKE) build/$(target)
endif

# Create output directory
create_output_dir:
	@mkdir -p $(OUTPUT_DIR)

has_minimum_go:
	@if [ $(GO_MAJOR) -gt $(MAJOR_SUPPORTED) ]; then \
		exit 0; \
	elif [ $(GO_MINOR) -lt $(MINOR_SUPPORTED) ]; then \
		echo "Golang version is not supported. Please upgrade to at least $(MAJOR_SUPPORTED).$(MINOR_SUPPORTED)"; \
		exit 1; \
	fi

# Build each target
build/%: create_output_dir
	@echo "Building for $*..."
	$(eval GOOS=$(word 1, $(subst /, ,$*)))
	$(eval GOARCH=$(word 2, $(subst /, ,$*)))
	$(eval OUTPUT_NAME=$(NAME)_$(GOOS)_$(GOARCH)$(if $(findstring windows,$(GOOS)),.exe))
	@echo "GOOS=$(GOOS), GOARCH=$(GOARCH), OUTPUT_NAME=$(OUTPUT_NAME)"
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUTPUT_DIR)/$(OUTPUT_NAME) main.go
	@if [ $$? -ne 0 ]; then \
		echo "Failed to build for $(GOOS)/$(GOARCH)"; \
		exit 1; \
	fi

.PHONY: clean
clean:
	@rm -rf $(OUTPUT_DIR)

# Additional targets to build specific OS/Arch combinations
linux/amd64:
	$(MAKE) build/linux/amd64

linux/arm64:
	$(MAKE) build/linux/arm64

darwin/amd64:
	$(MAKE) build/darwin/amd64

darwin/arm64:
	$(MAKE) build/darwin/arm64

freebsd/amd64:
	$(MAKE) build/freebsd/amd64

windows/amd64:
	$(MAKE) build/windows/amd64
