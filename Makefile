# Output directory
OUTPUT_DIR = build

# List of target OS and architecture combinations
TARGETS = \
    linux/amd64 \
    linux/386 \
    linux/arm \
    linux/arm64 \
    darwin/amd64 \
    darwin/arm64 \
    freebsd/amd64 \
    freebsd/386 \
    windows/amd64 \
    windows/386

# Default target
all: create_output_dir
ifeq ($(target),)
	$(foreach t,$(TARGETS),$(MAKE) build/$(t);)
else
	$(MAKE) build/$(target)
endif

# Create output directory
create_output_dir:
	@mkdir -p $(OUTPUT_DIR)

# Build each target
build/%: create_output_dir
	@echo "Building for $*..."
	$(eval GOOS=$(word 1, $(subst /, ,$*)))
	$(eval GOARCH=$(word 2, $(subst /, ,$*)))
	$(eval OUTPUT_NAME=saphanalyzer_$(GOOS)_$(GOARCH)$(if $(findstring windows,$(GOOS)),.exe))
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

linux/386:
	$(MAKE) build/linux/386

linux/arm:
	$(MAKE) build/linux/arm

linux/arm64:
	$(MAKE) build/linux/arm64

darwin/amd64:
	$(MAKE) build/darwin/amd64

darwin/arm64:
	$(MAKE) build/darwin/arm64

freebsd/amd64:
	$(MAKE) build/freebsd/amd64

freebsd/386:
	$(MAKE) build/freebsd/386

windows/amd64:
	$(MAKE) build/windows/amd64

windows/386:
	$(MAKE) build/windows/386
