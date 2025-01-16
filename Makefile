.PHONY: all
all: help

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

SOURCE_FILES = $(shell find . -name '*.go' -type f -not -path "./vendor/*")
BUILD_DIR = build
BINARY_NAME = $(BUILD_DIR)/promproxy
IMAGE_REGISTRY ?= ghcr.io
IMAGE_REPOSITORY ?= risingwavelabs/promproxy
IMAGE_TAG ?= $(shell git describe --tags --always --dirty)
IMAGE_REFERENCE = $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY):$(IMAGE_TAG)

.PHONY: build
build: $(BINARY_NAME) ## Build the binary.

$(BINARY_NAME): $(SOURCE_FILES)
	@go build -o $(BINARY_NAME)

.PHONY: clean
clean: ## Clean the build directory.
	@rm -rf $(BUILD_DIR)

.PHONY: fmt
fmt: ## Format the code.
	@go fmt ./...

.PHONY: run
run: $(BINARY_NAME) ## Run the binary.
	@$(BINARY_NAME)

.PHONY: vet
vet: ## Run go vet.
	@go vet ./...

##@ Docker

.PHONY: docker-build
docker-build: ## Build the Docker image.
	@docker build -t $(IMAGE_REFERENCE) . --load

##@ Testing
.PHONY: test
test: ## Run tests.
	@go test -v ./...
