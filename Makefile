VERSION=v0.2.9

OUT_DIR=dist
YEAR?=$(shell date +"%Y")

CLI_NAME?=cf
IMAGE_REPOSITORY?=quay.io
IMAGE_NAMESPACE?=codefresh

RUNTIME_DEF_URL="https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
ADD_CLUSTER_DEF_URL="https://github.com/codefresh-io/csdp-official/add-cluster/kustomize"

# when developing, point this to your local clone of csdp-official
DEV_RUNTIME_DEF_URL="https://raw.githubusercontent.com/codefresh-io/csdp-official/stable/csdp/hybrid/basic/runtime.yaml"
DEV_ADD_CLUSTER_DEF_URL="https://github.com/codefresh-io/csdp-official/add-cluster/kustomize" # specify dev branch using ?ref=<branch> here if you want to test a change

CLI_SRCS := $(shell find . -name '*.go')

MKDOCS_DOCKER_IMAGE?=squidfunk/mkdocs-material:4.1.1

GIT_COMMIT=$(shell git rev-parse HEAD)
BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

DEV_MODE?=true
SEGMENT_WRITE_KEY?=""

ifeq (${DEV_MODE},true)
	RUNTIME_DEF_URL=${DEV_RUNTIME_DEF_URL}
	ADD_CLUSTER_DEF_URL=${DEV_ADD_CLUSTER_DEF_URL}
endif

ifdef LOCAL_MANIFESTS
	RUNTIME_DEF_URL=${LOCAL_MANIFESTS}
endif

ifndef GOBIN
ifndef GOPATH
$(error GOPATH is not set, please make sure you set your GOPATH correctly!)
endif
GOBIN=$(GOPATH)/bin
ifndef GOBIN
$(error GOBIN is not set, please make sure you set your GOBIN correctly!)
endif
endif

define docker_build
	docker buildx build -t $(IMAGE_REPOSITORY)/$(IMAGE_NAMESPACE)/$(1):dev-$(VERSION) .
endef

.PHONY: all
all: bin image

.PHONY: local
local: bin-local

.PHONY: bin
bin: cli

.PHONY: bin-local
bin-local: cli-local

.PHONY: image
image: cli-image

.PHONY: cur-version
cur-version:
	@echo -n $(VERSION)

.PHONY: cli
cli: $(OUT_DIR)/$(CLI_NAME)-linux-amd64.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-arm64.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-ppc64le.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-s390x.sha256 $(OUT_DIR)/$(CLI_NAME)-darwin-amd64.sha256 $(OUT_DIR)/$(CLI_NAME)-darwin-arm64.sha256 $(OUT_DIR)/$(CLI_NAME)-windows-amd64.sha256

.PHONY: cli-local
cli-local: $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH)
	@rm /usr/local/bin/$(CLI_NAME)-dev 2>/dev/null || true
	@ln $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) /usr/local/bin/$(CLI_NAME)-dev

.PHONY: cli-e2e
cli-e2e: cli-package

.PHONY: cli-package
cli-package: $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH)
	@cp $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) $(OUT_DIR)/$(CLI_NAME)

$(OUT_DIR)/$(CLI_NAME)-linux-amd64: GO_FLAGS='GOOS=linux GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-darwin-amd64: GO_FLAGS='GOOS=darwin GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-darwin-arm64: GO_FLAGS='GOOS=darwin GOARCH=arm64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-windows-amd64.exe: GO_FLAGS='GOOS=windows GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-arm64: GO_FLAGS='GOOS=linux GOARCH=arm64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-ppc64le: GO_FLAGS='GOOS=linux GOARCH=ppc64le CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-s390x: GO_FLAGS='GOOS=linux GOARCH=s390x CGO_ENABLED=0'

$(OUT_DIR)/$(CLI_NAME)-windows-amd64.tar.gz:
	@make $(OUT_DIR)/$(CLI_NAME)-windows-amd64.exe
	cd $(OUT_DIR) && tar -czvf $(CLI_NAME)-windows-amd64.tar.gz $(CLI_NAME)-windows-amd64.exe && cd ..

$(OUT_DIR)/$(CLI_NAME)-%.tar.gz:
	@make $(OUT_DIR)/$(CLI_NAME)-$*
	cd $(OUT_DIR) && tar -czvf $(CLI_NAME)-$*.tar.gz $(CLI_NAME)-$* && cd ..

$(OUT_DIR)/$(CLI_NAME)-%.sha256:
	@make $(OUT_DIR)/$(CLI_NAME)-$*.tar.gz
	openssl dgst -sha256 "$(OUT_DIR)/$(CLI_NAME)-$*.tar.gz" | awk '{ print $$2 }' > "$(OUT_DIR)/$(CLI_NAME)-$*".sha256

$(OUT_DIR)/$(CLI_NAME)-%: $(CLI_SRCS)
	@GO_FLAGS=$(GO_FLAGS) \
	BINARY_NAME=$(CLI_NAME) \
	VERSION=$(VERSION) \
	BUILD_DATE=$(BUILD_DATE) \
	GIT_COMMIT=$(GIT_COMMIT) \
	RUNTIME_DEF_URL=$(RUNTIME_DEF_URL) \
	ADD_CLUSTER_DEF_URL=$(ADD_CLUSTER_DEF_URL) \
	SEGMENT_WRITE_KEY=$(SEGMENT_WRITE_KEY) \
	DEV_MODE=$(DEV_MODE) \
	OUT_FILE=$(OUT_DIR)/$(CLI_NAME)-$* \
	MAIN=./cmd \
	./hack/build.sh

.PHONY: cli-image
cli-image: tidy $(OUT_DIR)/$(CLI_NAME).image

$(OUT_DIR)/$(CLI_NAME).image: $(CLI_SRCS)
	$(call docker_build,$(CLI_NAME))
	@mkdir -p $(OUT_DIR)
	@touch $(OUT_DIR)/$(CLI_NAME).image

.PHONY: lint
lint: $(GOBIN)/golangci-lint tidy
	@echo linting go code...
	@golangci-lint run --fix --timeout 10m

.PHONY: test
test:
	@./hack/test.sh

.PHONY: codegen
codegen: $(GOBIN)/mockgen
	rm -f ./docs/commands/*
	go generate ./...
	go run ./hack/license.go --license ./hack/boilerplate.txt --year $(YEAR) .

.PHONY: pre-commit
pre-commit: lint

.PHONY: pre-push
pre-push: tidy lint test codegen check-worktree

.PHONY: build-docs
build-docs:
	docker run ${MKDOCS_RUN_ARGS} --rm -it -p 8000:8000 -v $(shell pwd):/docs ${MKDOCS_DOCKER_IMAGE} build

.PHONY: serve-docs
serve-docs:
	docker run ${MKDOCS_RUN_ARGS} --rm -it -p 8000:8000 -v $(shell pwd):/docs ${MKDOCS_DOCKER_IMAGE} serve -a 0.0.0.0:8000

.PHONY: release
release: tidy check-worktree
	@./hack/release.sh

.PHONY: clean
clean:
	@rm -rf dist

.PHONY: tidy
tidy:
	@echo running go mod tidy...
	@go mod tidy

.PHONY: check-worktree
check-worktree:
	@./hack/check_worktree.sh

$(GOBIN)/mockgen:
	@go install github.com/golang/mock/mockgen@v1.6.0
	@mockgen -version

$(GOBIN)/golangci-lint:
	@mkdir dist || true
	@echo installing: golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.64.8
