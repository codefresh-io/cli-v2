VERSION=v0.0.21
OUT_DIR=dist
YEAR?=$(shell date +"%Y")

CLI_NAME?=cf
IMAGE_REPOSITORY?=quay.io
IMAGE_NAMESPACE?=codefresh

ARGOCD_INSTALLATION_MANIFESTS_URL="github.com/codefresh-io/cli-v2/manifests/argo-cd?ref=$(VERSION)"
EVENTS_INSTALLATION_MANIFESTS_URL="github.com/codefresh-io/cli-v2/manifests/argo-events?ref=$(VERSION)"
ROLLOUTS_INSTALLATION_MANIFESTS_URL="github.com/codefresh-io/cli-v2/manifests/argo-rollouts?ref=$(VERSION)"
WORKFLOWS_INSTALLATION_MANIFESTS_URL="github.com/codefresh-io/cli-v2/manifests/argo-workflows?ref=$(VERSION)"

DEV_ARGOCD_INSTALLATION_MANIFESTS_URL="manifests/argo-cd"
DEV_EVENTS_INSTALLATION_MANIFESTS_URL="manifests/argo-events"
DEV_ROLLOUTS_INSTALLATION_MANIFESTS_URL="manifests/argo-rollouts"
DEV_WORKFLOWS_INSTALLATION_MANIFESTS_URL="manifests/argo-workflows"

CLI_SRCS := $(shell find . -name '*.go')

MKDOCS_DOCKER_IMAGE?=squidfunk/mkdocs-material:4.1.1

GIT_COMMIT=$(shell git rev-parse HEAD)
BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

DEV_MODE?=true

ifeq (${DEV_MODE},true)
	ARGOCD_INSTALLATION_MANIFESTS_URL=${DEV_ARGOCD_INSTALLATION_MANIFESTS_URL}
	EVENTS_INSTALLATION_MANIFESTS_URL=${DEV_EVENTS_INSTALLATION_MANIFESTS_URL}
	ROLLOUTS_INSTALLATION_MANIFESTS_URL=${DEV_ROLLOUTS_INSTALLATION_MANIFESTS_URL}
	WORKFLOWS_INSTALLATION_MANIFESTS_URL=${DEV_WORKFLOWS_INSTALLATION_MANIFESTS_URL}
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
cli: $(OUT_DIR)/$(CLI_NAME)-linux-amd64.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-arm64.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-ppc64le.sha256 $(OUT_DIR)/$(CLI_NAME)-linux-s390x.sha256 $(OUT_DIR)/$(CLI_NAME)-darwin-amd64.sha256 $(OUT_DIR)/$(CLI_NAME)-windows-amd64.sha256

.PHONY: cli-local
cli-local: $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH)
	@cp $(OUT_DIR)/$(CLI_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) /usr/local/bin/$(CLI_NAME)

$(OUT_DIR)/$(CLI_NAME)-linux-amd64: GO_FLAGS='GOOS=linux GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-darwin-amd64: GO_FLAGS='GOOS=darwin GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-windows-amd64: GO_FLAGS='GOOS=windows GOARCH=amd64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-arm64: GO_FLAGS='GOOS=linux GOARCH=arm64 CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-ppc64le: GO_FLAGS='GOOS=linux GOARCH=ppc64le CGO_ENABLED=0'
$(OUT_DIR)/$(CLI_NAME)-linux-s390x: GO_FLAGS='GOOS=linux GOARCH=s390x CGO_ENABLED=0'

$(OUT_DIR)/$(CLI_NAME)-%.tar.gz:
	@make $(OUT_DIR)/$(CLI_NAME)-$*
	cd $(OUT_DIR) && tar -czvf $(CLI_NAME)-$*.tar.gz $(CLI_NAME)-$* && cd ..

$(OUT_DIR)/$(CLI_NAME)-%.sha256:
	@make $(OUT_DIR)/$(CLI_NAME)-$*.tar.gz
	openssl dgst -sha256 "$(OUT_DIR)/$(CLI_NAME)-$*.tar.gz" | awk '{ print $$2 }' > "$(OUT_DIR)/$(CLI_NAME)-$*".sha256

$(OUT_DIR)/$(CLI_NAME)-%: $(CLI_SRCS)
	@GO_FLAGS=$(GO_FLAGS) \
	BUILD_DATE=$(BUILD_DATE) \
	BINARY_NAME=$(CLI_NAME) \
	VERSION=$(VERSION) \
	GIT_COMMIT=$(GIT_COMMIT) \
	OUT_FILE=$(OUT_DIR)/$(CLI_NAME)-$* \
	ARGOCD_INSTALLATION_MANIFESTS_URL=$(ARGOCD_INSTALLATION_MANIFESTS_URL) \
	EVENTS_INSTALLATION_MANIFESTS_URL=$(EVENTS_INSTALLATION_MANIFESTS_URL) \
	ROLLOUTS_INSTALLATION_MANIFESTS_URL=$(ROLLOUTS_INSTALLATION_MANIFESTS_URL) \
	WORKFLOWS_INSTALLATION_MANIFESTS_URL=$(WORKFLOWS_INSTALLATION_MANIFESTS_URL) \
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
	@golangci-lint run --fix --timeout 6m

.PHONY: test
test:
	@./hack/test.sh

.PHONY: codegen
codegen: $(GOBIN)/mockery
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

$(GOBIN)/mockery:
	@mkdir dist || true
	@echo installing: mockery
	@curl -L -o dist/mockery.tar.gz -- https://github.com/vektra/mockery/releases/download/v1.1.1/mockery_1.1.1_$(shell uname -s)_$(shell uname -m).tar.gz
	@tar zxvf dist/mockery.tar.gz mockery
	@rm dist/mockery.tar.gz
	@chmod +x mockery
	@mkdir -p $(GOBIN)
	@mv mockery $(GOBIN)/mockery
	@mockery -version

$(GOBIN)/golangci-lint:
	@mkdir dist || true
	@echo installing: golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) v1.36.0
