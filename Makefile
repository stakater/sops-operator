OPERATOR_NAME ?= sops-operator
CATALOG_DIR_PATH ?= catalog
DOCKER_REPO_BASE ?= ghcr.io/stakater

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE is the registry path of the operator image; the bundle and catalog images add -bundle and
# -catalog, e.g. ghcr.io/stakater/sops-operator-bundle:v0.0.5.
IMAGE_TAG_BASE ?= $(DOCKER_REPO_BASE)/$(OPERATOR_NAME)

# catalog/channels.yaml decides the version: the highest version it lists is the version the next merge releases.
CHANNEL_VERSION = $(shell $(YQ) ea 'select(.schema == "olm.channel") | .entries[].name' $(CATALOG_DIR_PATH)/channels.yaml \
	| grep -v '^---$$' | sed 's/^$(OPERATOR_NAME)\.v//' | sort -uV | tail -n1)

# The next version to release: CHANNEL_VERSION while its bundle is not published, nothing once it is, so a
# published version is never built again. Only "manifest unknown" means unpublished; any other registry error
# is reported, so an outage is never taken for an unpublished version. Looked up once, when first needed.
NEXT_VERSION = $(eval NEXT_VERSION := $(shell \
	if err=$$($(CONTAINER_TOOL) manifest inspect $(BUNDLE_REPO):v$(CHANNEL_VERSION) 2>&1 >/dev/null); then :; \
	elif echo "$$err" | grep -qiE 'manifest unknown|not found|name unknown'; then echo $(CHANNEL_VERSION); \
	else echo "cannot tell whether $(BUNDLE_REPO):v$(CHANNEL_VERSION) is published: $$err"; fi))$(NEXT_VERSION)

# TAG is the version a build releases, e.g. 0.0.5; by default the next version. PR_TAG marks a pre-release build of
# it: pr-<number>-<sha7> in CI, dev-<time> locally by default, empty for a release. The build's version is then
# TAG-PR_TAG, e.g. 0.0.5-pr-19-abc1234, and its images are tagged v<version>.
TAG ?= $(NEXT_VERSION)
ifeq ($(origin PR_TAG),undefined)
PR_TAG := dev-$(shell date +%s)
endif
VERSION = $(TAG)$(if $(PR_TAG),-$(PR_TAG))
IMG ?= $(IMAGE_TAG_BASE):v$(VERSION)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)
# Where make images saves the three images.
IMAGES_DIR ?= $(LOCALBIN)/images/v$(VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

OPERATOR_SDK_VERSION ?= v1.42.3

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

.PHONY: test-scripts
test-scripts: sops yq age-keygen ## Test scripts/encrypt.sh with a throwaway key (no cluster).
	PATH="$(LOCALBIN):$$PATH" scripts/test.sh

# e2e tests install the operator the way customers do: OLM installs it from a catalog built from this tree, on a
# Kind cluster with a local registry. Resources are compared with committed golden files (test/e2e/testdata).
# Record or update them with: make test-e2e UPDATE_GOLDEN=true
KIND_CLUSTER ?= sops-operator-e2e
# Oldest node image published with KIND_VERSION; the 1.31 floor is covered by envtest.
KIND_NODE_IMAGE ?= kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d
OLM_VERSION ?= 0.46.0
REGISTRY_IMAGE ?= registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e
# Local registry for e2e images; its own name and port, so other projects' kind registries are untouched.
REGISTRY_NAME ?= sops-operator-registry
REGISTRY_PORT ?= 5011
E2E_KUBECONFIG = $(LOCALBIN)/kubeconfig-$(KIND_CLUSTER)
E2E_REGISTRY ?= localhost:$(REGISTRY_PORT)
.PHONY: setup-test-e2e
setup-test-e2e: kind operator-sdk ## Kind cluster with a local registry (localhost:$(REGISTRY_PORT)) and OLM, for e2e tests and scorecard.
	hack/kind-with-registry.sh $(KIND) $(KIND_CLUSTER) $(KIND_NODE_IMAGE) $(REGISTRY_IMAGE) $(REGISTRY_NAME) $(REGISTRY_PORT)
	$(KIND) get kubeconfig --name $(KIND_CLUSTER) > $(E2E_KUBECONFIG)
	KUBECONFIG=$(E2E_KUBECONFIG) $(OPERATOR_SDK) olm status >/dev/null 2>&1 \
		|| KUBECONFIG=$(E2E_KUBECONFIG) $(OPERATOR_SDK) olm install --version $(OLM_VERSION) --timeout 5m

.PHONY: images
images: opm yq kustomize operator-sdk ## Build the operator, bundle and catalog images of TAG and PR_TAG and save them to IMAGES_DIR.
	@test -n "$(TAG)" || { echo "no next version: list a version that is not published in catalog/channels.yaml" >&2; exit 1; }
	@$(if $(filter cannot,$(firstword $(TAG))),echo "$(TAG)" >&2; exit 1,true)
	$(CONTAINER_TOOL) image inspect $(IMG) >/dev/null 2>&1 || $(MAKE) docker-build TAG=$(TAG) PR_TAG=$(PR_TAG)
	$(MAKE) bundle TAG=$(TAG) PR_TAG=$(PR_TAG)
	$(MAKE) bundle-build TAG=$(TAG) PR_TAG=$(PR_TAG)
	$(MAKE) catalog-render TAG=$(TAG) PR_TAG=$(PR_TAG)
	$(MAKE) catalog-build TAG=$(TAG) PR_TAG=$(PR_TAG)
	mkdir -p $(IMAGES_DIR)
	$(CONTAINER_TOOL) save $(IMG) -o $(IMAGES_DIR)/operator.tar
	$(CONTAINER_TOOL) save $(BUNDLE_IMG) -o $(IMAGES_DIR)/bundle.tar
	$(CONTAINER_TOOL) save $(CATALOG_IMG) -o $(IMAGES_DIR)/catalog.tar

.PHONY: e2e-images
e2e-images: ## Load the images of TAG and PR_TAG from IMAGES_DIR (built first when missing) into the kind registry, which the cluster uses as a mirror of ghcr.io.
	@test -f $(IMAGES_DIR)/catalog.tar || $(MAKE) images TAG=$(TAG) PR_TAG=$(PR_TAG)
	for kind in operator bundle catalog; do $(CONTAINER_TOOL) load -i $(IMAGES_DIR)/$$kind.tar; done
	for ref in $(IMG) $(BUNDLE_IMG) $(CATALOG_IMG); do \
		$(CONTAINER_TOOL) tag $$ref $(E2E_REGISTRY)/$${ref#*/} && $(CONTAINER_TOOL) push $(E2E_REGISTRY)/$${ref#*/}; \
	done

.PHONY: test-e2e
test-e2e: setup-test-e2e sops yq e2e-images ## Run the e2e tests against the images of TAG installed by OLM (cluster kept for reruns; remove with cleanup-test-e2e).
	KIND_CLUSTER=$(KIND_CLUSTER) SOPS=$(SOPS) YQ=$(YQ) E2E_CATALOG_IMG=$(CATALOG_IMG) \
		go test ./test/e2e/ -v -count=1 -timeout 30m -parallel 12 $(if $(filter true,$(UPDATE_GOLDEN)),-update) \
		$(if $(E2E_RUN),-run '$(E2E_RUN)')

.PHONY: test-upgrade
test-upgrade: setup-test-e2e e2e-images ## Run the upgrade paths of test/e2e/upgrade_test.go through the catalog of TAG (published bundles + this build).
	KIND_CLUSTER=$(KIND_CLUSTER) E2E_CATALOG_IMG=$(CATALOG_IMG) E2E_UPGRADE=true \
		go test ./test/e2e/ -v -count=1 -timeout 30m -run '^TestUpgrade$$'

.PHONY: cleanup-test-e2e
cleanup-test-e2e: kind ## Tear down the e2e Kind cluster (the registry container is kept).
	$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-scripts
lint-scripts: ## Run shellcheck on scripts/ (shellcheck must be installed; it is on GitHub's Ubuntu runners).
	shellcheck scripts/*.sh

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Build

# Where build writes the manager binary; CI builds dist/manager-<arch> for the Dockerfile's prebuilt stage,
# with GOOS, GOARCH and CGO_ENABLED=0 in the environment.
MANAGER_BIN ?= bin/manager
# Extra flags for docker-build, bundle-build and catalog-build, e.g. --target prebuilt, or with
# CONTAINER_TOOL="docker buildx" the platforms, SBOM, provenance and --push of a release.
DOCKER_BUILD_ARGS ?=

.PHONY: build
build: manifests generate fmt vet ## Build manager binary (MANAGER_BIN).
	go build -trimpath -o $(MANAGER_BIN) cmd/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build $(DOCKER_BUILD_ARGS) -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KIND ?= $(LOCALBIN)/kind
SOPS ?= $(LOCALBIN)/sops
YQ ?= $(LOCALBIN)/yq
AGE_KEYGEN ?= $(LOCALBIN)/age-keygen
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KIND_VERSION ?= v0.33.0
SOPS_VERSION ?= v3.13.3
YQ_VERSION ?= v4.53.6
AGE_VERSION ?= v1.3.2
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.18.0
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= 1.31.0
GOLANGCI_LINT_VERSION ?= v2.1.0

.PHONY: sops
sops: $(SOPS) ## Download the sops CLI locally if necessary (used by e2e tests like a developer would).
$(SOPS): $(LOCALBIN)
	$(call go-install-tool,$(SOPS),github.com/getsops/sops/v3/cmd/sops,$(SOPS_VERSION))

.PHONY: yq
yq: $(YQ) ## Download yq locally if necessary.
$(YQ): $(LOCALBIN)
	$(call go-install-tool,$(YQ),github.com/mikefarah/yq/v4,$(YQ_VERSION))

.PHONY: age-keygen
age-keygen: $(AGE_KEYGEN) ## Download age-keygen locally if necessary (throwaway keys for test-scripts).
$(AGE_KEYGEN): $(LOCALBIN)
	$(call go-install-tool,$(AGE_KEYGEN),filippo.io/age/cmd/age-keygen,$(AGE_VERSION))

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

# operator-sdk and opm come from GitHub releases, verified against the release checksums.
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
OPM ?= $(LOCALBIN)/opm
OPM_VERSION ?= v1.74.0
BOOTSTRAP_STAMP = $(LOCALBIN)/.bootstrap-$(OPERATOR_SDK_VERSION)-$(OPM_VERSION)

.PHONY: operator-sdk opm
operator-sdk: $(BOOTSTRAP_STAMP) ## Install the pinned operator-sdk into bin/ (checksum-verified, with opm).
opm: $(BOOTSTRAP_STAMP) ## Install the pinned opm into bin/ (checksum-verified, with operator-sdk).

$(BOOTSTRAP_STAMP):
	mkdir -p $(LOCALBIN)
	BIN_DIR=$(LOCALBIN) OPERATOR_SDK_VERSION=$(OPERATOR_SDK_VERSION) OPM_VERSION=$(OPM_VERSION) hack/bootstrap-tools.sh
	touch $@

.PHONY: csv
csv: manifests kustomize operator-sdk yq ## Regenerate the base CSV from API markers and stamp operator-icon.svg into it.
	$(OPERATOR_SDK) generate kustomize manifests -q --interactive=false
	ICON="$$(base64 < operator-icon.svg | tr -d '\n')" $(YQ) -i \
		'.spec.icon = [{"base64data": strenv(ICON), "mediatype": "image/svg+xml"}]' \
		config/manifests/bases/sops-operator.clusterserviceversion.yaml

.PHONY: bundle
bundle: csv ## Generate bundle manifests and metadata for IMG, then validate them. Committed files are not changed.
	@# generate bundle does not remove manifests of an earlier run; start empty so nothing stale ships.
	rm -rf bundle bundle.Dockerfile
	$(KUSTOMIZE) build config/manifests | sed 's#image: controller:latest#image: $(IMG)#' \
		| $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle --select-optional suite=operatorframework

# Kind cluster scorecard runs its test pods in.
SCORECARD_CLUSTER ?= $(KIND_CLUSTER)

.PHONY: scorecard
scorecard: bundle kind ## Run the scorecard suites against ./bundle on the Kind cluster SCORECARD_CLUSTER.
	$(KIND) get kubeconfig --name $(SCORECARD_CLUSTER) > $(LOCALBIN)/kubeconfig-$(SCORECARD_CLUSTER)
	$(OPERATOR_SDK) scorecard ./bundle --kubeconfig $(LOCALBIN)/kubeconfig-$(SCORECARD_CLUSTER) \
		--namespace default --wait-time 180s

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	$(CONTAINER_TOOL) build $(DOCKER_BUILD_ARGS) -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)


# Published bundle images; every listed version other than this build's is rendered from here.
BUNDLE_REPO ?= $(IMAGE_TAG_BASE)-bundle
# Catalog metadata of a pull request build: catalog/* with TAG replaced by VERSION; catalog/ itself never changes.
PR_CATALOG_DIR = $(LOCALBIN)/catalog/v$(VERSION)

.PHONY: next-version
next-version: yq ## Print the next version to release: the highest version in catalog/channels.yaml if its bundle is not published, else nothing.
	@$(if $(filter cannot,$(firstword $(NEXT_VERSION))),echo "$(NEXT_VERSION)" >&2; exit 1,echo $(NEXT_VERSION))

# A release renders catalog/* with every bundle published, its own included. A pull request build renders the
# copy of hack/pr-catalog.sh, with its bundle, which is not published, from ./bundle.
.PHONY: catalog-render
catalog-render: opm yq ## Render and validate catalog/release/index.yaml for TAG, or for TAG and PR_TAG.
ifneq ($(PR_TAG),)
	SOURCE_DIR=$(CATALOG_DIR_PATH) OUT_DIR=$(PR_CATALOG_DIR) PACKAGE=$(OPERATOR_NAME) TAG=$(TAG) VERSION=$(VERSION) \
		YQ=$(YQ) hack/pr-catalog.sh
endif
	SOURCE_DIR=$(if $(PR_TAG),$(PR_CATALOG_DIR),$(CATALOG_DIR_PATH)) OUT_DIR=$(CATALOG_DIR_PATH)/release \
		VERSION=$(VERSION) BUNDLE_IMG=$(BUNDLE_IMG) BUNDLE_DIR=$(if $(PR_TAG),bundle) BUNDLE_REPO=$(BUNDLE_REPO) \
		PACKAGE=$(OPERATOR_NAME) ICON=operator-icon.svg OPM=$(OPM) YQ=$(YQ) hack/generate-catalog-index.sh

.PHONY: catalog-build
catalog-build: ## Build the catalog image from CATALOG_DIR_PATH/release.
	@test -f $(CATALOG_DIR_PATH)/release/index.yaml || { echo "$(CATALOG_DIR_PATH)/release/index.yaml does not exist:" \
		"run make catalog-render first"; exit 1; }
	$(CONTAINER_TOOL) build $(DOCKER_BUILD_ARGS) -f catalog.Dockerfile -t $(CATALOG_IMG) .

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)
