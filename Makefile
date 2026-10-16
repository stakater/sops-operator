# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.0.6
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
# -catalog, e.g. ghcr.io/stakater/sops-operator-bundle:v$(VERSION).
IMAGE_TAG_BASE ?= $(DOCKER_REPO_BASE)/$(OPERATOR_NAME)

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)

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
# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):v$(VERSION)

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
# A new tag per run so OLM never reuses a cached catalog or bundle.
E2E_TAG := e2e-$(shell date +%s)
# Set to an operator image that already exists locally (e.g. built in CI) to skip the build.
E2E_OPERATOR_IMG ?=
# Channels file of the e2e catalog; test-upgrade passes catalog/channels.yaml.
E2E_CATALOG_CHANNELS ?= $(LOCALBIN)/e2e-channels.yaml

.PHONY: setup-test-e2e
setup-test-e2e: kind operator-sdk ## Kind cluster with a local registry (localhost:$(REGISTRY_PORT)) and OLM, for e2e tests and scorecard.
	hack/kind-with-registry.sh $(KIND) $(KIND_CLUSTER) $(KIND_NODE_IMAGE) $(REGISTRY_IMAGE) $(REGISTRY_NAME) $(REGISTRY_PORT)
	$(KIND) get kubeconfig --name $(KIND_CLUSTER) > $(E2E_KUBECONFIG)
	KUBECONFIG=$(E2E_KUBECONFIG) $(OPERATOR_SDK) olm status >/dev/null 2>&1 \
		|| KUBECONFIG=$(E2E_KUBECONFIG) $(OPERATOR_SDK) olm install --version $(OLM_VERSION) --timeout 5m

.PHONY: e2e-images
e2e-images: opm yq kustomize operator-sdk ## Build and push the operator, bundle and catalog images for the e2e run to E2E_REGISTRY.
ifeq ($(E2E_OPERATOR_IMG),)
	$(CONTAINER_TOOL) build -t $(E2E_REGISTRY)/sops-operator:$(E2E_TAG) .
else
	$(CONTAINER_TOOL) tag $(E2E_OPERATOR_IMG) $(E2E_REGISTRY)/sops-operator:$(E2E_TAG)
endif
	$(CONTAINER_TOOL) push $(E2E_REGISTRY)/sops-operator:$(E2E_TAG)
	$(MAKE) bundle IMG=$(E2E_REGISTRY)/sops-operator:$(E2E_TAG)
	$(MAKE) bundle-build bundle-push BUNDLE_IMG=$(E2E_REGISTRY)/sops-operator-bundle:$(E2E_TAG)
	@# By default the catalog lists only this bundle (a fresh install of this build, whatever
	@# catalog/channels.yaml promotes); test-upgrade renders the real channel graph instead.
	printf 'schema: olm.channel\npackage: $(OPERATOR_NAME)\nname: alpha\nentries:\n  - name: $(OPERATOR_NAME).v$(VERSION)\n' \
		> $(LOCALBIN)/e2e-channels.yaml
	$(MAKE) catalog-render CATALOG_CHANNELS=$(E2E_CATALOG_CHANNELS) \
		BUNDLE_IMG=$(E2E_REGISTRY)/sops-operator-bundle:$(E2E_TAG) BUNDLE_IMG_RENDER_FLAGS=--use-http
	$(MAKE) catalog-build catalog-push CATALOG_IMG=$(E2E_REGISTRY)/sops-operator-catalog:$(E2E_TAG)

.PHONY: test-e2e
test-e2e: setup-test-e2e age e2e-images ## Run the e2e tests against the operator installed by OLM (cluster kept for reruns; remove with cleanup-test-e2e).
	KIND_CLUSTER=$(KIND_CLUSTER) AGE=$(AGE) E2E_CATALOG_IMG=$(E2E_REGISTRY)/sops-operator-catalog:$(E2E_TAG) \
		go test ./test/e2e/ -v -count=1 -timeout 30m -parallel 12 $(if $(filter true,$(UPDATE_GOLDEN)),-update)

.PHONY: test-upgrade
test-upgrade: setup-test-e2e ## Run the upgrade paths of test/e2e/upgrade_test.go through the real channel graph (published bundles + this build).
	$(MAKE) e2e-images E2E_TAG=$(E2E_TAG) E2E_CATALOG_CHANNELS=$(CATALOG_DIR_PATH)/channels.yaml
	KIND_CLUSTER=$(KIND_CLUSTER) E2E_CATALOG_IMG=$(E2E_REGISTRY)/sops-operator-catalog:$(E2E_TAG) E2E_UPGRADE=true \
		go test ./test/e2e/ -v -count=1 -timeout 30m -run '^TestUpgrade$$'

.PHONY: cleanup-test-e2e
cleanup-test-e2e: kind ## Tear down the e2e Kind cluster (the registry container is kept).
	$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

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
AGE ?= $(LOCALBIN)/age
YQ ?= $(LOCALBIN)/yq
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KIND_VERSION ?= v0.33.0
AGE_VERSION ?= v1.3.2
YQ_VERSION ?= v4.53.6
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.18.0
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= 1.31.0
GOLANGCI_LINT_VERSION ?= v2.1.0

.PHONY: age
age: $(AGE) ## Download the age CLI locally if necessary (used by e2e tests like a developer would).
$(AGE): $(LOCALBIN)
	$(call go-install-tool,$(AGE),filippo.io/age/cmd/age,$(AGE_VERSION))

.PHONY: yq
yq: $(YQ) ## Download yq locally if necessary.
$(YQ): $(LOCALBIN)
	$(call go-install-tool,$(YQ),github.com/mikefarah/yq/v4,$(YQ_VERSION))

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
	$(CONTAINER_TOOL) build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)


# The catalog image catalog-build tags.
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Published bundle images; channel entries other than VERSION are rendered from here.
BUNDLE_REPO ?= $(IMAGE_TAG_BASE)-bundle
# Channels file catalog-render renders (the upgrade graph); the OLM e2e run passes its own.
CATALOG_CHANNELS ?= $(CATALOG_DIR_PATH)/channels.yaml

.PHONY: catalog-render
catalog-render: opm yq ## Render catalog/release/index.yaml from catalog/channels.yaml (only if VERSION is promoted).
	CATALOG_DIR=$(CATALOG_DIR_PATH) CHANNELS=$(CATALOG_CHANNELS) VERSION=$(VERSION) BUNDLE_REPO=$(BUNDLE_REPO) BUNDLE_IMG=$(BUNDLE_IMG) \
		ICON=operator-icon.svg OPM=$(OPM) YQ=$(YQ) BUNDLE_IMG_RENDER_FLAGS="$(BUNDLE_IMG_RENDER_FLAGS)" \
		hack/generate-catalog-index.sh

.PHONY: catalog-build
catalog-build: ## Build the catalog image from CATALOG_DIR_PATH/release.
	@test -f $(CATALOG_DIR_PATH)/release/index.yaml || { echo "$(CATALOG_DIR_PATH)/release/index.yaml does not exist:" \
		"run make catalog-render; it builds no catalog when $(OPERATOR_NAME).v$(VERSION) is not listed in" \
		"$(CATALOG_CHANNELS)"; exit 1; }
	$(CONTAINER_TOOL) build -f catalog.Dockerfile -t $(CATALOG_IMG) .

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)
