# OLM Delivery Implementation Plan (plan 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship sops-operator as an OLM bundle and file-based catalog with Hestia's channel promotion flow, console-ready CSV descriptors, scorecard, and an e2e mode that runs the existing e2e suite against the operator installed by OLM from that catalog.

**Architecture:** The bundle is generated from `config/manifests` (base CSV with icon and descriptors from API markers, CRDs, operator RBAC, tenant ClusterRoles, samples, scorecard config) and is never committed. The catalog follows Hestia: `catalog/package.yaml` and `catalog/channels.yaml` are committed and edited by hand to promote versions; `hack/generate-catalog-index.sh` renders every bundle the channels list into `catalog/release/index.yaml`, which `catalog.Dockerfile` serves. `E2E_INSTALL=olm` publishes operator, bundle and catalog images to a local registry, installs OLM v0 on a dedicated kind cluster and subscribes to the catalog; the unchanged e2e suite and golden files then run against that install.

**Tech Stack:** operator-sdk v1.42.3, opm v1.74.0, OLM v0 v0.46.0, kind v0.33.0, registry 3.0.0, yq v4.53.6, Go 1.25, GitHub Actions.

**Spec:** `DESIGN.md` (§5.2 RBAC objects shipped in the bundle, §9 Delivery, D3, D23, D27, D32–D34). Hestia (`github.com/stakater/Hestia`) is the reference for the icon and the catalog promotion flow.

## Global Constraints

- Distribution: OLM only; bundle + file-based catalog images; channels `alpha` → `stable`; install mode `AllNamespaces` only; no webhooks; no OLM dependencies.
- Images: `ghcr.io/stakater/sops-operator`, `-bundle`, `-catalog`, tagged `vX.Y.Z`. Package name `sops-operator`; CSV name `sops-operator.vX.Y.Z`.
- CSV: provider "Stakater AB", `maturity: alpha`, `minKubeVersion: 1.31.0`, SVG icon = Hestia's `operator-icon.svg` (Stakater style, black outline, `#fecd07`).
- Tenant-facing ClusterRoles `sops-key-owner`, `sops-secret-writer` (and the aggregated ones) are shipped as static objects in the bundle with exactly these names (D32).
- Tools are pinned in the Makefile: operator-sdk v1.42.3, opm v1.74.0, kind v0.33.0, yq v4.53.6, sops v3.13.3; new pins: `OLM_VERSION ?= 0.46.0`, `REGISTRY_IMAGE ?= registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e`, catalog base `quay.io/operator-framework/opm:v1.74.0`.
- Every `kubectl`, `kind`, `operator-sdk` call names its cluster explicitly (`--context kind-<cluster>`, `--name <cluster>`, or a kubeconfig file written by `kind get kubeconfig --name <cluster>`); nothing relies on the current context.
- Tests follow the repo convention: one top-level test per feature, `shall …` subtests; every new or changed assertion is shown failing for the right reason before it passes.
- Commit messages: conventional commits, no attribution or AI mention.
- CI: actions pinned by SHA, job-level minimal permissions, no write token in jobs that run PR code (authoring-github-actions checklist).

## Review Focus

- A promotion that lists a bundle version which cannot be rendered (not published, typo) must fail the catalog build, not silently drop that version from the catalog customers upgrade through — Task 4 test "shall fail when a listed bundle cannot be rendered".
- A version not listed in any channel must produce no catalog (it is not promoted), and a stale `release/index.yaml` from an earlier run must not be shipped — Task 4 test "shall not build a catalog for an unpromoted version".
- `make bundle` must not rewrite committed sources (the scaffolded target ran `kustomize edit set image` on `config/manager`, which also breaks the e2e image placeholder) — Task 1 step checks `git status --porcelain` after `make bundle`.
- An OLM install must work without applying `config/tenant-rbac` by hand: onboarding templates reference those ClusterRoles — Task 6 runs the whole suite on an OLM install that never applies them, and proves the suite fails when they are left out of the bundle.
- An invalid `RESYNC_INTERVAL` (typo, `0s`, negative) in `Subscription.spec.config.env` must stop the operator with a clear error instead of running with an unintended interval — Task 3 tests.

Out of scope (plan 3): publishing images on push/tag, signing, SBOM, a release workflow that runs the catalog promotion against ghcr. An upgrade e2e between two catalog versions needs a second published version and is deferred until then.

---

### Task 1: Bundle generation with icon, base CSV and tenant ClusterRoles

**Files:**
- Create: `operator-icon.svg` (copied from Hestia)
- Create: `config/manifests/bases/sops-operator.clusterserviceversion.yaml`
- Modify: `config/manifests/kustomization.yaml` (add `../tenant-rbac`)
- Modify: `Makefile` (`csv` target, non-mutating `bundle` target)
- Modify: `.gitignore` (`bundle/`, `bundle.Dockerfile`)
- Modify: `DESIGN.md` (§9, decision D41)

**Interfaces:**
- Produces: `make csv` (regenerates the committed base CSV from API markers and stamps the icon), `make bundle IMG=<operator image>` (writes `bundle/` and `bundle.Dockerfile`, validates with the `operatorframework` suite, leaves committed files unchanged), `make bundle-build bundle-push BUNDLE_IMG=<ref>` (unchanged scaffold targets).

- [ ] **Step 1: Write the failing check**

The bundle must pass OperatorHub validation and generation must not touch committed files. Run on the current tree:

```bash
make bundle; bin/operator-sdk bundle validate ./bundle --select-optional suite=operatorframework; git status --porcelain
```

Expected: FAIL. Validation reports missing `icon`, `maintainers`, `provider`, `description`/`displayName` and `minKubeVersion` (or `generate kustomize manifests` stops without a base CSV), and `git status` shows `config/manager/kustomization.yaml` modified by `kustomize edit set image`. Record the output in the ledger, then restore: `git checkout -- config/manager/kustomization.yaml && rm -rf bundle bundle.Dockerfile config/manifests/bases`.

- [ ] **Step 2: Copy the icon from Hestia**

```bash
gh api repos/stakater/Hestia/contents/operator-icon.svg --jq .content | base64 -d > operator-icon.svg
head -c 80 operator-icon.svg   # Expected: <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 78 59.841" ...
```

- [ ] **Step 3: Write the base CSV**

`config/manifests/bases/sops-operator.clusterserviceversion.yaml`:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  annotations:
    alm-examples: '[]'
    capabilities: Basic Install
    categories: Security
    description: Decrypts SOPS-encrypted SopsSecrets into Kubernetes Secrets with per-tenant keys.
    repository: https://github.com/stakater/sops-operator
    support: Stakater AB
  name: sops-operator.v0.0.0
  namespace: placeholder
spec:
  apiservicedefinitions: {}
  customresourcedefinitions: {}
  description: |
    SOPS Operator turns SOPS-encrypted `SopsSecret` resources committed to Git into Kubernetes Secrets.

    - **Tenant keys**: a `SopsTenant` holds a post-quantum age key. The operator generates it when the key
      Secret does not exist, or uses a key you provide.
    - **Zero trust**: the operator holds no Secret permissions of its own. It reads keys and writes Secrets
      only through each tenant's identity, in the namespaces the cluster admin granted to that tenant.
    - **Scoped ciphertext**: every file carries an encrypted `<namespace>/<name>` scope, so ciphertext copied
      to another namespace or name is rejected.

    Before a tenant can use its key, the cluster admin onboards it by binding the `sops-key-owner` and
    `sops-secret-writer` ClusterRoles to the tenant's `sops` ServiceAccount.
  displayName: SOPS Operator
  icon:
  - base64data: ""
    mediatype: image/svg+xml
  install:
    spec:
      deployments: null
    strategy: ""
  installModes:
  - supported: false
    type: OwnNamespace
  - supported: false
    type: SingleNamespace
  - supported: false
    type: MultiNamespace
  - supported: true
    type: AllNamespaces
  keywords:
  - sops
  - age
  - secrets
  - gitops
  - encryption
  - multi-tenancy
  links:
  - name: Source code
    url: https://github.com/stakater/sops-operator
  maintainers:
  - email: hello@stakater.com
    name: Stakater AB
  maturity: alpha
  minKubeVersion: 1.31.0
  provider:
    name: Stakater AB
    url: https://www.stakater.com
  version: 0.0.0
```

- [ ] **Step 4: Ship the tenant ClusterRoles in the bundle**

In `config/manifests/kustomization.yaml`, add `- ../tenant-rbac` under `resources` after `- ../default`.

- [ ] **Step 5: Make generation non-mutating and stamp the icon**

Replace the scaffolded `bundle` target in `Makefile` and add `csv`:

```makefile
.PHONY: csv
csv: manifests kustomize operator-sdk yq ## Regenerate the base CSV from API markers and stamp operator-icon.svg into it.
	$(OPERATOR_SDK) generate kustomize manifests -q --interactive=false
	ICON="$$(base64 < operator-icon.svg | tr -d '\n')" $(YQ) -i \
		'.spec.icon = [{"base64data": strenv(ICON), "mediatype": "image/svg+xml"}]' \
		config/manifests/bases/sops-operator.clusterserviceversion.yaml

.PHONY: bundle
bundle: csv ## Generate bundle manifests and metadata for IMG, then validate them. Committed files are not changed.
	$(KUSTOMIZE) build config/manifests | sed 's#image: controller:latest#image: $(IMG)#' \
		| $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle --select-optional suite=operatorframework
```

Add to `.gitignore` under "Binaries and build output":

```gitignore
bundle/
bundle.Dockerfile
```

- [ ] **Step 6: Run the check again**

```bash
make bundle && git status --porcelain
yq '.spec.icon[0].mediatype, .spec.minKubeVersion, .spec.provider.name' bundle/manifests/sops-operator.clusterserviceversion.yaml
ls bundle/manifests | grep -E 'sops-key-owner|sops-secret-writer'
make bundle && git status --porcelain   # second run: same output, idempotent
```

Expected: validation prints no errors (descriptor warnings are fixed in Task 2); `git status --porcelain` lists only this task's files (`operator-icon.svg`, `config/manifests/…`, `Makefile`, `.gitignore`) and nothing under `config/manager`; yq prints `image/svg+xml`, `1.31.0`, `Stakater AB`; both ClusterRole manifests are listed.

- [ ] **Step 7: Record the decision in DESIGN.md**

Add to §9 Delivery after the Distribution bullet:

```markdown
- **Bundle**: generated by `make bundle IMG=<image>` from `config/manifests` (base CSV, CRDs, operator RBAC, the
  tenant ClusterRoles of §5.2, samples, scorecard configuration) and validated with the `operatorframework` suite.
  `bundle/` is a build output and is not committed. The base CSV is regenerated from API markers by `make csv`,
  which also stamps `operator-icon.svg` (Hestia's icon) into it.
```

Add decision row:

```markdown
| D41 | The bundle is generated and not committed; the base CSV is | Generated files drift; the base CSV carries hand-written metadata and is checked by CI like other generated files. |
```

- [ ] **Step 8: Commit**

```bash
git add operator-icon.svg config/manifests Makefile .gitignore DESIGN.md
git commit -m "feat(olm): generate a validated bundle with icon and tenant ClusterRoles"
```

---

### Task 2: Scorecard and console descriptors

**Files:**
- Modify: `api/v1alpha1/sopstenant_types.go`, `api/v1alpha1/sopssecret_types.go` (CSV markers)
- Modify: `Makefile` (`scorecard` target)
- Regenerated: `config/manifests/bases/sops-operator.clusterserviceversion.yaml` (by `make csv`)

**Interfaces:**
- Consumes: `make bundle` (Task 1).
- Produces: `make scorecard [SCORECARD_CLUSTER=<kind cluster>]` running the basic and OLM suites of `config/scorecard` against `./bundle` in that cluster.

- [ ] **Step 1: Add the scorecard target**

```makefile
# Kind cluster scorecard runs its test pods in.
SCORECARD_CLUSTER ?= $(KIND_CLUSTER)

.PHONY: scorecard
scorecard: bundle kind ## Run the scorecard suites against ./bundle on the Kind cluster SCORECARD_CLUSTER.
	$(KIND) get kubeconfig --name $(SCORECARD_CLUSTER) > $(LOCALBIN)/kubeconfig-$(SCORECARD_CLUSTER)
	$(OPERATOR_SDK) scorecard ./bundle --kubeconfig $(LOCALBIN)/kubeconfig-$(SCORECARD_CLUSTER) \
		--namespace default --wait-time 180s
```

- [ ] **Step 2: Run scorecard to see it fail**

```bash
make setup-test-e2e scorecard
```

Expected: FAIL. `olm-crds-have-resources` fails with "Owned CRDs do not have resources specified"; `olm-spec-descriptors` fails with "generateKey does not have a spec descriptor" and the same for `deletionPolicy`, `scope`, `stringData`, `template`, `tenantRef`, `type`. `basic-check-spec`, `olm-bundle-validation` and `olm-crds-have-validation` pass; `olm-status-descriptors` passes with suggestions (the samples have no status).

- [ ] **Step 3: Add markers to SopsTenant**

In `api/v1alpha1/sopstenant_types.go`:

```go
type SopsTenantSpec struct {
	// GenerateKey generates a post-quantum age key when the key Secret does not exist.
	// +kubebuilder:default=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Generate key",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:booleanSwitch"}
	// +optional
	GenerateKey *bool `json:"generateKey,omitempty"`
}

type SopsTenantStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Observed generation"
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// UsedBy is the number of SopsSecrets referencing this tenant.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Used by"
	// +optional
	UsedBy int32 `json:"usedBy,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

and on the `SopsTenant` type, below the printcolumn markers:

```go
// +operator-sdk:csv:customresourcedefinitions:displayName="SOPS Tenant",resources={{Secret,v1,""}}
```

- [ ] **Step 4: Add markers to SopsSecret**

Ciphertext fields are hidden from the console form: editing them by hand breaks the SOPS MAC. In `api/v1alpha1/sopssecret_types.go`:

```go
type TenantReference struct {
	// +kubebuilder:validation:MinLength=1
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant name"
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant namespace",xDescriptors={"urn:alm:descriptor:io.kubernetes:Namespace"}
	Namespace string `json:"namespace"`
}

type SopsSecretSpec struct {
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant"
	TenantRef TenantReference `json:"tenantRef"`
	// Scope is the encrypted "<namespace>/<name>" this document may be decrypted into.
	// +kubebuilder:validation:MinLength=1
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Scope (encrypted)",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:hidden"}
	Scope string `json:"scope"`
	// +kubebuilder:default=Delete
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Deletion policy",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:select:Delete","urn:alm:descriptor:com.tectonic.ui:select:Retain"}
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Secret metadata",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:advanced"}
	// +optional
	Template SecretTemplate `json:"template,omitempty"`
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls;kubernetes.io/dockerconfigjson;kubernetes.io/basic-auth;kubernetes.io/ssh-auth
	// +kubebuilder:default=Opaque
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Secret type",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:select:Opaque","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/tls","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/dockerconfigjson","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/basic-auth","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/ssh-auth"}
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
	// Data holds encrypted base64 values.
	// +kubebuilder:validation:MaxProperties=256
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Data (encrypted)",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:hidden"}
	// +optional
	Data map[string]string `json:"data,omitempty"`
	// StringData holds encrypted text values.
	// +kubebuilder:validation:MaxProperties=256
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="String data (encrypted)",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:hidden"}
	// +optional
	StringData map[string]string `json:"stringData,omitempty"`
}
```

Add to the status fields (keeping their existing `+optional`, `+listType`, `+listMapKey` markers):

```go
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Observed generation"
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Last sync"
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// SecretUID is the UID of the Secret this SopsSecret created.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Secret UID"
	SecretUID types.UID `json:"secretUID,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Conditions []metav1.Condition `json:"conditions,omitempty"`
```

and on the `SopsSecret` type:

```go
// +operator-sdk:csv:customresourcedefinitions:displayName="SOPS Secret",resources={{Secret,v1,""}}
```

- [ ] **Step 5: Run scorecard and check the hidden descriptors**

```bash
make scorecard
yq '.spec.customresourcedefinitions.owned[] | select(.kind == "SopsSecret") | .specDescriptors[] | select(.x-descriptors[] == "urn:alm:descriptor:com.tectonic.ui:hidden") | .path' bundle/manifests/sops-operator.clusterserviceversion.yaml
git diff --stat config/crd
make test
```

Expected: all six scorecard tests `State: pass`; yq prints `scope`, `data`, `stringData`; `git diff --stat config/crd` prints nothing (markers do not change the CRDs); `make test` passes.

- [ ] **Step 6: Commit**

```bash
git add api config/manifests Makefile
git commit -m "feat(olm): CSV descriptors for the console and a scorecard target"
```

---

### Task 3: Resync interval from the environment

OLM installs configure the operator through `Subscription.spec.config.env` (DESIGN §9); the OLM e2e run needs a 10s resync.

**Files:**
- Modify: `cmd/main.go`
- Create: `cmd/main_test.go`
- Modify: `DESIGN.md` (§9 Configuration)

**Interfaces:**
- Produces: environment variable `RESYNC_INTERVAL` (Go duration, > 0) as the default of `--resync-interval`; an explicit flag still wins.

- [ ] **Step 1: Write the failing test**

`cmd/main_test.go` (license header from `hack/boilerplate.go.txt`):

```go
package main

import (
	"strings"
	"testing"
	"time"
)

func TestResyncIntervalFromEnvironment(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		set     bool
		want    time.Duration
		wantErr bool
	}{
		{name: "shall use the default when unset", want: 10 * time.Minute},
		{name: "shall use a valid duration", value: "10s", set: true, want: 10 * time.Second},
		{name: "shall reject a value that is not a duration", value: "soon", set: true, wantErr: true},
		{name: "shall reject zero", value: "0s", set: true, wantErr: true},
		{name: "shall reject a negative duration", value: "-1m", set: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("RESYNC_INTERVAL", tc.value)
			}
			got, err := durationFromEnv("RESYNC_INTERVAL", 10*time.Minute)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "RESYNC_INTERVAL") {
					t.Fatalf("want an error naming RESYNC_INTERVAL, got %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/ -run TestResyncIntervalFromEnvironment`
Expected: FAIL to compile with "undefined: durationFromEnv".

- [ ] **Step 3: Implement**

In `cmd/main.go`, add:

```go
// durationFromEnv returns the positive duration in the environment variable name, or fallback
// when it is unset. OLM installs set it through Subscription.spec.config.env.
func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q must be a positive duration such as 10m", name, v)
	}
	return d, nil
}
```

and replace the `--resync-interval` flag definition:

```go
	defaultResync, err := durationFromEnv("RESYNC_INTERVAL", 10*time.Minute)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var resyncInterval time.Duration
	flag.DurationVar(&resyncInterval, "resync-interval", defaultResync,
		"How often tenants and SopsSecrets are re-checked (key changes, revoked grants, drift). "+
			"Defaults to RESYNC_INTERVAL if set.")
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/ && make test lint`
Expected: PASS, `0 issues.`

- [ ] **Step 5: Document**

In DESIGN.md §9, replace the Configuration bullet with:

```markdown
- **Configuration**: flags, with environment defaults settable through `Subscription.spec.config.env`:
  `RESYNC_INTERVAL` (Go duration, default `10m`). An invalid value stops the operator at startup.
```

- [ ] **Step 6: Commit**

```bash
git add cmd DESIGN.md
git commit -m "feat: default the resync interval from RESYNC_INTERVAL"
```

---

### Task 4: File-based catalog with Hestia's promotion flow

Promotion is a reviewed edit of `catalog/channels.yaml`: adding `sops-operator.vX.Y.Z` to a channel (with `replaces` or `skipRange`) releases it there. Every catalog build renders all bundles any channel lists, so customers on older versions keep an upgrade path, and a version listed in no channel is not released.

**Files:**
- Create: `catalog/package.yaml`, `catalog/channels.yaml`, `catalog/.gitignore`
- Create: `hack/generate-catalog-index.sh`, `hack/test-generate-catalog-index.sh`
- Create: `catalog.Dockerfile`
- Modify: `Makefile` (replace the scaffolded `catalog-build`; add `catalog-render`, `test-catalog`)
- Modify: `DESIGN.md` (§9, decision D42)

**Interfaces:**
- Consumes: bundle images `$(BUNDLE_REPO):vX.Y.Z` in a registry; `operator-icon.svg` (Task 1).
- Produces: `make catalog-render [BUNDLE_IMG=<ref for VERSION>] [OPM_RENDER_FLAGS=--use-http]` → `catalog/release/index.yaml` (or none when VERSION is not promoted); `make catalog-build catalog-push CATALOG_IMG=<ref>`; `make test-catalog`.

- [ ] **Step 1: Write the failing test**

`hack/test-generate-catalog-index.sh` (fake `opm`, real `yq`, no registry):

```bash
#!/usr/bin/env bash
# Tests hack/generate-catalog-index.sh with a fake opm. Run with `make test-catalog`.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
YQ=$(realpath "${YQ:-${root}/bin/yq}")
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# Fake opm: `render <ref>` prints a bundle named after the ref's tag and fails for tags containing
# "missing"; `validate` succeeds.
cat > "${work}/opm" <<'OPM'
#!/usr/bin/env bash
case "$1" in
  render)
    tag=${2##*:}
    [[ "$tag" == *missing* ]] && { echo "unable to pull $2" >&2; exit 1; }
    printf 'schema: olm.bundle\npackage: sops-operator\nname: sops-operator.%s\nimage: %s\n' "$tag" "$2" ;;
  validate) exit 0 ;;
  *) exit 2 ;;
esac
OPM
chmod +x "${work}/opm"

fails=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }

catalog() { # catalog <dir> <channel entries...>: write package.yaml and channels.yaml
  local dir=$1; shift
  mkdir -p "${dir}"
  printf 'schema: olm.package\nname: sops-operator\ndefaultChannel: alpha\n' > "${dir}/package.yaml"
  { printf 'schema: olm.channel\npackage: sops-operator\nname: alpha\nentries:\n'
    for e in "$@"; do printf '  - name: %s\n' "$e"; done; } > "${dir}/channels.yaml"
}
generate() { # generate <dir> <version> [bundle img]
  CATALOG_DIR="$1" VERSION="$2" BUNDLE_IMG="${3:-}" BUNDLE_REPO=ghcr.io/stakater/sops-operator-bundle \
    OPM="${work}/opm" YQ="${YQ}" ICON="${root}/operator-icon.svg" "${root}/hack/generate-catalog-index.sh"
}

catalog "${work}/a" sops-operator.v0.0.1 sops-operator.v0.0.2
generate "${work}/a" 0.0.2 localhost:5001/sops-operator-bundle:e2e > /dev/null || true
index="${work}/a/release/index.yaml"
check "shall build a catalog when the version is promoted" '[ -f "${index}" ]'
check "shall render the published bundle of older versions" \
  '[ "$("${YQ}" ea "select(.name == \"sops-operator.v0.0.1\") | .image" "${index}" 2>/dev/null)" = ghcr.io/stakater/sops-operator-bundle:v0.0.1 ]'
check "shall render BUNDLE_IMG for the version being built" \
  '"${YQ}" ea "select(.schema == \"olm.bundle\") | .image" "${index}" 2>/dev/null | grep -qx localhost:5001/sops-operator-bundle:e2e'
check "shall stamp the icon into the package" \
  '[ "$("${YQ}" ea "select(.schema == \"olm.package\") | .icon.mediatype" "${index}" 2>/dev/null)" = image/svg+xml ]'

catalog "${work}/b" sops-operator.v0.0.1
mkdir -p "${work}/b/release" && echo stale > "${work}/b/release/index.yaml"
generate "${work}/b" 0.0.2 > /dev/null || true
check "shall not build a catalog for an unpromoted version" '[ ! -e "${work}/b/release/index.yaml" ]'

catalog "${work}/c" sops-operator.v0.0.1 sops-operator.vmissing
check "shall fail when a listed bundle cannot be rendered" '! generate "${work}/c" 0.0.1 > /dev/null 2>&1'

exit "${fails}"
```

Makefile:

```makefile
.PHONY: test-catalog
test-catalog: yq ## Test the catalog promotion script with a fake opm.
	YQ=$(YQ) hack/test-generate-catalog-index.sh
```

- [ ] **Step 2: Run it to see it fail**

Run: `chmod +x hack/test-generate-catalog-index.sh && make test-catalog`
Expected: FAIL. The checks that need an index report `FAIL` because `hack/generate-catalog-index.sh` does not exist ("No such file or directory"). (The "fail when a bundle cannot be rendered" check passes vacuously here; it is proven in Step 4's mutation.)

- [ ] **Step 3: Implement the script**

`hack/generate-catalog-index.sh`, adapted from Hestia's `generate-catalog-index.sh`:

```bash
#!/usr/bin/env bash
# Renders the file-based catalog from catalog/channels.yaml (Hestia's promotion flow).
#
# channels.yaml is the upgrade graph: a version is released by adding sops-operator.vX.Y.Z to a
# channel in a reviewed change. Every bundle any channel lists is rendered, so older versions stay
# installable. When VERSION is listed in no channel, nothing is released and no index is written.
#
# Environment: CATALOG_DIR, VERSION, BUNDLE_REPO (published bundles, tagged vX.Y.Z), BUNDLE_IMG
# (bundle for VERSION; default $BUNDLE_REPO:v$VERSION), ICON, OPM, YQ, OPM_RENDER_FLAGS (e.g. --use-http).
set -euo pipefail

: "${CATALOG_DIR:?}" "${VERSION:?}" "${BUNDLE_REPO:?}" "${ICON:?}"
OPM=${OPM:-opm}
YQ=${YQ:-yq}
PACKAGE=sops-operator
BUNDLE_IMG=${BUNDLE_IMG:-${BUNDLE_REPO}:v${VERSION}}
release="${CATALOG_DIR}/release"
bundles="${CATALOG_DIR}/bundles.yaml"

rm -rf "${release}" "${bundles}"
entries=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CATALOG_DIR}/channels.yaml" \
  | grep -v '^---$' | sort -u)

if ! grep -qx "${PACKAGE}.v${VERSION}" <<<"${entries}"; then
  echo "${PACKAGE}.v${VERSION} is not listed in ${CATALOG_DIR}/channels.yaml: not promoted, no catalog built"
  exit 0
fi

for entry in ${entries}; do
  version=${entry#"${PACKAGE}.v"}
  ref="${BUNDLE_REPO}:v${version}"
  [ "${version}" = "${VERSION}" ] && ref="${BUNDLE_IMG}"
  # shellcheck disable=SC2086 # OPM_RENDER_FLAGS holds separate flags
  "${OPM}" render "${ref}" --output=yaml ${OPM_RENDER_FLAGS:-} >> "${bundles}"
  echo "rendered ${ref}"
done

mkdir -p "${release}"
ICON_DATA=$(base64 < "${ICON}" | tr -d '\n') "${YQ}" \
  '.icon = {"base64data": strenv(ICON_DATA), "mediatype": "image/svg+xml"}' "${CATALOG_DIR}/package.yaml" \
  > "${release}/index.yaml"
{ echo '---'; "${YQ}" ea '.' "${CATALOG_DIR}/channels.yaml" "${bundles}"; } >> "${release}/index.yaml"
"${OPM}" validate "${release}"
echo "wrote ${release}/index.yaml"
```

- [ ] **Step 4: Run the test, then prove the failure check**

Run: `chmod +x hack/generate-catalog-index.sh && make test-catalog`
Expected: six `ok` lines, exit 0.
Then temporarily change the render line to `"${OPM}" render "${ref}" --output=yaml ${OPM_RENDER_FLAGS:-} >> "${bundles}" || true` (Hestia's behaviour, failures ignored) and rerun: Expected `FAIL shall fail when a listed bundle cannot be rendered`. Restore and ledger the output.

- [ ] **Step 5: Add the catalog files**

`catalog/package.yaml`:

```yaml
schema: olm.package
name: sops-operator
defaultChannel: alpha
description: |
  Decrypts SOPS-encrypted SopsSecrets into Kubernetes Secrets with per-tenant post-quantum age keys,
  without giving the operator access to any Secret.
```

`catalog/channels.yaml`:

```yaml
schema: olm.channel
package: sops-operator
name: alpha
entries:
  - name: sops-operator.v0.0.1
```

`catalog/.gitignore`:

```gitignore
/release/
/bundles.yaml
```

`catalog.Dockerfile`:

```dockerfile
# Serves the file-based catalog rendered by hack/generate-catalog-index.sh.
FROM quay.io/operator-framework/opm:v1.74.0
ENTRYPOINT ["/bin/opm"]
CMD ["serve", "/configs", "--cache-dir=/tmp/cache"]
ADD catalog/release /configs
RUN ["/bin/opm", "serve", "/configs", "--cache-dir=/tmp/cache", "--cache-only"]
LABEL operators.operatorframework.io.index.configs.v1=/configs
```

- [ ] **Step 6: Replace the scaffolded catalog targets**

Delete the scaffolded `BUNDLE_IMGS`, `FROM_INDEX_OPT` and the `opm index add` `catalog-build` recipe, and add:

```makefile
# Published bundle images; channel entries other than VERSION are rendered from here.
BUNDLE_REPO ?= $(IMAGE_TAG_BASE)-bundle

.PHONY: catalog-render
catalog-render: opm yq ## Render catalog/release/index.yaml from catalog/channels.yaml (only if VERSION is promoted).
	CATALOG_DIR=$(CATALOG_DIR_PATH) VERSION=$(VERSION) BUNDLE_REPO=$(BUNDLE_REPO) BUNDLE_IMG=$(BUNDLE_IMG) \
		ICON=operator-icon.svg OPM=$(OPM) YQ=$(YQ) OPM_RENDER_FLAGS="$(OPM_RENDER_FLAGS)" \
		hack/generate-catalog-index.sh

.PHONY: catalog-build
catalog-build: ## Build the catalog image from catalog/release.
	test -f $(CATALOG_DIR_PATH)/release/index.yaml || { echo "run make catalog-render first"; exit 1; }
	$(CONTAINER_TOOL) build -f catalog.Dockerfile -t $(CATALOG_IMG) .
```

Keep `catalog-push`.

- [ ] **Step 7: Document**

In DESIGN.md §9, after the Bundle bullet:

```markdown
- **Catalog and promotion** (from Hestia): `catalog/package.yaml` and `catalog/channels.yaml` are committed;
  `channels.yaml` is the upgrade graph. A version is released to a channel by adding `sops-operator.vX.Y.Z` to it
  (with `replaces` or `skipRange`) in a reviewed change, so any number of channels and parallel version streams
  can be maintained. `make catalog-render` renders every bundle the channels list (published ones from
  `ghcr.io/stakater/sops-operator-bundle:vX.Y.Z`) into `catalog/release/index.yaml` and validates it; a version
  listed in no channel builds no catalog, and a bundle that cannot be rendered fails the build.
```

Decision row:

```markdown
| D42 | Catalog releases follow Hestia's promotion flow (hand-edited `channels.yaml`, all listed bundles re-rendered) and fail on any bundle that cannot be rendered | Customers run several versions in parallel across channels; releases must be declarative and reviewed, and a missing bundle must never silently remove a version from the upgrade graph. |
```

- [ ] **Step 8: Commit**

```bash
git add catalog catalog.Dockerfile hack/generate-catalog-index.sh hack/test-generate-catalog-index.sh Makefile DESIGN.md
git commit -m "feat(olm): file-based catalog with channel promotion"
```

---

### Task 5: Kind cluster with a local registry and OLM

**Files:**
- Create: `hack/kind-with-registry.sh`
- Modify: `Makefile` (`setup-test-e2e-olm`, `cleanup-test-e2e-olm`)

**Interfaces:**
- Produces: Kind cluster `$(KIND_CLUSTER_OLM)` (default `sops-operator-test-e2e-olm`) whose nodes pull `localhost:5001/<image>` from the registry container `kind-registry` over HTTP; OLM `$(OLM_VERSION)` installed; kubeconfig file `bin/kubeconfig-$(KIND_CLUSTER_OLM)`; host pushes go to `localhost:5001`.

- [ ] **Step 1: Write the script**

From the kind local-registry guide. kind v0.33 nodes run containerd 2 with config `version = 2` and no `config_path` (checked on the current e2e node), so the patch is required.

`hack/kind-with-registry.sh`:

```bash
#!/usr/bin/env bash
# Creates Kind cluster CLUSTER (node image NODE_IMAGE) whose nodes pull localhost:5001/* from the
# registry container kind-registry (image REGISTRY_IMAGE) over HTTP. Idempotent.
# Usage: kind-with-registry.sh KIND CLUSTER NODE_IMAGE REGISTRY_IMAGE
set -euo pipefail
KIND=$1 CLUSTER=$2 NODE_IMAGE=$3 REGISTRY_IMAGE=$4
reg_name=kind-registry
reg_port=5001

if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != true ]; then
  docker run -d --restart=always -p "127.0.0.1:${reg_port}:5000" --network bridge --name "${reg_name}" "${REGISTRY_IMAGE}"
fi

if ! "${KIND}" get clusters | grep -qx "${CLUSTER}"; then
  "${KIND}" create cluster --name "${CLUSTER}" --image "${NODE_IMAGE}" --config=- <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
fi

dir="/etc/containerd/certs.d/localhost:${reg_port}"
for node in $("${KIND}" get nodes --name "${CLUSTER}"); do
  docker exec "${node}" mkdir -p "${dir}"
  printf '[host."http://%s:5000"]\n' "${reg_name}" | docker exec -i "${node}" cp /dev/stdin "${dir}/hosts.toml"
done

if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = null ]; then
  docker network connect kind "${reg_name}"
fi
```

- [ ] **Step 2: Add the Makefile targets**

```makefile
KIND_CLUSTER_OLM ?= sops-operator-test-e2e-olm
OLM_VERSION ?= 0.46.0
REGISTRY_IMAGE ?= registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e
OLM_KUBECONFIG = $(LOCALBIN)/kubeconfig-$(KIND_CLUSTER_OLM)

.PHONY: setup-test-e2e-olm
setup-test-e2e-olm: kind operator-sdk ## Kind cluster with a local registry (localhost:5001) and OLM, for OLM e2e tests and scorecard.
	hack/kind-with-registry.sh $(KIND) $(KIND_CLUSTER_OLM) $(KIND_NODE_IMAGE) $(REGISTRY_IMAGE)
	$(KIND) get kubeconfig --name $(KIND_CLUSTER_OLM) > $(OLM_KUBECONFIG)
	KUBECONFIG=$(OLM_KUBECONFIG) $(OPERATOR_SDK) olm status >/dev/null 2>&1 \
		|| KUBECONFIG=$(OLM_KUBECONFIG) $(OPERATOR_SDK) olm install --version $(OLM_VERSION) --timeout 5m

.PHONY: cleanup-test-e2e-olm
cleanup-test-e2e-olm: kind ## Tear down the OLM Kind cluster (the registry container is kept).
	$(KIND) delete cluster --name $(KIND_CLUSTER_OLM)
```

- [ ] **Step 3: Verify the cluster pulls from the registry and OLM runs**

```bash
make setup-test-e2e-olm
docker pull busybox:1.37 && docker tag busybox:1.37 localhost:5001/busybox:1.37 && docker push localhost:5001/busybox:1.37
kubectl --context kind-sops-operator-test-e2e-olm run pull-check --image=localhost:5001/busybox:1.37 --restart=Never --command -- true
kubectl --context kind-sops-operator-test-e2e-olm wait pod/pull-check --for=jsonpath='{.status.phase}'=Succeeded --timeout=90s
kubectl --context kind-sops-operator-test-e2e-olm delete pod pull-check
KUBECONFIG=bin/kubeconfig-sops-operator-test-e2e-olm bin/operator-sdk olm status
make setup-test-e2e-olm   # second run: nothing recreated
```

Expected: the pod reaches `Succeeded`; `olm status` lists OLM resources as `Installed`; the second run creates nothing and exits 0. If `olm install` fails for 0.46.0, read the error, use the newest OLM v0 release that installs, and ledger a ruling for the pin.

- [ ] **Step 4: Run scorecard on this cluster** (the one CI uses)

Run: `make scorecard SCORECARD_CLUSTER=sops-operator-test-e2e-olm`
Expected: all six tests pass.

- [ ] **Step 5: Commit**

```bash
git add hack/kind-with-registry.sh Makefile
git commit -m "test(e2e): kind cluster with a local registry and OLM"
```

---

### Task 6: E2E against an OLM install from the catalog

**Files:**
- Modify: `test/e2e/main_test.go` (install modes)
- Modify: `test/e2e/helpers_test.go` (`renderFile` without `*testing.T`)
- Create: `test/e2e/fixtures/olm-install.yaml`
- Modify: `test/e2e/operator_restart_test.go` (restart by deleting the pod)
- Modify: `Makefile` (`test-e2e-olm`)
- Modify: `DESIGN.md` (§9 Testing, decision D43)

**Interfaces:**
- Consumes: Tasks 1, 3, 4, 5 (`make bundle`, `RESYNC_INTERVAL`, `make catalog-render`, `setup-test-e2e-olm`).
- Produces: `make test-e2e-olm [E2E_OLM_OPERATOR_IMG=<prebuilt local image>]`; env `E2E_INSTALL=kustomize|olm` and `E2E_CATALOG_IMG` read by `test/e2e`.

- [ ] **Step 1: Make the restart test independent of who owns the Deployment**

Under OLM the CSV owns the Deployment and may revert `kubectl rollout restart`'s template annotation. Restart by deleting the operator pod; the lease wait already detects the new process. In `test/e2e/operator_restart_test.go`, replace the `kubectl rollout restart/status` loop with:

```go
		// Delete the pod rather than restarting the Deployment: under OLM the CSV owns the Deployment.
		if err := k8s.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(operatorNamespace),
			client.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			t.Fatal(err)
		}
```

(import `corev1 "k8s.io/api/core/v1"`; drop the now unused `kubectl` slice). Run `make test-e2e` and confirm `TestOperatorRestart` passes on the kustomize install. Then prove it still fails for the right reason: temporarily make the SopsSecret reconciler read through the cache (in `Reconcile`, delete the `if r.APIReader != nil { reader = r.APIReader }` branch — the D38 bug) and run `make test-e2e`. Expected: `TestOperatorRestart` FAILs at `waitForNewSync` with a `Conflict` reason. Restore and ledger the output.

- [ ] **Step 2: Write the install fixture**

`test/e2e/fixtures/olm-install.yaml`:

```yaml
# Installs the operator the way a customer does: catalog, OperatorGroup for all namespaces, Subscription.
apiVersion: v1
kind: Namespace
metadata:
  name: {{ .Namespace }}
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: sops-operator-catalog
  namespace: {{ .Namespace }}
spec:
  sourceType: grpc
  image: {{ .CatalogImage }}
  displayName: SOPS Operator (e2e)
  grpcPodConfig:
    securityContextConfig: restricted
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: sops-operator
  namespace: {{ .Namespace }}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: sops-operator
  namespace: {{ .Namespace }}
spec:
  channel: alpha
  name: sops-operator
  source: sops-operator-catalog
  sourceNamespace: {{ .Namespace }}
  installPlanApproval: Automatic
  config:
    env:
      - name: RESYNC_INTERVAL
        value: {{ .ResyncInterval }}
```

- [ ] **Step 3: Split setup into install modes**

In `test/e2e/helpers_test.go`, move the template rendering out of `render` so setup can use it without a `*testing.T`:

```go
// renderFile renders fixtures/<fixture> with data.
func renderFile(fixture string, data any) ([]byte, error) {
	tpl, err := template.ParseFiles(filepath.Join("fixtures", fixture))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = tpl.Execute(&b, data)
	return b.Bytes(), err
}

func render(t *testing.T, fixture string, data any) []byte {
	t.Helper()
	b, err := renderFile(fixture, data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
```

(keep any template functions the existing `render` registers.) In `test/e2e/main_test.go`, move the image build/load, kustomize deploy, tenant-rbac apply and rollout steps of `setup` unchanged into `installWithKustomize(cluster string) error`, and make `setup` choose after the scheme registration:

```go
	var err error
	switch install := envOr("E2E_INSTALL", "kustomize"); install {
	case "kustomize":
		err = installWithKustomize(cluster)
	case "olm":
		err = installWithOLM()
	default:
		err = fmt.Errorf("E2E_INSTALL=%q: want kustomize or olm", install)
	}
	if err != nil {
		return err
	}
```

followed by the existing client creation and the `SopsTenantList` check. Add:

```go
// installWithOLM installs the operator from the catalog image E2E_CATALOG_IMG, published by
// `make test-e2e-olm`, through a Subscription, as a customer does. The tenant ClusterRoles come
// from the bundle; nothing from config/ is applied.
func installWithOLM() error {
	catalog := os.Getenv("E2E_CATALOG_IMG")
	if catalog == "" {
		return fmt.Errorf("E2E_CATALOG_IMG is not set (run make test-e2e-olm)")
	}
	kubectl := func(stdin string, args ...string) (string, error) {
		return run(stdin, "kubectl", append([]string{"--context", kubeContext}, args...)...)
	}
	// A rerun replaces the previous install so the new catalog image is used.
	if _, err := kubectl("", "delete", "namespace", operatorNamespace, "--ignore-not-found", "--wait", "--timeout=180s"); err != nil {
		return err
	}
	manifests, err := renderFile("olm-install.yaml", map[string]any{
		"Namespace": operatorNamespace, "CatalogImage": catalog, "ResyncInterval": resyncInterval,
	})
	if err != nil {
		return err
	}
	if _, err := kubectl(string(manifests), "apply", "-f", "-"); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"-n", operatorNamespace, "wait", "subscription/sops-operator", "--for=jsonpath={.status.state}=AtLatestKnown", "--timeout=300s"},
		{"-n", operatorNamespace, "wait", "csv", "--all", "--for=jsonpath={.status.phase}=Succeeded", "--timeout=300s"},
		{"-n", operatorNamespace, "rollout", "status", "deployment/sops-operator-controller-manager", "--timeout=180s"},
	} {
		if _, err := kubectl("", args...); err != nil {
			return err
		}
	}
	return nil
}
```

If Step 5 shows `kubectl wait` erroring on the Subscription before it has a status, or on `csv --all` before the CSV exists, wrap those waits in a retry of up to 120 s (every 2 s) and ledger it.

- [ ] **Step 4: Add the Makefile target**

```makefile
E2E_REGISTRY ?= localhost:5001
# A new tag per run so OLM never reuses a cached catalog or bundle.
E2E_OLM_TAG := e2e-$(shell date +%s)
# Set to an operator image that already exists locally (e.g. built in CI) to skip the build.
E2E_OLM_OPERATOR_IMG ?=

.PHONY: test-e2e-olm
test-e2e-olm: setup-test-e2e-olm opm yq sops kustomize operator-sdk ## Run the e2e tests against the operator installed by OLM from a freshly built catalog.
ifeq ($(E2E_OLM_OPERATOR_IMG),)
	$(CONTAINER_TOOL) build -t $(E2E_REGISTRY)/sops-operator:$(E2E_OLM_TAG) .
else
	$(CONTAINER_TOOL) tag $(E2E_OLM_OPERATOR_IMG) $(E2E_REGISTRY)/sops-operator:$(E2E_OLM_TAG)
endif
	$(CONTAINER_TOOL) push $(E2E_REGISTRY)/sops-operator:$(E2E_OLM_TAG)
	$(MAKE) bundle IMG=$(E2E_REGISTRY)/sops-operator:$(E2E_OLM_TAG)
	$(MAKE) bundle-build bundle-push BUNDLE_IMG=$(E2E_REGISTRY)/sops-operator-bundle:$(E2E_OLM_TAG)
	$(MAKE) catalog-render BUNDLE_IMG=$(E2E_REGISTRY)/sops-operator-bundle:$(E2E_OLM_TAG) OPM_RENDER_FLAGS=--use-http
	$(MAKE) catalog-build catalog-push CATALOG_IMG=$(E2E_REGISTRY)/sops-operator-catalog:$(E2E_OLM_TAG)
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER_OLM) KUSTOMIZE=$(KUSTOMIZE) SOPS=$(SOPS) YQ=$(YQ) \
		E2E_INSTALL=olm E2E_CATALOG_IMG=$(E2E_REGISTRY)/sops-operator-catalog:$(E2E_OLM_TAG) \
		go test ./test/e2e/ -v -count=1 -timeout 30m -parallel 12
```

(`-update` is deliberately not supported here: the OLM run must match the goldens recorded by `make test-e2e`.)

- [ ] **Step 5: Run it**

Run: `make test-e2e-olm 2>&1 | tee /tmp/e2e-olm.log | grep -E -- '^(--- |ok|FAIL)|golden files'`
Expected: every top-level test `--- PASS`, `ok …/test/e2e`, no golden diffs and no obsolete golden files. Then confirm the tenant ClusterRoles came from OLM, not from a manual apply:

```bash
kubectl --context kind-sops-operator-test-e2e-olm get clusterrole sops-key-owner sops-secret-writer \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.labels.olm\.owner}{"\n"}{end}'
```

Expected: both names followed by `sops-operator.v0.0.1`.

- [ ] **Step 6: Prove the OLM mode fails for the right reasons**

1. Remove `- ../tenant-rbac` from `config/manifests/kustomization.yaml` and rerun `make test-e2e-olm`. Expected: FAIL in `onboardedTenant` with tenants stuck at `AccessDenied` (the onboarding RoleBindings reference ClusterRoles that do not exist). Restore.
2. Remove the `config.env` block from `fixtures/olm-install.yaml` and rerun `make test-e2e-olm`. Expected: FAIL in `TestSelfHealing` with "timed out waiting for the Secret to be recreated" (the operator resyncs every 10 minutes). Restore.

Ledger both outputs.

- [ ] **Step 7: Document**

DESIGN.md §9 Testing, append:

```markdown
  `make test-e2e-olm` runs the same suite and golden files against an install by OLM: it builds the operator,
  bundle and catalog images, pushes them to a local registry (`localhost:5001`), installs OLM v0 on a dedicated
  kind cluster and subscribes to the catalog, passing `RESYNC_INTERVAL=10s` through `Subscription.spec.config.env`.
  Nothing from `config/` is applied, so the tenant ClusterRoles must come from the bundle. `make scorecard` runs the
  operator-sdk basic and OLM suites against the bundle.
```

Decision row:

```markdown
| D43 | OLM e2e installs from the rendered catalog through a Subscription, not `operator-sdk run bundle` | Tests the path customers use (catalog, channel, OperatorGroup, Subscription config), works with kind's standard local registry, and exercises the promotion flow on every pull request. |
```

- [ ] **Step 8: Commit**

```bash
git add test/e2e Makefile DESIGN.md
git commit -m "test(e2e): run the e2e suite against an OLM install from the catalog"
```

---

### Task 7: CI for bundle, catalog, scorecard and OLM e2e

**Files:**
- Modify: `.github/workflows/pull_request.yaml`

**Interfaces:**
- Consumes: `make csv`, `make test-catalog`, `make setup-test-e2e-olm`, `make test-e2e-olm E2E_OLM_OPERATOR_IMG=…`, `make scorecard SCORECARD_CLUSTER=…`; the `image` artifact of the build job (`sops-operator:pr`).

- [ ] **Step 1: Extend the generated-files check and add the catalog test** in the `verify` job:

```yaml
      - name: Check generated files are up to date
        run: |
          make manifests generate csv
          go mod tidy
          git diff --exit-code

      - name: Test catalog promotion
        run: make test-catalog
```

- [ ] **Step 2: Add the OLM job** after `e2e` (both run after `build`, in parallel):

```yaml
  e2e-olm:
    name: E2E on OLM
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e  # v7.0.0
        with:
          go-version-file: go.mod

      # kind, kustomize, controller-gen, operator-sdk, opm, sops and yq; all pinned in the Makefile.
      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9  # v6.1.0
        with:
          path: bin
          key: e2e-olm-tools-${{ runner.os }}-${{ hashFiles('Makefile', 'hack/bootstrap-tools.sh') }}

      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333  # v8.0.2
        with:
          name: image
          path: ${{ runner.temp }}

      # Installs the image built above through OLM from a catalog rendered from catalog/channels.yaml;
      # all images go to a registry on the runner only.
      - name: Run e2e tests on OLM
        run: |
          docker load -i "${RUNNER_TEMP}/image.tar"
          make test-e2e-olm E2E_OLM_OPERATOR_IMG=sops-operator:pr

      - name: Scorecard
        run: make scorecard SCORECARD_CLUSTER=sops-operator-test-e2e-olm
```

and change the `push` job to `needs: [e2e, e2e-olm]`.

- [ ] **Step 3: Review against the authoring-github-actions checklist**

Every `uses:` pinned by SHA (reuse the pins above); job permissions `contents: read`; no PR-controlled values interpolated into `run:`; the only write token stays in `push`, which runs no PR code; `hashFiles` paths are workspace-relative. Fix any ❌ before committing.

- [ ] **Step 4: Validate locally and commit**

```bash
make manifests generate csv && go mod tidy && git diff --exit-code && make test-catalog lint test
git add .github/workflows/pull_request.yaml
git commit -m "ci: bundle, catalog, scorecard and OLM e2e on pull requests"
```

Expected: no diff, all green. Pushing to the PR is the user's call; when they approve the push, watch the run (`gh run watch <id> --repo stakater/sops-operator --exit-status`) and report each job's result and duration.
