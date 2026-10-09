# SOPS Operator Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the operator core — toolchain bootstrap, `SopsTenant` and `SopsSecret` APIs, key handling, SOPS decryption, and the two controllers — with zero standing Secret privileges, verified against a real API server with RBAC enforced.

**Architecture:** operator-sdk (go/v4) project. Pure packages (`internal/crypto`, `internal/document`) do key parsing and SOPS decryption. `internal/identity` builds clients that impersonate a tenant's `sops` ServiceAccount; `internal/secretwriter` writes Secrets without ever reading them, using the stored Secret UID as an update precondition. Two controllers in `internal/controller` tie it together. All integration tests run on envtest with the RBAC authorizer and a non-admin operator user bound to the generated operator ClusterRole.

**Tech Stack:** Go ≥ 1.25.8, operator-sdk v1.42.3 (go/v4 plugin), opm v1.74.0, controller-runtime, envtest (Kubernetes 1.31), `github.com/getsops/sops/v3` v3.13.3, `filippo.io/age` v1.3.1, gomega.

**Spec:** `DESIGN.md` (repository root). Read §4 (API), §5 (authorization), §6 (zero trust) before starting.

**Scope:** This is plan 1 of 3. Plan 2 covers the OLM bundle/catalog (using the `opm` installed here) and kind e2e tests; plan 3 covers GitHub Actions CI. Not in this plan: bundle manifests, e2e, CI, docs beyond `DESIGN.md`.

## Global Constraints

- Go module `github.com/stakater/sops-operator`; API group/version `sops.stakater.com/v1alpha1` (D25).
- Tool versions: operator-sdk `v1.42.3`, opm `v1.74.0`, installed into `./bin` by `hack/bootstrap-tools.sh` with checksum verification. All commands use `bin/operator-sdk` and `bin/opm`, never a globally installed copy.
- Minimum Kubernetes 1.31; envtest runs Kubernetes 1.31 (D27).
- `github.com/getsops/sops/v3` v3.13.3 and `filippo.io/age` v1.3.1; sops requires Go ≥ 1.25.8.
- The operator's own identity has **no** permission on Secrets, Roles, RoleBindings or ServiceAccounts other than `impersonate` on ServiceAccounts named `sops` (D9).
- Tenant identity user name: `system:serviceaccount:<tenant-namespace>:sops`.
- Shipped ClusterRoles keep these exact names: `sops-key-owner` (`secrets`: `get`, `create`), `sops-secret-writer` (`secrets`: `create`, `update`).
- Generated keys are age post-quantum hybrid (`AGE-SECRET-KEY-PQ-1…`, recipient `age1pq1…`) (D6).
- Key Secret field name: `age.agekey`. Key Secret name/namespace = `SopsTenant` name/namespace.
- Required SOPS settings: `encrypted_regex: ^(data|stringData|scope)$`, `mac_only_encrypted: true`, age recipients only, one key group.
- Never put private keys or decrypted values in logs, events, status messages or error strings.
- Commit messages: conventional commits; **no** `Co-Authored-By` line and no mention of Claude or AI.

## Review Focus

1. A file encrypted without sorting keys first → status `DecryptFailed` with a message that tells the user to run `yq -i 'sort_keys(..)'` before encrypting (test in Task 5).
2. Non-string `stringData` values (`port: 5432`, `enabled: true`) → written as `"5432"` / `"true"`, like `kubectl` does (test in Task 8).
3. Invalid base64 in `data` → `DecryptFailed` naming the key but never the value (test in Task 8).
4. Key Secret with CRLF line endings, trailing spaces and comments → still loads (test in Task 4).
5. `SopsSecret` deleted with `deletionPolicy: Retain` and recreated with the same name → `Conflict`, the existing Secret is not overwritten (test in Task 12).

---

## File Structure

| Path | Responsibility |
|---|---|
| `DESIGN.md` | Spec; updated in Task 1 with implementation decisions |
| `hack/bootstrap-tools.sh` | Installs pinned, checksum-verified `operator-sdk` and `opm` into `bin/` |
| `api/v1alpha1/sopstenant_types.go` | `SopsTenant` API |
| `api/v1alpha1/sopssecret_types.go` | `SopsSecret` API, SOPS metadata schema, CEL rules |
| `api/v1alpha1/constants.go` | Condition type, reasons, labels, annotations |
| `api/v1alpha1/validation_test.go` | CRD validation tests (envtest) |
| `internal/crypto/keys.go` | Parse/generate age key files |
| `internal/crypto/sops.go` | SOPS recipients + decryption with in-memory identities |
| `internal/crypto/cryptotest/encrypt.go` | Test helper: encrypt like `sops encrypt` |
| `internal/document/document.go` | Canonical encrypted document from a `SopsSecret`; plaintext payload parsing |
| `internal/identity/identity.go` | Impersonating client factory; SubjectAccessReview grant check |
| `internal/secretwriter/writer.go` | Write-only create/update with UID precondition |
| `internal/controller/rbac.go` | Operator RBAC markers (single source for `config/rbac/role.yaml`) |
| `internal/controller/indexes.go` | Field index `spec.tenantRef` |
| `internal/controller/sopstenant_controller.go` | Tenant key reconciler |
| `internal/controller/sopssecret_controller.go` | SopsSecret reconciler |
| `internal/testenv/testenv.go` | envtest harness with RBAC, operator user, onboarding helper |
| `config/tenant-rbac/` | Shipped tenant-facing ClusterRoles |
| `cmd/main.go` | Manager wiring and flags |

---

### Task 1: Record implementation decisions in DESIGN.md

**Files:**
- Modify: `DESIGN.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the spec text later tasks implement (writer verbs, Retain semantics, key sorting, SOPS metadata constraints, `status.secretUID`, tool versions).

- [ ] **Step 1: Update §4.3 `SopsSecret` example status**

In the `SopsSecret` YAML example, replace:

```yaml
status:
  observedGeneration: 1
  lastSyncTime: "2026-10-09T10:00:00Z"
```

with:

```yaml
status:
  observedGeneration: 1
  lastSyncTime: "2026-10-09T10:00:00Z"
  secretUID: 6f1c2b8e-0d1a-4c5e-9b7f-2a3d4e5f6a7b   # UID of the Secret this SopsSecret created
```

- [ ] **Step 2: Update §4.3 field table rows**

Replace the `spec.deletionPolicy` row's meaning with:
`` `Delete`: the output Secret has an ownerReference to the `SopsSecret` and is garbage-collected with it. `Retain`: the output Secret has no ownerReference and stays when the `SopsSecret` is deleted. ``

Replace the `sops` row's meaning with:
`` SOPS metadata written by `sops encrypt`. Must contain `mac`, `lastmodified`, `version`, at least one `age` recipient, `encrypted_regex: ^(data|stringData|scope)$` and `mac_only_encrypted: true`. Only age recipients in a single key group are supported; other key types are rejected by the schema. ``

- [ ] **Step 3: Update §4.3 behaviour bullets**

Replace the bullet starting "Output Secrets carry an ownerReference" with:

```markdown
- With `deletionPolicy: Delete`, output Secrets carry an ownerReference to the `SopsSecret` (Argo CD shows them as
  children; `blockOwnerDeletion` is not set). Output Secrets never carry GitOps tracking labels or annotations
  (`argocd.argoproj.io/*`, `kustomize.toolkit.fluxcd.io/*`), so GitOps tools do not prune them.
- `status.secretUID` records the Secret the operator created. Every later write is an update with that UID as a
  precondition: `404` → recreate, `409` → `Conflict`. A `SopsSecret` without `status.secretUID` whose Secret already
  exists is a `Conflict`.
```

- [ ] **Step 4: Update §5.2 and §5.3 permissions**

In the §5.2 table, set the `sops-secret-writer` rules cell to `` `secrets`: `create`, `update` — no read (D28) `` and add below the table:

```markdown
The tenant-facing ClusterRoles are shipped from `config/tenant-rbac/` with exactly these names (not prefixed).
```

In §5.3, replace the first rule block

```yaml
- apiGroups: [sops.stakater.com]
  resources: [sopstenants, sopssecrets]
  verbs: [get, list, watch, update, patch]
```

with

```yaml
- apiGroups: [sops.stakater.com]
  resources: [sopstenants, sopssecrets]
  verbs: [get, list, watch]
```

- [ ] **Step 5: Add key sorting to §8.2**

In the §8.2 bash block, insert this line directly before `sops encrypt -i prod/db-creds.sops.yaml`:

```bash
yq -i 'sort_keys(..)' prod/db-creds.sops.yaml
```

and add this bullet after the bash block:

```markdown
- Keys must be sorted before encryption. The SOPS MAC depends on key order and the Kubernetes API returns objects with
  keys sorted; an unsorted file fails with `DecryptFailed`.
```

- [ ] **Step 6: Record tool versions in §9 Delivery**

Append to the **Language/framework** bullet in §9: `` Tools pinned and checksum-verified by `hack/bootstrap-tools.sh`: operator-sdk v1.42.3, opm v1.74.0. ``

- [ ] **Step 7: Update the decision log**

Replace "sending it as a precondition on every patch" with "sending it as a precondition on every update" in D28, and insert these rows directly after the D28 row (D34 already exists below it):

```markdown
| D29 | Files are key-sorted (`yq 'sort_keys(..)'`) before encryption | The SOPS MAC is order-dependent and the API server returns keys sorted. |
| D30 | `Retain` means "no ownerReference"; no finalizer on `SopsSecret` | Deletion needs no Secret access and no extra verbs. |
| D31 | Only age recipients in one key group; `encrypted_regex` and `mac_only_encrypted` enforced by the CRD schema | Unsupported files are rejected at apply time, not at decryption. |
| D32 | Tenant-facing ClusterRoles shipped from `config/tenant-rbac/` with fixed names | Onboarding templates reference stable names. |
| D33 | operator-sdk and opm are pinned and installed per project into `bin/` with checksum verification | Reproducible builds locally and in CI; no reliance on globally installed tools. |
```

- [ ] **Step 8: Commit**

```bash
git add DESIGN.md
git commit -m "docs: record implementation decisions for writer role, retain, key sorting and tools"
```

---

### Task 2: Bootstrap the toolchain

**Files:**
- Create: `hack/bootstrap-tools.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `bin/operator-sdk` (v1.42.3) and `bin/opm` (v1.74.0); the script reads overrides from `OPERATOR_SDK_VERSION` and `OPM_VERSION`.

Prerequisites installed by the developer (not by this script): Go ≥ 1.25.8, `make`, `curl`, `git`. Everything else (controller-gen, kustomize, setup-envtest, golangci-lint) is installed into `bin/` by the scaffolded `Makefile` in Task 3.

- [ ] **Step 1: Write the bootstrap script**

`hack/bootstrap-tools.sh`:

```bash
#!/usr/bin/env bash
# Installs pinned operator-sdk and opm into ./bin, verifying the release checksums.
set -euo pipefail

OPERATOR_SDK_VERSION="${OPERATOR_SDK_VERSION:-v1.42.3}"
OPM_VERSION="${OPM_VERSION:-v1.74.0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT}/bin"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${BIN_DIR}"

# install <release base URL> <asset name> <target name>
install_verified() {
  local base="$1" asset="$2" target="$3"
  curl -fsSL -o "${TMP}/${asset}" "${base}/${asset}"
  curl -fsSL -o "${TMP}/checksums.txt" "${base}/checksums.txt"
  if ! grep -E "[[:space:]]${asset}\$" "${TMP}/checksums.txt" > "${TMP}/expected.txt"; then
    echo "no checksum for ${asset} in ${base}/checksums.txt" >&2
    exit 1
  fi
  (cd "${TMP}" && shasum -a 256 -c expected.txt)
  install -m 0755 "${TMP}/${asset}" "${BIN_DIR}/${target}"
}

install_verified \
  "https://github.com/operator-framework/operator-sdk/releases/download/${OPERATOR_SDK_VERSION}" \
  "operator-sdk_${OS}_${ARCH}" operator-sdk
install_verified \
  "https://github.com/operator-framework/operator-registry/releases/download/${OPM_VERSION}" \
  "${OS}-${ARCH}-opm" opm

"${BIN_DIR}/operator-sdk" version
"${BIN_DIR}/opm" version
```

- [ ] **Step 2: Run it**

```bash
chmod +x hack/bootstrap-tools.sh
hack/bootstrap-tools.sh
```

Expected: two `…: OK` checksum lines, then `operator-sdk version: "v1.42.3"…` and an `opm` version line containing `v1.74.0`. A checksum mismatch aborts the script with a non-zero exit code; do not continue in that case.

- [ ] **Step 3: Check Go**

Run: `go version`
Expected: `go1.25.8` or newer. If older, upgrade Go before Task 3.

- [ ] **Step 4: Commit**

```bash
git add hack/bootstrap-tools.sh
git commit -m "build: bootstrap pinned operator-sdk and opm with checksum verification"
```

---

### Task 3: Scaffold the operator-sdk project

**Files:**
- Create (generated): `go.mod`, `Makefile`, `PROJECT`, `cmd/main.go`, `api/v1alpha1/*`, `internal/controller/*`, `config/**`, `test/**`, `Dockerfile`, `hack/boilerplate.go.txt`
- Delete: `internal/controller/suite_test.go`, `internal/controller/sopstenant_controller_test.go`, `internal/controller/sopssecret_controller_test.go`
- Modify: `Makefile` (tool versions, envtest version), `.gitignore` (keep secret patterns)

**Interfaces:**
- Consumes: `bin/operator-sdk`, `bin/opm` (Task 2).
- Produces: packages `github.com/stakater/sops-operator/api/v1alpha1` (with `GroupVersion`, `AddToScheme`) and `github.com/stakater/sops-operator/internal/controller`; make targets `manifests`, `generate`, `build`, `test`, `lint`, `setup-envtest`, `operator-sdk`, `opm`.

- [ ] **Step 1: Initialise the project**

```bash
cd /Users/julian/Projects/sealed-secrets
bin/operator-sdk init --domain stakater.com --repo github.com/stakater/sops-operator \
  --plugins=go/v4 --project-name sops-operator
```

Expected: scaffolding completes. If it fails with "target directory is not empty and contains a disallowed file", move `docs/` and `hack/` aside (`mv docs ../sops-docs-tmp && mv hack ../sops-hack-tmp`), rerun, then move them back (`mv ../sops-docs-tmp docs`; copy `../sops-hack-tmp/bootstrap-tools.sh` into the scaffolded `hack/` and remove `../sops-hack-tmp`).

- [ ] **Step 2: Restore secret patterns in .gitignore**

Run `git diff .gitignore`. If the scaffold replaced the file, append:

```gitignore
# Plaintext secrets must never be committed
*.dec.yaml
*.plain.yaml
*.agekey
age.key
key.txt
```

- [ ] **Step 3: Pin tool versions and align the Makefile with Stakater operators**

The scaffolded `Makefile` downloads `operator-sdk` and `opm` itself when they are missing from `bin/`. Make it use the same versions as `hack/bootstrap-tools.sh`:

1. Set the line starting with `OPERATOR_SDK_VERSION ?=` to `OPERATOR_SDK_VERSION ?= v1.42.3`.
2. In the `opm` target, replace the hard-coded opm release in the download URL (e.g. `v1.23.0`) with `$(OPM_VERSION)`, and add near the other version variables: `OPM_VERSION ?= v1.74.0`.
3. Set the line starting with `ENVTEST_K8S_VERSION ?=` to `ENVTEST_K8S_VERSION ?= 1.31.0`.

Stakater operators (e.g. `stakater/Hestia`) share reusable CI in `stakater/.github`, which calls these Makefile variables and targets. Use the same names so plan 3 can reuse that CI. Replace the scaffolded `VERSION ?=` and `IMAGE_TAG_BASE ?=` lines with:

```makefile
VERSION ?= 0.0.1
OPERATOR_NAME ?= sops-operator
CATALOG_DIR_PATH ?= catalog
DOCKER_REPO_BASE ?= ghcr.io/stakater
IMAGE_TAG_BASE ?= $(DOCKER_REPO_BASE)/$(OPERATOR_NAME)
```

and set `IMG ?= $(IMAGE_TAG_BASE):v$(VERSION)`. Keep the scaffolded `BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)` and `CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)`. The targets `catalog-render`, `cluster` and `test-e2e` used by the shared CI are added in plan 2.

Run: `make operator-sdk opm && bin/operator-sdk version && bin/opm version`
Expected: both report the pinned versions (the targets reuse the binaries already in `bin/`).

- [ ] **Step 4: Create the two APIs**

```bash
bin/operator-sdk create api --group sops --version v1alpha1 --kind SopsTenant --resource --controller
bin/operator-sdk create api --group sops --version v1alpha1 --kind SopsSecret --resource --controller
```

Expected: `api/v1alpha1/sopstenant_types.go`, `api/v1alpha1/sopssecret_types.go`, `internal/controller/sopstenant_controller.go`, `internal/controller/sopssecret_controller.go` exist.

- [ ] **Step 5: Add dependencies and remove Ginkgo scaffold tests**

```bash
go get github.com/getsops/sops/v3@v3.13.3 filippo.io/age@v1.3.1 github.com/onsi/gomega
rm internal/controller/suite_test.go internal/controller/sopstenant_controller_test.go internal/controller/sopssecret_controller_test.go
go mod tidy
```

The plan uses plain `go test` with gomega matchers; the Ginkgo suite would start a second envtest.

- [ ] **Step 6: Build and prepare envtest**

```bash
make manifests generate build setup-envtest
export KUBEBUILDER_ASSETS="$(bin/setup-envtest use 1.31.x --bin-dir bin -p path)"
echo "$KUBEBUILDER_ASSETS"
```

Expected: build succeeds; `KUBEBUILDER_ASSETS` prints a path under `bin/k8s/`. Every later `go test` command in this plan assumes this variable is exported.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: scaffold operator with operator-sdk v1.42.3 go/v4"
```

---

### Task 4: Age key files

**Files:**
- Create: `internal/crypto/keys.go`
- Test: `internal/crypto/keys_test.go`

**Interfaces:**
- Consumes: `filippo.io/age`.
- Produces:
  - `const crypto.KeyFileField = "age.agekey"`
  - `var crypto.ErrKeyInvalid error`
  - `type crypto.KeySet struct { Identities []age.Identity; Recipients []string }` — same order, first is primary
  - `func crypto.ParseKeyFile(data []byte) (*KeySet, error)`
  - `func crypto.GenerateKeyFile(now time.Time) (keyFile []byte, recipient string, err error)`

- [ ] **Step 1: Write the failing tests**

`internal/crypto/keys_test.go`:

```go
package crypto_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/stakater/sops-operator/internal/crypto"
)

func TestGenerateKeyFileIsPostQuantum(t *testing.T) {
	keyFile, recipient, err := crypto.GenerateKeyFile(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if !strings.HasPrefix(recipient, "age1pq1") {
		t.Fatalf("recipient %.12q… is not post-quantum", recipient)
	}
	if !bytes.Contains(keyFile, []byte("# public key: "+recipient)) {
		t.Fatal("key file does not contain the public key comment")
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatalf("ParseKeyFile: %v", err)
	}
	if len(ks.Recipients) != 1 || ks.Recipients[0] != recipient {
		t.Fatal("parsed recipient does not match the generated one")
	}
}

func TestParseKeyFileAcceptsMixedTypesInOrder(t *testing.T) {
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// CRLF line endings, trailing spaces, blank lines and comments must be tolerated.
	file := "# created: 2026-10-09T10:00:00Z\r\n" + pq.String() + "  \r\n\r\n# old key\n" + x.String() + "\n"

	ks, err := crypto.ParseKeyFile([]byte(file))
	if err != nil {
		t.Fatalf("ParseKeyFile: %v", err)
	}
	want := []string{pq.Recipient().String(), x.Recipient().String()}
	if !reflect.DeepEqual(ks.Recipients, want) {
		t.Fatal("recipients are not in file order")
	}
	if len(ks.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(ks.Identities))
	}
}

func TestParseKeyFileRejectsWithoutLeakingKeyMaterial(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	truncated := x.String()[:len(x.String())-4]
	cases := map[string]string{
		"empty":          "",
		"comments only":  "# public key: age1qqqq\n",
		"ssh key":        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"plugin":         "AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQ\n",
		"corrupt x25519": truncated + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.ParseKeyFile([]byte(in))
			if !errors.Is(err, crypto.ErrKeyInvalid) {
				t.Fatalf("got %v, want ErrKeyInvalid", err)
			}
			if strings.Contains(err.Error(), "AGE-SECRET-KEY") || strings.Contains(err.Error(), "AGE-PLUGIN") {
				t.Fatal("error message contains key material")
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crypto/ -run 'KeyFile' -v`
Expected: FAIL — `undefined: crypto.GenerateKeyFile` (package does not exist yet).

- [ ] **Step 3: Implement**

`internal/crypto/keys.go`:

```go
// Package crypto handles tenant age keys and SOPS decryption.
package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
)

// KeyFileField is the field of a tenant key Secret that holds the age identities.
const KeyFileField = "age.agekey"

// ErrKeyInvalid reports a key file that is empty or contains an unsupported or corrupt identity.
var ErrKeyInvalid = errors.New("invalid key file")

// KeySet holds the identities of a tenant key file and their recipients, in file order.
// The first identity is the primary one.
type KeySet struct {
	Identities []age.Identity
	Recipients []string
}

// ParseKeyFile parses an age identity file. Only X25519 and post-quantum hybrid identities
// are accepted. Errors never contain key material.
func ParseKeyFile(data []byte) (*KeySet, error) {
	ks := &KeySet{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			id, err := age.ParseHybridIdentity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d is not a valid post-quantum age identity", ErrKeyInvalid, n)
			}
			ks.Identities = append(ks.Identities, id)
			ks.Recipients = append(ks.Recipients, id.Recipient().String())
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d is not a valid X25519 age identity", ErrKeyInvalid, n)
			}
			ks.Identities = append(ks.Identities, id)
			ks.Recipients = append(ks.Recipients, id.Recipient().String())
		default:
			return nil, fmt.Errorf("%w: line %d is not an X25519 or post-quantum age identity", ErrKeyInvalid, n)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	if len(ks.Identities) == 0 {
		return nil, fmt.Errorf("%w: no identities", ErrKeyInvalid)
	}
	return ks, nil
}

// GenerateKeyFile generates a post-quantum hybrid age identity and renders it in the
// age-keygen file format.
func GenerateKeyFile(now time.Time) (keyFile []byte, recipient string, err error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, "", fmt.Errorf("generate age identity: %w", err)
	}
	recipient = id.Recipient().String()
	var b bytes.Buffer
	fmt.Fprintf(&b, "# created: %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# public key: %s\n", recipient)
	fmt.Fprintf(&b, "%s\n", id.String())
	return b.Bytes(), recipient, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/crypto/ -run 'KeyFile' -v`
Expected: PASS (3 tests, 5 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/keys.go internal/crypto/keys_test.go
git commit -m "feat(crypto): parse and generate post-quantum age key files"
```

---

### Task 5: SOPS decryption with in-memory identities

**Files:**
- Create: `internal/crypto/sops.go`, `internal/crypto/cryptotest/encrypt.go`
- Test: `internal/crypto/sops_test.go`

**Interfaces:**
- Consumes: `crypto.KeySet`, `crypto.ParseKeyFile`, `crypto.GenerateKeyFile` (Task 4).
- Produces:
  - `const crypto.EncryptedRegex = "^(data|stringData|scope)$"`
  - `var crypto.ErrMalformed, crypto.ErrUnsupported, crypto.ErrNotRecipient, crypto.ErrDecrypt error`
  - `func crypto.Recipients(doc []byte) ([]string, error)`
  - `func crypto.Decrypt(doc []byte, keys *KeySet) ([]byte, error)` — returns the plaintext YAML document
  - `func cryptotest.Encrypt(plain []byte, recipients ...string) ([]byte, error)` — test helper, same output as `sops encrypt` with the project's `.sops.yaml`

- [ ] **Step 1: Write the encryption test helper**

`internal/crypto/cryptotest/encrypt.go`:

```go
// Package cryptotest encrypts documents the way `sops encrypt` does with the project's
// .sops.yaml. It is used by tests only.
package cryptotest

import (
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/getsops/sops/v3/version"

	"github.com/stakater/sops-operator/internal/crypto"
)

// Encrypt encrypts a plaintext YAML document for the given age recipients with
// encrypted_regex ^(data|stringData|scope)$ and mac_only_encrypted.
func Encrypt(plain []byte, recipients ...string) ([]byte, error) {
	store := yaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plain)
	if err != nil {
		return nil, fmt.Errorf("load plaintext: %w", err)
	}
	var group sops.KeyGroup
	for _, r := range recipients {
		mk, err := sopsage.MasterKeyFromRecipient(r)
		if err != nil {
			return nil, fmt.Errorf("parse recipient: %w", err)
		}
		group = append(group, mk)
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:        []sops.KeyGroup{group},
			EncryptedRegex:   crypto.EncryptedRegex,
			MACOnlyEncrypted: true,
			Version:          version.Version,
		},
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
	if len(errs) > 0 {
		return nil, fmt.Errorf("generate data key: %w", errors.Join(errs...))
	}
	if err := common.EncryptTree(common.EncryptTreeOpts{Tree: &tree, Cipher: aes.NewCipher(), DataKey: dataKey}); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return store.EmitEncryptedFile(tree)
}
```

- [ ] **Step 2: Write the failing tests**

`internal/crypto/sops_test.go`:

```go
package crypto_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
)

// sortedPlain is a plaintext document whose keys are already sorted, as required (D29).
const sortedPlain = `spec:
  scope: solar-prod/db-creds
  stringData:
    a: one
    b: two
`

func newKeys(t *testing.T) *crypto.KeySet {
	t.Helper()
	keyFile, _, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func encrypt(t *testing.T, plain string, recipients ...string) []byte {
	t.Helper()
	enc, err := cryptotest.Encrypt([]byte(plain), recipients...)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return enc
}

// viaAPI simulates the Kubernetes API: the document is stored as JSON and returned with sorted keys.
func viaAPI(t *testing.T, doc []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(m)
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecryptRoundTrip(t *testing.T) {
	ks := newKeys(t)
	doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), nil)

	recipients, err := crypto.Recipients(doc)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if len(recipients) != 1 || recipients[0] != ks.Recipients[0] {
		t.Fatal("Recipients does not return the encryption recipient")
	}

	plain, err := crypto.Decrypt(doc, ks)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var got struct {
		Spec struct {
			Scope      string            `json:"scope"`
			StringData map[string]string `json:"stringData"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Scope != "solar-prod/db-creds" || got.Spec.StringData["a"] != "one" || got.Spec.StringData["b"] != "two" {
		t.Fatal("decrypted values do not match the plaintext")
	}
}

func TestDecryptNotRecipient(t *testing.T) {
	owner, other := newKeys(t), newKeys(t)
	doc := encrypt(t, sortedPlain, other.Recipients[0])
	if _, err := crypto.Decrypt(doc, owner); !errors.Is(err, crypto.ErrNotRecipient) {
		t.Fatalf("got %v, want ErrNotRecipient", err)
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	ks := newKeys(t)
	enc := encrypt(t, sortedPlain, ks.Recipients[0])
	cases := map[string]func(m map[string]any){
		"lastmodified changed": func(m map[string]any) {
			m["sops"].(map[string]any)["lastmodified"] = "2020-01-01T00:00:00Z"
		},
		"values swapped": func(m map[string]any) {
			sd := m["spec"].(map[string]any)["stringData"].(map[string]any)
			sd["a"], sd["b"] = sd["b"], sd["a"]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.Decrypt(viaAPI(t, enc, mutate), ks)
			if !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestDecryptUnsortedFileFailsWithHint(t *testing.T) {
	ks := newKeys(t)
	unsorted := "spec:\n  scope: solar-prod/db-creds\n  stringData:\n    b: two\n    a: one\n"
	doc := viaAPI(t, encrypt(t, unsorted, ks.Recipients[0]), nil)
	_, err := crypto.Decrypt(doc, ks)
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	if !strings.Contains(err.Error(), "sort_keys") {
		t.Fatalf("error %q does not tell the user to sort keys", err)
	}
}

func TestDecryptRejectsNonAgeKeys(t *testing.T) {
	ks := newKeys(t)
	doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), func(m map[string]any) {
		m["sops"].(map[string]any)["pgp"] = []any{map[string]any{
			"fp": "0000000000000000000000000000000000000000", "enc": "x", "created_at": "2026-01-01T00:00:00Z",
		}}
	})
	if _, err := crypto.Decrypt(doc, ks); !errors.Is(err, crypto.ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

func TestDecryptRejectsPlaintext(t *testing.T) {
	if _, err := crypto.Decrypt([]byte(sortedPlain), newKeys(t)); !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/crypto/... -run 'Decrypt' -v`
Expected: FAIL — `undefined: crypto.Decrypt`.

- [ ] **Step 4: Implement**

`internal/crypto/sops.go`:

```go
package crypto

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/yaml"
)

// EncryptedRegex is the only SOPS encrypted_regex the operator accepts.
const EncryptedRegex = "^(data|stringData|scope)$"

var (
	// ErrMalformed reports a document that is not a SOPS-encrypted YAML document.
	ErrMalformed = errors.New("malformed SOPS document")
	// ErrUnsupported reports SOPS key configurations other than age recipients in one key group.
	ErrUnsupported = errors.New("unsupported SOPS key configuration")
	// ErrNotRecipient reports a document that is not encrypted for any of the given keys.
	ErrNotRecipient = errors.New("document is not encrypted for this key")
	// ErrDecrypt reports a document that fails decryption or MAC verification.
	ErrDecrypt = errors.New("decryption failed")
)

func newStore() *yaml.Store { return yaml.NewStore(&config.YAMLStoreConfig{}) }

func load(doc []byte) (sops.Tree, error) {
	tree, err := newStore().LoadEncryptedFile(doc)
	if err != nil {
		return sops.Tree{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return tree, nil
}

// ageKeys returns the age master keys of a tree that has exactly one key group made of age keys only.
func ageKeys(tree sops.Tree) ([]*sopsage.MasterKey, error) {
	if n := len(tree.Metadata.KeyGroups); n != 1 {
		return nil, fmt.Errorf("%w: exactly one key group is required, found %d", ErrUnsupported, n)
	}
	var keys []*sopsage.MasterKey
	for _, k := range tree.Metadata.KeyGroups[0] {
		ak, ok := k.(*sopsage.MasterKey)
		if !ok {
			return nil, fmt.Errorf("%w: only age recipients are supported, found %s", ErrUnsupported, k.TypeToIdentifier())
		}
		keys = append(keys, ak)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no age recipients", ErrUnsupported)
	}
	return keys, nil
}

// Recipients returns the age recipients a document is encrypted for.
func Recipients(doc []byte) ([]string, error) {
	tree, err := load(doc)
	if err != nil {
		return nil, err
	}
	keys, err := ageKeys(tree)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Recipient)
	}
	return out, nil
}

// Decrypt decrypts a SOPS-encrypted YAML document with the given keys, verifies its MAC and
// returns the plaintext document. Identities are applied in memory to this document only.
func Decrypt(doc []byte, keys *KeySet) ([]byte, error) {
	tree, err := load(doc)
	if err != nil {
		return nil, err
	}
	fileKeys, err := ageKeys(tree)
	if err != nil {
		return nil, err
	}
	ids := sopsage.ParsedIdentities(keys.Identities)
	var dataKey []byte
	matched := false
	for _, k := range fileKeys {
		if !slices.Contains(keys.Recipients, k.Recipient) {
			continue
		}
		matched = true
		ids.ApplyToMasterKey(k)
		if dk, err := k.Decrypt(); err == nil {
			dataKey = dk
			break
		}
	}
	if !matched {
		return nil, ErrNotRecipient
	}
	if dataKey == nil {
		return nil, fmt.Errorf("%w: the data key could not be unwrapped", ErrDecrypt)
	}

	cipher := aes.NewCipher()
	computed, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	stored, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339))
	if s, ok := stored.(string); err != nil || !ok || s != computed {
		return nil, fmt.Errorf("%w: MAC mismatch; the file was modified, or its keys were not sorted "+
			"(yq -i 'sort_keys(..)') before encryption", ErrDecrypt)
	}
	plain, err := newStore().EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return plain, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/crypto/... -v`
Expected: PASS for all tests in Tasks 4 and 5.

- [ ] **Step 6: Commit**

```bash
git add internal/crypto/
git commit -m "feat(crypto): decrypt SOPS documents with in-memory age identities"
```

---

### Task 6: Operator RBAC, tenant roles and the envtest harness

**Files:**
- Create: `internal/controller/rbac.go`, `config/tenant-rbac/roles.yaml`, `config/tenant-rbac/kustomization.yaml`, `internal/testenv/testenv.go`
- Modify: `internal/controller/sopstenant_controller.go`, `internal/controller/sopssecret_controller.go` (delete `+kubebuilder:rbac` lines), `config/rbac/kustomization.yaml`
- Delete: generated `config/rbac/sopstenant_*_role.yaml`, `config/rbac/sopssecret_*_role.yaml`
- Test: `internal/testenv/testenv_test.go`

**Interfaces:**
- Consumes: `api/v1alpha1` scheme (Task 3).
- Produces:
  - Generated `config/rbac/role.yaml` (ClusterRole `manager-role`) from markers in `internal/controller/rbac.go`.
  - ClusterRoles `sops-key-owner`, `sops-secret-writer`, `sops-tenant-admin`, `sops-secret-editor`, `sops-viewer`.
  - `testenv.Start() (*testenv.Env, error)`, `(*Env).Stop() error`
  - `Env` fields: `Scheme *runtime.Scheme`, `Admin client.Client`, `OperatorConfig *rest.Config`, `Operator client.Client`
  - `(*Env).Namespace(t testing.TB, prefix string) string`
  - `(*Env).Onboard(t testing.TB, tenantNamespace string, writeNamespaces ...string)`

- [ ] **Step 1: Write the operator RBAC markers**

Delete every line starting with `// +kubebuilder:rbac` from `internal/controller/sopstenant_controller.go` and `internal/controller/sopssecret_controller.go`. Create `internal/controller/rbac.go`:

```go
package controller

// Operator permissions (DESIGN.md §5.3). The operator has no permission on Secrets; it reads
// tenant keys and writes Secrets only by impersonating tenant identities.
//
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants;sopssecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants/status;sopssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=impersonate,resourceNames=sops
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups="";events.k8s.io,resources=events,verbs=create;patch
```

- [ ] **Step 2: Write the tenant-facing roles**

`config/tenant-rbac/roles.yaml`:

```yaml
# Bound by the cluster admin to a tenant's "sops" ServiceAccount in the tenant namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sops-key-owner
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, create]
---
# Bound by the cluster admin to a tenant's "sops" ServiceAccount in each namespace the tenant may write to.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sops-secret-writer
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [create, update]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sops-tenant-admin
  labels:
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
rules:
  - apiGroups: [sops.stakater.com]
    resources: [sopstenants]
    verbs: [get, list, watch, create, update, patch, delete, deletecollection]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sops-secret-editor
  labels:
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
rules:
  - apiGroups: [sops.stakater.com]
    resources: [sopssecrets]
    verbs: [get, list, watch, create, update, patch, delete, deletecollection]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sops-viewer
  labels:
    rbac.authorization.k8s.io/aggregate-to-view: "true"
rules:
  - apiGroups: [sops.stakater.com]
    resources: [sopstenants, sopssecrets, sopstenants/status, sopssecrets/status]
    verbs: [get, list, watch]
```

`config/tenant-rbac/kustomization.yaml`:

```yaml
resources:
  - roles.yaml
```

- [ ] **Step 3: Remove the generated editor/viewer roles**

```bash
ls config/rbac/
rm -f config/rbac/sopstenant_*_role.yaml config/rbac/sopssecret_*_role.yaml
```

Remove the matching entries (any line referencing `sopstenant_` or `sopssecret_`) from `config/rbac/kustomization.yaml`. Then run `make manifests` and check:

Run: `cat config/rbac/role.yaml && bin/kustomize build config/default > /dev/null && echo OK`
Expected: `role.yaml` contains exactly the five rules from Step 1 and no `secrets` resource; `OK` printed. (`bin/kustomize` is installed by `make manifests`' dependencies; if missing, run `make kustomize`.)

- [ ] **Step 4: Write the failing harness tests**

`internal/testenv/testenv_test.go`:

```go
package testenv_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func TestOperatorHasNoStandingSecretAccess(t *testing.T) {
	err := env.Operator.List(context.Background(), &corev1.SecretList{})
	if !apierrors.IsForbidden(err) {
		t.Fatalf("operator listing Secrets: got %v, want Forbidden", err)
	}
}

func TestOperatorCanReadItsResources(t *testing.T) {
	ctx := context.Background()
	if err := env.Operator.List(ctx, &sopsv1alpha1.SopsTenantList{}); err != nil {
		t.Fatalf("list SopsTenants: %v", err)
	}
	if err := env.Operator.List(ctx, &sopsv1alpha1.SopsSecretList{}); err != nil {
		t.Fatalf("list SopsSecrets: %v", err)
	}
}

func TestOperatorImpersonatesOnlySopsServiceAccounts(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "imp")
	// Both ServiceAccounts may read Secrets, so only the impersonation check can deny.
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "read-secrets", Namespace: ns},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "read-secrets", Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "read-secrets"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.ServiceAccountKind, Name: "sops", Namespace: ns},
			{Kind: rbacv1.ServiceAccountKind, Name: "default", Namespace: ns},
		},
	}
	probe := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: ns}}
	for _, o := range []client.Object{role, binding, probe} {
		if err := env.Admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	for sa, allowed := range map[string]bool{"sops": true, "default": false} {
		cfg := rest.CopyConfig(env.OperatorConfig)
		cfg.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + ns + ":" + sa}
		c, err := client.New(cfg, client.Options{Scheme: env.Scheme})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Get(ctx, client.ObjectKeyFromObject(probe), &corev1.Secret{})
		if allowed && err != nil {
			t.Fatalf("impersonating %s: %v", sa, err)
		}
		if !allowed && !apierrors.IsForbidden(err) {
			t.Fatalf("impersonating %s: got %v, want Forbidden", sa, err)
		}
	}
}
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `go test ./internal/testenv/ -v`
Expected: FAIL — `undefined: testenv.Start`.

- [ ] **Step 6: Implement the harness**

`internal/testenv/testenv.go`:

```go
// Package testenv starts a Kubernetes API server for integration tests with the RBAC
// authorizer, the operator's CRDs and roles installed, and a non-admin operator user bound
// to the generated operator ClusterRole, so tests exercise real permissions.
package testenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// OperatorUser is the user the operator runs as in tests.
const OperatorUser = "sops-operator"

// Env is a running test API server.
type Env struct {
	env            *envtest.Environment
	Scheme         *runtime.Scheme
	Admin          client.Client
	OperatorConfig *rest.Config
	Operator       client.Client
}

// Start starts the API server and installs CRDs, roles and the operator user.
func Start() (*Env, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := sopsv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	te.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := te.Start()
	if err != nil {
		return nil, fmt.Errorf("start envtest: %w", err)
	}
	e := &Env{env: te, Scheme: scheme}
	if err := e.setup(root, cfg); err != nil {
		_ = te.Stop()
		return nil, err
	}
	return e, nil
}

func (e *Env) setup(root string, cfg *rest.Config) error {
	ctx := context.Background()
	admin, err := client.New(cfg, client.Options{Scheme: e.Scheme})
	if err != nil {
		return err
	}
	e.Admin = admin
	for _, f := range []string{
		filepath.Join(root, "config", "rbac", "role.yaml"),
		filepath.Join(root, "config", "tenant-rbac", "roles.yaml"),
	} {
		if err := applyFile(ctx, admin, f); err != nil {
			return err
		}
	}
	user, err := e.env.AddUser(envtest.User{Name: OperatorUser}, cfg)
	if err != nil {
		return fmt.Errorf("add operator user: %w", err)
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorUser},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "manager-role"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: OperatorUser}},
	}
	if err := admin.Create(ctx, binding); err != nil {
		return err
	}
	e.OperatorConfig = user.Config()
	e.Operator, err = client.New(e.OperatorConfig, client.Options{Scheme: e.Scheme})
	return err
}

// Stop stops the API server.
func (e *Env) Stop() error { return e.env.Stop() }

// Namespace creates a namespace with a generated name and returns the name.
func (e *Env) Namespace(t testing.TB, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	if err := e.Admin.Create(context.Background(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}

// Onboard does what the cluster admin's onboarding template does (DESIGN.md §5.2): it creates
// the tenant's "sops" ServiceAccount, lets it own keys in the tenant namespace and lets it
// write Secrets in each of writeNamespaces.
func (e *Env) Onboard(t testing.TB, tenantNamespace string, writeNamespaces ...string) {
	t.Helper()
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "sops", Namespace: tenantNamespace}}
	objs := []client.Object{
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "sops", Namespace: tenantNamespace},
			AutomountServiceAccountToken: ptr.To(false),
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "sops-key-owner", Namespace: tenantNamespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-key-owner"},
			Subjects:   subjects,
		},
	}
	for _, ns := range writeNamespaces {
		objs = append(objs, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "sops-" + tenantNamespace, Namespace: ns},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-secret-writer"},
			Subjects:   subjects,
		})
	}
	for _, o := range objs {
		if err := e.Admin.Create(context.Background(), o); err != nil {
			t.Fatalf("onboard: create %T: %v", o, err)
		}
	}
}

func applyFile(ctx context.Context, c client.Client, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode %s: %w", path, err)
		}
		if len(obj) == 0 {
			continue
		}
		u := &unstructured.Unstructured{Object: obj}
		if err := c.Create(ctx, u); err != nil {
			return fmt.Errorf("create %s %s from %s: %w", u.GetKind(), u.GetName(), path, err)
		}
	}
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the working directory")
		}
		dir = parent
	}
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/testenv/ -v`
Expected: PASS (3 tests). If `TestOperatorImpersonatesOnlySopsServiceAccounts` fails with "impersonating sops: … forbidden", check that `config/rbac/role.yaml` contains `resourceNames: [sops]` under the `impersonate` rule.

- [ ] **Step 8: Commit**

```bash
git add internal/controller/rbac.go internal/controller/sopstenant_controller.go internal/controller/sopssecret_controller.go \
  config/rbac config/tenant-rbac internal/testenv
git commit -m "feat(rbac): minimal operator role, tenant roles and RBAC-enforcing envtest harness"
```

---

### Task 7: API types and CRD validation

**Files:**
- Modify (replace contents): `api/v1alpha1/sopstenant_types.go`, `api/v1alpha1/sopssecret_types.go`
- Create: `api/v1alpha1/constants.go`
- Test: `api/v1alpha1/validation_test.go`

**Interfaces:**
- Consumes: `testenv` (Task 6).
- Produces (package `v1alpha1`):
  - `SopsTenant{Spec SopsTenantSpec; Status SopsTenantStatus}`, `SopsTenantSpec{GenerateKey *bool}`, `SopsTenantStatus{ObservedGeneration int64; UsedBy int32; Conditions []metav1.Condition}`, `(*SopsTenant).ShouldGenerateKey() bool`, `SopsTenantList`
  - `SopsSecret{Spec SopsSecretSpec; Sops SopsMetadata; Status SopsSecretStatus}`, `SopsSecretList`
  - `SopsSecretSpec{TenantRef TenantReference; Scope string; DeletionPolicy DeletionPolicy; Template SecretTemplate; Type corev1.SecretType; Data map[string]string; StringData map[string]string}`
  - `TenantReference{Name, Namespace string}`, `SecretTemplate{Metadata SecretTemplateMetadata}`, `SecretTemplateMetadata{Labels, Annotations map[string]string}`
  - `DeletionPolicy` with `DeletionPolicyDelete = "Delete"`, `DeletionPolicyRetain = "Retain"`
  - `SopsMetadata{Age []SopsAgeRecipient; MAC, LastModified, Version, EncryptedRegex string; MACOnlyEncrypted bool}`, `SopsAgeRecipient{Recipient, Enc string}`
  - `SopsSecretStatus{ObservedGeneration int64; LastSyncTime *metav1.Time; SecretUID types.UID; Conditions []metav1.Condition}`
  - Constants in `constants.go` (below).

- [ ] **Step 1: Write the types**

`api/v1alpha1/constants.go`:

```go
package v1alpha1

// ConditionReady is the only condition type of SopsTenant and SopsSecret.
const ConditionReady = "Ready"

// SopsTenant Ready reasons.
const (
	ReasonKeyLoaded    = "KeyLoaded"
	ReasonKeyGenerated = "KeyGenerated"
	ReasonKeyMissing   = "KeyMissing"
	ReasonKeyInvalid   = "KeyInvalid"
	ReasonAccessDenied = "AccessDenied"
)

// SopsSecret Ready reasons. ReasonAccessDenied is shared with SopsTenant.
const (
	ReasonDecrypted      = "Decrypted"
	ReasonSuspended      = "Suspended"
	ReasonTenantNotFound = "TenantNotFound"
	ReasonTenantNotReady = "TenantNotReady"
	ReasonNotRecipient   = "NotRecipient"
	ReasonScopeMismatch  = "ScopeMismatch"
	ReasonDecryptFailed  = "DecryptFailed"
	ReasonConflict       = "Conflict"
	ReasonApplyFailed    = "ApplyFailed"
)

// Labels and annotations.
const (
	// AnnotationSuspend set to "true" on a SopsSecret pauses its reconciliation.
	AnnotationSuspend = "sops.stakater.com/suspend"
	// LabelManagedBy marks Secrets created by the operator.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value of LabelManagedBy.
	ManagedByValue = "sops-operator"
	// LabelSopsSecret names the SopsSecret an output Secret was created from.
	LabelSopsSecret = "sops.stakater.com/sopssecret"
)
```

`api/v1alpha1/sopstenant_types.go` (replace the whole file):

```go
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SopsTenantSpec defines a tenant key. The key is the Secret with the tenant's name in the
// tenant's namespace.
type SopsTenantSpec struct {
	// GenerateKey generates a post-quantum age key when the key Secret does not exist.
	// +kubebuilder:default=true
	// +optional
	GenerateKey *bool `json:"generateKey,omitempty"`
}

// SopsTenantStatus reports the state of the tenant key.
type SopsTenantStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// UsedBy is the number of SopsSecrets referencing this tenant.
	// +optional
	UsedBy int32 `json:"usedBy,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Used By",type=integer,JSONPath=`.status.usedBy`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SopsTenant is a tenant key used to decrypt SopsSecrets.
type SopsTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec SopsTenantSpec `json:"spec,omitempty"`
	// +optional
	Status SopsTenantStatus `json:"status,omitempty"`
}

// ShouldGenerateKey reports whether a missing key Secret should be generated.
func (t *SopsTenant) ShouldGenerateKey() bool {
	return t.Spec.GenerateKey == nil || *t.Spec.GenerateKey
}

// +kubebuilder:object:root=true

// SopsTenantList contains a list of SopsTenant.
type SopsTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SopsTenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SopsTenant{}, &SopsTenantList{})
}
```

`api/v1alpha1/sopssecret_types.go` (replace the whole file):

```go
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TenantReference names a SopsTenant.
type TenantReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// DeletionPolicy decides what happens to the output Secret when the SopsSecret is deleted.
// +kubebuilder:validation:Enum=Delete;Retain
type DeletionPolicy string

const (
	// DeletionPolicyDelete garbage-collects the output Secret with the SopsSecret.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyRetain keeps the output Secret.
	DeletionPolicyRetain DeletionPolicy = "Retain"
)

// SecretTemplate holds metadata for the output Secret.
type SecretTemplate struct {
	// +optional
	Metadata SecretTemplateMetadata `json:"metadata,omitempty"`
}

// SecretTemplateMetadata holds labels and annotations for the output Secret.
type SecretTemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SopsSecretSpec is the encrypted definition of one Secret with the same name and namespace.
// +kubebuilder:validation:XValidation:rule="has(self.data) || has(self.stringData)",message="at least one of data or stringData is required"
// +kubebuilder:validation:XValidation:rule="!has(self.data) || !has(self.stringData) || self.data.all(k, !(k in self.stringData))",message="a key must not appear in both data and stringData"
type SopsSecretSpec struct {
	TenantRef TenantReference `json:"tenantRef"`
	// Scope is the encrypted "<namespace>/<name>" this document may be decrypted into.
	// +kubebuilder:validation:MinLength=1
	Scope string `json:"scope"`
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +optional
	Template SecretTemplate `json:"template,omitempty"`
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls;kubernetes.io/dockerconfigjson;kubernetes.io/basic-auth;kubernetes.io/ssh-auth
	// +kubebuilder:default=Opaque
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
	// Data holds encrypted base64 values.
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	Data map[string]string `json:"data,omitempty"`
	// StringData holds encrypted text values.
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	StringData map[string]string `json:"stringData,omitempty"`
}

// SopsAgeRecipient is one age recipient entry of the SOPS metadata.
type SopsAgeRecipient struct {
	// +kubebuilder:validation:MinLength=1
	Recipient string `json:"recipient"`
	// +kubebuilder:validation:MinLength=1
	Enc string `json:"enc"`
}

// SopsMetadata is the metadata block written by `sops encrypt`.
type SopsMetadata struct {
	// +kubebuilder:validation:MinItems=1
	Age []SopsAgeRecipient `json:"age"`
	// +kubebuilder:validation:MinLength=1
	MAC string `json:"mac"`
	// +kubebuilder:validation:MinLength=1
	LastModified string `json:"lastmodified"`
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// +kubebuilder:validation:XValidation:rule="self == '^(data|stringData|scope)$'",message="encrypted_regex must be ^(data|stringData|scope)$"
	EncryptedRegex string `json:"encrypted_regex"`
	// +kubebuilder:validation:XValidation:rule="self",message="mac_only_encrypted must be true"
	MACOnlyEncrypted bool `json:"mac_only_encrypted"`
}

// SopsSecretStatus reports the state of the output Secret.
type SopsSecretStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// SecretUID is the UID of the Secret this SopsSecret created.
	// +optional
	SecretUID types.UID `json:"secretUID,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SopsSecret is a SOPS-encrypted Secret.
type SopsSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SopsSecretSpec `json:"spec"`
	Sops SopsMetadata   `json:"sops"`
	// +optional
	Status SopsSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SopsSecretList contains a list of SopsSecret.
type SopsSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SopsSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SopsSecret{}, &SopsSecretList{})
}
```

- [ ] **Step 2: Regenerate and confirm the CRDs build**

Run: `make manifests generate && go build ./...`
Expected: success; `config/crd/bases/sops.stakater.com_sopssecrets.yaml` contains `x-kubernetes-validations` with the three CEL rules and `required: [sops, spec]` at the top level.

- [ ] **Step 3: Write the validation tests**

`api/v1alpha1/validation_test.go`:

```go
package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

const enc = "ENC[AES256_GCM,data:eA==,iv:eA==,tag:eA==,type:str]"

func validSopsSecret(ns string) *sopsv1alpha1.SopsSecret {
	return &sopsv1alpha1.SopsSecret{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "s-", Namespace: ns},
		Spec: sopsv1alpha1.SopsSecretSpec{
			TenantRef:  sopsv1alpha1.TenantReference{Name: "solar", Namespace: "solar-system"},
			Scope:      enc,
			StringData: map[string]string{"password": enc},
		},
		Sops: sopsv1alpha1.SopsMetadata{
			Age:              []sopsv1alpha1.SopsAgeRecipient{{Recipient: "age1pq1example", Enc: "-----BEGIN AGE ENCRYPTED FILE-----\nx\n-----END AGE ENCRYPTED FILE-----\n"}},
			MAC:              enc,
			LastModified:     "2026-10-09T10:00:00Z",
			Version:          "3.13.3",
			EncryptedRegex:   "^(data|stringData|scope)$",
			MACOnlyEncrypted: true,
		},
	}
}

func TestSopsSecretValidation(t *testing.T) {
	ns := env.Namespace(t, "validation")
	cases := []struct {
		name   string
		mutate func(s *sopsv1alpha1.SopsSecret)
		valid  bool
	}{
		{"valid", func(*sopsv1alpha1.SopsSecret) {}, true},
		{"missing scope", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Scope = "" }, false},
		{"no data", func(s *sopsv1alpha1.SopsSecret) { s.Spec.StringData = nil }, false},
		{"key in data and stringData", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Data = map[string]string{"password": enc} }, false},
		{"service account token type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeServiceAccountToken }, false},
		{"tls type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeTLS }, true},
		{"other encrypted_regex", func(s *sopsv1alpha1.SopsSecret) { s.Sops.EncryptedRegex = "^data$" }, false},
		{"mac_only_encrypted false", func(s *sopsv1alpha1.SopsSecret) { s.Sops.MACOnlyEncrypted = false }, false},
		{"no age recipients", func(s *sopsv1alpha1.SopsSecret) { s.Sops.Age = nil }, false},
		{"unknown deletion policy", func(s *sopsv1alpha1.SopsSecret) { s.Spec.DeletionPolicy = "Orphan" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSopsSecret(ns)
			tc.mutate(s)
			err := env.Admin.Create(context.Background(), s)
			if tc.valid && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("want Invalid, got %v", err)
			}
		})
	}
}

func TestSopsSecretDefaults(t *testing.T) {
	s := validSopsSecret(env.Namespace(t, "defaults"))
	if err := env.Admin.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if s.Spec.DeletionPolicy != sopsv1alpha1.DeletionPolicyDelete || s.Spec.Type != corev1.SecretTypeOpaque {
		t.Fatalf("defaults not applied: deletionPolicy=%q type=%q", s.Spec.DeletionPolicy, s.Spec.Type)
	}
}

func TestSopsTenantGenerateKeyDefaultsToTrue(t *testing.T) {
	tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: "solar", Namespace: env.Namespace(t, "tenant")}}
	if err := env.Admin.Create(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	var got sopsv1alpha1.SopsTenant
	if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.GenerateKey == nil || !*got.Spec.GenerateKey || !got.ShouldGenerateKey() {
		t.Fatal("generateKey does not default to true")
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./api/... -v`
Expected: PASS (all 10 subtests plus 2 tests). A failure like "estimated rule cost exceeds budget" during CRD install means a map lacks `MaxProperties`; check Step 1.

- [ ] **Step 5: Commit**

```bash
git add api/ config/crd/
git commit -m "feat(api): SopsTenant and SopsSecret types with CEL validation"
```

---

### Task 8: Canonical document and plaintext payload

**Files:**
- Create: `internal/document/document.go`
- Test: `internal/document/document_test.go`

**Interfaces:**
- Consumes: `v1alpha1.SopsSecret` (Task 7), `crypto.Decrypt`, `crypto.ParseKeyFile`, `crypto.GenerateKeyFile`, `cryptotest.Encrypt` (Tasks 4–5).
- Produces:
  - `func document.Canonical(s *v1alpha1.SopsSecret) ([]byte, error)` — encrypted YAML with keys sorted
  - `type document.Payload struct { Scope string; Data map[string][]byte }`
  - `func document.ParsePlain(plain []byte) (*Payload, error)`
  - `func document.ScopeFor(namespace, name string) string`

- [ ] **Step 1: Write the failing tests**

`internal/document/document_test.go`:

```go
package document_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
	"github.com/stakater/sops-operator/internal/document"
)

// encryptedSopsSecret builds a SopsSecret the way a developer would (sorted plaintext, then
// sops encrypt) and returns it as the API server would hand it to the operator.
func encryptedSopsSecret(t *testing.T, spec map[string]any) (*sopsv1alpha1.SopsSecret, *crypto.KeySet) {
	t.Helper()
	keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := yaml.Marshal(map[string]any{
		"apiVersion": "sops.stakater.com/v1alpha1",
		"kind":       "SopsSecret",
		"metadata":   map[string]any{"name": "db-creds", "namespace": "solar-prod"},
		"spec":       spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cryptotest.Encrypt(plain, recipient)
	if err != nil {
		t.Fatal(err)
	}
	var s sopsv1alpha1.SopsSecret
	if err := yaml.Unmarshal(enc, &s); err != nil {
		t.Fatal(err)
	}
	// Round-trip through JSON like the API server.
	raw, err := json.Marshal(&s)
	if err != nil {
		t.Fatal(err)
	}
	var stored sopsv1alpha1.SopsSecret
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	return &stored, ks
}

func decrypt(t *testing.T, s *sopsv1alpha1.SopsSecret, ks *crypto.KeySet) (*document.Payload, error) {
	t.Helper()
	doc, err := document.Canonical(s)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	plain, err := crypto.Decrypt(doc, ks)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return document.ParsePlain(plain)
}

func TestCanonicalDecryptsAfterAPIRoundTrip(t *testing.T) {
	s, ks := encryptedSopsSecret(t, map[string]any{
		"tenantRef":  map[string]any{"name": "solar", "namespace": "solar-system"},
		"scope":      "solar-prod/db-creds",
		"data":       map[string]any{"cert": "AAEC"}, // bytes 0x00 0x01 0x02
		"stringData": map[string]any{"password": "hunter2"},
	})
	p, err := decrypt(t, s, ks)
	if err != nil {
		t.Fatalf("ParsePlain: %v", err)
	}
	if p.Scope != document.ScopeFor("solar-prod", "db-creds") {
		t.Fatalf("scope = %q", p.Scope)
	}
	if string(p.Data["password"]) != "hunter2" || string(p.Data["cert"]) != "\x00\x01\x02" {
		t.Fatal("payload values do not match the plaintext")
	}
}

func TestParsePlainConvertsScalarsToStrings(t *testing.T) {
	s, ks := encryptedSopsSecret(t, map[string]any{
		"tenantRef":  map[string]any{"name": "solar", "namespace": "solar-system"},
		"scope":      "solar-prod/db-creds",
		"stringData": map[string]any{"enabled": true, "port": 5432, "ratio": 0.5},
	})
	p, err := decrypt(t, s, ks)
	if err != nil {
		t.Fatalf("ParsePlain: %v", err)
	}
	for k, want := range map[string]string{"enabled": "true", "port": "5432", "ratio": "0.5"} {
		if got := string(p.Data[k]); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestParsePlainRejectsInvalidBase64WithoutValue(t *testing.T) {
	const secretValue = "not-base64-%%%"
	_, err := document.ParsePlain([]byte("spec:\n  scope: a/b\n  data:\n    token: " + secretValue + "\n"))
	if err == nil {
		t.Fatal("want error for invalid base64")
	}
	if !strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), secretValue) {
		t.Fatalf("error %q must name the key and not contain the value", err)
	}
}

func TestParsePlainRejectsNestedValues(t *testing.T) {
	_, err := document.ParsePlain([]byte("spec:\n  scope: a/b\n  stringData:\n    nested:\n      x: y\n"))
	if err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("want error naming the nested key, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/document/ -v`
Expected: FAIL — `undefined: document.Canonical`.

- [ ] **Step 3: Implement**

`internal/document/document.go`:

```go
// Package document converts between SopsSecret objects and the YAML documents SOPS works on.
package document

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Canonical renders the encrypted part of a SopsSecret (spec and sops) as the YAML document
// SOPS decrypts. Keys are sorted at every level, matching the Kubernetes API's JSON encoding
// and files prepared with `yq 'sort_keys(..)'`. Encrypted values keep their paths (spec:…),
// which SOPS uses as authenticated data.
func Canonical(s *sopsv1alpha1.SopsSecret) ([]byte, error) {
	spec, err := toMap(s.Spec)
	if err != nil {
		return nil, fmt.Errorf("render spec: %w", err)
	}
	meta, err := toMap(s.Sops)
	if err != nil {
		return nil, fmt.Errorf("render sops metadata: %w", err)
	}
	return yaml.Marshal(map[string]any{"spec": spec, "sops": meta})
}

func toMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Payload is the decrypted content of a SopsSecret.
type Payload struct {
	Scope string
	Data  map[string][]byte
}

// ScopeFor returns the scope value a SopsSecret named name in namespace must carry.
func ScopeFor(namespace, name string) string { return namespace + "/" + name }

// ParsePlain extracts the scope and values from a decrypted document. stringData scalars are
// converted to strings the way kubectl does. Errors name keys but never values.
func ParsePlain(plain []byte) (*Payload, error) {
	raw, err := yaml.YAMLToJSON(plain)
	if err != nil {
		return nil, fmt.Errorf("decrypted document is not valid YAML")
	}
	var doc struct {
		Spec struct {
			Scope      string         `json:"scope"`
			Data       map[string]any `json:"data"`
			StringData map[string]any `json:"stringData"`
		} `json:"spec"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decrypted document does not match the SopsSecret schema")
	}
	p := &Payload{Scope: doc.Spec.Scope, Data: map[string][]byte{}}
	for k, v := range doc.Spec.Data {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("data.%s must be a base64 string", k)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("data.%s is not valid base64", k)
		}
		p.Data[k] = b
	}
	for k, v := range doc.Spec.StringData {
		s, ok := scalar(v)
		if !ok {
			return nil, fmt.Errorf("stringData.%s must be a string, number or boolean", k)
		}
		if _, dup := p.Data[k]; dup {
			return nil, fmt.Errorf("key %s appears in both data and stringData", k)
		}
		p.Data[k] = []byte(s)
	}
	return p, nil
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/document/ -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/document/
git commit -m "feat(document): canonical SOPS document and payload parsing"
```

---

### Task 9: Tenant identity and grant check

**Files:**
- Create: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

**Interfaces:**
- Consumes: `testenv` (Task 6).
- Produces:
  - `const identity.ServiceAccountName = "sops"`
  - `func identity.UserName(tenantNamespace string) string`
  - `type identity.Factory`; `func identity.NewFactory(base *rest.Config, scheme *runtime.Scheme) *Factory`
  - `func (*Factory) ClientFor(tenantNamespace string) (client.Client, error)` — uncached, impersonating
  - `func identity.CanWriteSecrets(ctx context.Context, c client.Client, tenantNamespace, namespace string) (bool, error)`

- [ ] **Step 1: Write the failing tests**

`internal/identity/identity_test.go`:

```go
package identity_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func TestUserName(t *testing.T) {
	if got := identity.UserName("solar-system"); got != "system:serviceaccount:solar-system:sops" {
		t.Fatalf("UserName = %q", got)
	}
}

func TestTenantReadsKeyOnlyWhenOnboarded(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	key := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "solar", Namespace: tenantNS}}
	if err := env.Admin.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	f := identity.NewFactory(env.OperatorConfig, env.Scheme)
	c, err := f.ClientFor(tenantNS)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(key), &corev1.Secret{}); !apierrors.IsForbidden(err) {
		t.Fatalf("before onboarding: got %v, want Forbidden", err)
	}
	env.Onboard(t, tenantNS)
	if err := c.Get(ctx, client.ObjectKeyFromObject(key), &corev1.Secret{}); err != nil {
		t.Fatalf("after onboarding: %v", err)
	}
}

func TestCanWriteSecretsFollowsGrants(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	granted := env.Namespace(t, "granted")
	other := env.Namespace(t, "other")
	env.Onboard(t, tenantNS, granted)

	for ns, want := range map[string]bool{granted: true, other: false} {
		got, err := identity.CanWriteSecrets(ctx, env.Operator, tenantNS, ns)
		if err != nil {
			t.Fatalf("CanWriteSecrets(%s): %v", ns, err)
		}
		if got != want {
			t.Fatalf("CanWriteSecrets(%s) = %v, want %v", ns, got, want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/ -v`
Expected: FAIL — `undefined: identity.NewFactory`.

- [ ] **Step 3: Implement**

`internal/identity/identity.go`:

```go
// Package identity provides clients that act as a tenant's "sops" ServiceAccount.
package identity

import (
	"context"
	"fmt"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceAccountName is the name of every tenant identity's ServiceAccount.
const ServiceAccountName = "sops"

// UserName returns the user name of the tenant identity of tenantNamespace.
func UserName(tenantNamespace string) string {
	return "system:serviceaccount:" + tenantNamespace + ":" + ServiceAccountName
}

func groups(tenantNamespace string) []string {
	return []string{"system:serviceaccounts", "system:serviceaccounts:" + tenantNamespace, "system:authenticated"}
}

// Factory creates and caches one impersonating client per tenant namespace.
type Factory struct {
	base    *rest.Config
	scheme  *runtime.Scheme
	mu      sync.Mutex
	clients map[string]client.Client
}

// NewFactory returns a Factory that impersonates tenant identities using base credentials.
func NewFactory(base *rest.Config, scheme *runtime.Scheme) *Factory {
	return &Factory{base: base, scheme: scheme, clients: map[string]client.Client{}}
}

// ClientFor returns an uncached client acting as the tenant identity of tenantNamespace.
func (f *Factory) ClientFor(tenantNamespace string) (client.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[tenantNamespace]; ok {
		return c, nil
	}
	cfg := rest.CopyConfig(f.base)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: UserName(tenantNamespace)}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		return nil, fmt.Errorf("client for tenant identity in %s: %w", tenantNamespace, err)
	}
	f.clients[tenantNamespace] = c
	return c, nil
}

// CanWriteSecrets reports whether the tenant identity of tenantNamespace may create Secrets in
// namespace. It is an early check; the API server enforces the same rule on every write.
func CanWriteSecrets(ctx context.Context, c client.Client, tenantNamespace, namespace string) (bool, error) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   UserName(tenantNamespace),
			Groups: groups(tenantNamespace),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "create",
				Resource:  "secrets",
			},
		},
	}
	if err := c.Create(ctx, sar); err != nil {
		return false, fmt.Errorf("subject access review: %w", err)
	}
	return sar.Status.Allowed, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/identity/ -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): impersonating tenant clients and grant check"
```

---

### Task 10: Write-only Secret writer (D28 spike)

**Files:**
- Create: `internal/secretwriter/writer.go`
- Test: `internal/secretwriter/writer_test.go`

**Interfaces:**
- Consumes: `identity.NewFactory`, `(*Factory).ClientFor` (Task 9), `testenv` (Task 6).
- Produces:
  - `var secretwriter.ErrConflict error`
  - `func secretwriter.Write(ctx context.Context, c client.Client, desired *corev1.Secret, knownUID types.UID) (types.UID, error)`

This task proves D28. If `TestForeignReplacementIsNeverOverwritten` cannot pass, stop and report: the fallback (adding `get` to `sops-secret-writer`) needs the user's approval.

- [ ] **Step 1: Write the failing tests**

`internal/secretwriter/writer_test.go`:

```go
package secretwriter_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwriter"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

// setup returns a tenant client that may only create and update Secrets in ns.
func setup(t *testing.T) (client.Client, string) {
	t.Helper()
	tenantNS := env.Namespace(t, "tenant")
	ns := env.Namespace(t, "target")
	env.Onboard(t, tenantNS, ns)
	c, err := identity.NewFactory(env.OperatorConfig, env.Scheme).ClientFor(tenantNS)
	if err != nil {
		t.Fatal(err)
	}
	return c, ns
}

func secret(ns, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns},
		Data:       map[string][]byte{"password": []byte(value)},
	}
}

func adminRead(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestCreateThenUpdate(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil || uid == "" {
		t.Fatalf("create: uid=%q err=%v", uid, err)
	}
	uid2, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid)
	if err != nil || uid2 != uid {
		t.Fatalf("update: uid=%q err=%v", uid2, err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "v2" {
		t.Fatalf("password = %q, want v2", got)
	}
}

func TestExistingForeignSecretIsConflict(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	if err := env.Admin.Create(ctx, secret(ns, "foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := secretwriter.Write(ctx, c, secret(ns, "mine"), ""); !errors.Is(err, secretwriter.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "foreign" {
		t.Fatal("foreign Secret was modified")
	}
}

func TestDeletedSecretIsRecreated(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Delete(ctx, secret(ns, "")); err != nil {
		t.Fatal(err)
	}
	uid2, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid)
	if err != nil || uid2 == "" || uid2 == uid {
		t.Fatalf("recreate: uid=%q (old %q) err=%v", uid2, uid, err)
	}
}

func TestForeignReplacementIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Delete(ctx, secret(ns, "")); err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Create(ctx, secret(ns, "foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid); !errors.Is(err, secretwriter.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "foreign" {
		t.Fatal("foreign replacement was overwritten")
	}
}

func TestTenantCannotReadSecrets(t *testing.T) {
	c, ns := setup(t)
	if err := env.Admin.Create(context.Background(), secret(ns, "x")); err != nil {
		t.Fatal(err)
	}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &corev1.Secret{})
	if !apierrors.IsForbidden(err) {
		t.Fatalf("got %v, want Forbidden", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/secretwriter/ -v`
Expected: FAIL — `undefined: secretwriter.Write`.

- [ ] **Step 3: Implement**

`internal/secretwriter/writer.go`:

```go
// Package secretwriter writes Secrets without reading them (DESIGN.md D28).
package secretwriter

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrConflict reports a Secret with the desired name that this writer did not create.
var ErrConflict = errors.New("a Secret with this name exists and is not managed by this SopsSecret")

// Write creates or replaces desired. knownUID is the UID returned by the previous successful
// Write for this Secret, or "" if there was none. An update carries knownUID, so the API server
// rejects it (409) when the Secret was replaced by someone else; a missing Secret (404) is
// created again. It returns the UID of the written Secret.
func Write(ctx context.Context, c client.Client, desired *corev1.Secret, knownUID types.UID) (types.UID, error) {
	if knownUID != "" {
		obj := desired.DeepCopy()
		obj.UID = knownUID
		obj.ResourceVersion = ""
		err := c.Update(ctx, obj)
		switch {
		case err == nil:
			return obj.UID, nil
		case apierrors.IsConflict(err):
			return "", ErrConflict
		case !apierrors.IsNotFound(err):
			return "", err
		}
	}
	obj := desired.DeepCopy()
	obj.UID = ""
	obj.ResourceVersion = ""
	if err := c.Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return "", ErrConflict
		}
		return "", err
	}
	return obj.UID, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/secretwriter/ -v`
Expected: PASS (5 tests). If `TestForeignReplacementIsNeverOverwritten` fails because the update succeeded, stop and report to the user (see the note at the top of this task).

- [ ] **Step 5: Commit**

```bash
git add internal/secretwriter/
git commit -m "feat(secretwriter): write-only Secret writes guarded by UID precondition"
```

---

### Task 11: SopsTenant controller and manager wiring

**Files:**
- Create: `internal/controller/indexes.go`, `internal/controller/main_test.go`, `internal/controller/helpers_test.go`
- Modify (replace contents): `internal/controller/sopstenant_controller.go`
- Modify: `cmd/main.go`
- Test: `internal/controller/sopstenant_controller_test.go`

**Interfaces:**
- Consumes: `crypto.ParseKeyFile`, `crypto.GenerateKeyFile`, `crypto.KeyFileField` (Task 4); `identity.Factory` (Task 9); API types and constants (Task 7); `testenv` (Task 6); `cryptotest.Encrypt` (Task 5).
- Produces:
  - `const controller.IndexTenantRef = "spec.tenantRef"`, `func controller.TenantRefKey(namespace, name string) string`, `func controller.SetupIndexes(ctx context.Context, mgr ctrl.Manager) error`
  - `type controller.SopsTenantReconciler struct { client.Client; Identities *identity.Factory; Recorder record.EventRecorder; ResyncInterval time.Duration; Now func() time.Time }` with `Reconcile` and `SetupWithManager(mgr ctrl.Manager) error`
  - Test helpers (package `controller_test`): `env`, `tenantName`, `onboardedTenant(t, writeNS ...string) (tenantNS, recipient string)`, `encryptedSopsSecret(t, recipient, tenantNS, ns, name, scope string, stringData map[string]any) *sopsv1alpha1.SopsSecret`, `readyCondition(obj client.Object) *metav1.Condition`, `eventuallyReason(t, obj client.Object, reason string)`

- [ ] **Step 1: Write the index helpers**

`internal/controller/indexes.go`:

```go
package controller

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// IndexTenantRef indexes SopsSecrets by the tenant they reference.
const IndexTenantRef = "spec.tenantRef"

// TenantRefKey is the IndexTenantRef value of a tenant.
func TenantRefKey(namespace, name string) string { return namespace + "/" + name }

// SetupIndexes registers the field indexes the controllers use.
func SetupIndexes(ctx context.Context, mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(ctx, &sopsv1alpha1.SopsSecret{}, IndexTenantRef,
		func(o client.Object) []string {
			s := o.(*sopsv1alpha1.SopsSecret)
			return []string{TenantRefKey(s.Spec.TenantRef.Namespace, s.Spec.TenantRef.Name)}
		})
}
```

- [ ] **Step 2: Write the test harness**

`internal/controller/main_test.go`:

```go
package controller_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/stakater/sops-operator/internal/controller"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/testenv"
)

const resync = 2 * time.Second

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := startManager(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = env.Stop()
		os.Exit(1)
	}
	code := m.Run()
	cancel()
	_ = env.Stop()
	os.Exit(code)
}

// startManager runs the controllers as the non-admin operator user.
func startManager(ctx context.Context) error {
	mgr, err := ctrl.NewManager(env.OperatorConfig, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		return err
	}
	if err := controller.SetupIndexes(ctx, mgr); err != nil {
		return err
	}
	ids := identity.NewFactory(env.OperatorConfig, env.Scheme)
	recorder := mgr.GetEventRecorderFor("sops-operator")
	if err := (&controller.SopsTenantReconciler{
		Client: mgr.GetClient(), Identities: ids, Recorder: recorder, ResyncInterval: resync,
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()
	return nil
}
```

`internal/controller/helpers_test.go`:

```go
package controller_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
)

const tenantName = "solar"

// readyCondition returns the Ready condition of a SopsTenant or SopsSecret, or nil.
func readyCondition(obj client.Object) *metav1.Condition {
	switch o := obj.(type) {
	case *sopsv1alpha1.SopsTenant:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	case *sopsv1alpha1.SopsSecret:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	}
	return nil
}

// eventuallyReason waits until obj's Ready condition has the given reason; obj is refreshed in place.
func eventuallyReason(t *testing.T, obj client.Object, reason string) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		c := readyCondition(obj)
		g.Expect(c).NotTo(BeNil())
		g.Expect(c.Reason).To(Equal(reason), "message: %s", c.Message)
	}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
}

// onboardedTenant creates an onboarded tenant namespace with a generated key and returns the
// namespace and the key's recipient.
func onboardedTenant(t *testing.T, writeNS ...string) (string, string) {
	t.Helper()
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	env.Onboard(t, tenantNS, writeNS...)
	tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS}}
	if err := env.Admin.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
		g.Expect(meta.IsStatusConditionTrue(tenant.Status.Conditions, sopsv1alpha1.ConditionReady)).To(BeTrue())
	}).WithTimeout(20 * time.Second).Should(Succeed())

	var key corev1.Secret
	if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: tenantName}, &key); err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		t.Fatal(err)
	}
	return tenantNS, ks.Recipients[0]
}

// encryptedSopsSecret builds a SopsSecret named name in ns, encrypted for recipient with the given scope.
func encryptedSopsSecret(t *testing.T, recipient, tenantNS, ns, name, scope string, stringData map[string]any) *sopsv1alpha1.SopsSecret {
	t.Helper()
	plain, err := yaml.Marshal(map[string]any{
		"apiVersion": "sops.stakater.com/v1alpha1",
		"kind":       "SopsSecret",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"tenantRef":  map[string]any{"name": tenantName, "namespace": tenantNS},
			"scope":      scope,
			"stringData": stringData,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cryptotest.Encrypt(plain, recipient)
	if err != nil {
		t.Fatal(err)
	}
	var s sopsv1alpha1.SopsSecret
	if err := yaml.Unmarshal(enc, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}
```

- [ ] **Step 3: Write the failing tenant tests**

`internal/controller/sopstenant_controller_test.go`:

```go
package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

func newTenant(ns string, generate *bool) *sopsv1alpha1.SopsTenant {
	return &sopsv1alpha1.SopsTenant{
		ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns},
		Spec:       sopsv1alpha1.SopsTenantSpec{GenerateKey: generate},
	}
}

func keySecret(ns string, keyFile string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns},
		Data:       map[string][]byte{crypto.KeyFileField: []byte(keyFile)},
	}
}

func TestTenantGeneratesPostQuantumKey(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "tenant")
	env.Onboard(t, ns)
	tenant := newTenant(ns, nil)
	if err := env.Admin.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
		c := readyCondition(tenant)
		g.Expect(c).NotTo(BeNil())
		g.Expect(c.Status).To(Equal(metav1.ConditionTrue))
	}).WithTimeout(20 * time.Second).Should(Succeed())

	var key corev1.Secret
	if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &key); err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ks.Recipients[0], "age1pq1") {
		t.Fatal("generated key is not post-quantum")
	}
	if key.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
		t.Fatal("generated key is missing the managed-by label")
	}
	if len(key.OwnerReferences) != 0 {
		t.Fatal("key Secret must not have an ownerReference")
	}
}

func TestTenantLoadsExistingKeyWithoutChangingIt(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "tenant")
	env.Onboard(t, ns)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := keySecret(ns, x.String()+"\n")
	if err := env.Admin.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
		t.Fatal(err)
	}
	eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyLoaded)

	var after corev1.Secret
	if err := env.Admin.Get(ctx, client.ObjectKeyFromObject(key), &after); err != nil {
		t.Fatal(err)
	}
	if after.ResourceVersion != key.ResourceVersion {
		t.Fatal("existing key Secret was modified")
	}
}

func TestTenantReportsInvalidKey(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "tenant")
	env.Onboard(t, ns)
	if err := env.Admin.Create(ctx, keySecret(ns, "-----BEGIN OPENSSH PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
		t.Fatal(err)
	}
	eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyInvalid)
}

func TestTenantWithoutGenerationReportsMissingKey(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "tenant")
	env.Onboard(t, ns)
	if err := env.Admin.Create(ctx, newTenant(ns, ptr.To(false))); err != nil {
		t.Fatal(err)
	}
	eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyMissing)
	err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("key Secret must not be created: %v", err)
	}
}

func TestTenantNotOnboardedIsAccessDenied(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "tenant")
	if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
		t.Fatal(err)
	}
	eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonAccessDenied)
	err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("key Secret must not be created: %v", err)
	}
}

func TestTenantCountsSopsSecrets(t *testing.T) {
	ctx := context.Background()
	target := env.Namespace(t, "target")
	tenantNS, recipient := onboardedTenant(t, target)
	for _, name := range []string{"a", "b"} {
		s := encryptedSopsSecret(t, recipient, tenantNS, target, name, target+"/"+name, map[string]any{"k": "v"})
		if err := env.Admin.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	tenant := newTenant(tenantNS, nil)
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
		g.Expect(tenant.Status.UsedBy).To(Equal(int32(2)))
	}).WithTimeout(20 * time.Second).Should(Succeed())
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/controller/ -run Tenant -v`
Expected: FAIL — compile error: unknown fields `Identities`, `Recorder`, `ResyncInterval` in `controller.SopsTenantReconciler`.

- [ ] **Step 5: Implement the reconciler**

`internal/controller/sopstenant_controller.go` (replace the whole file):

```go
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/identity"
)

// SopsTenantReconciler loads or generates a tenant key and reports its state. It accesses the
// key Secret only as the tenant identity.
type SopsTenantReconciler struct {
	client.Client
	Identities     *identity.Factory
	Recorder       record.EventRecorder
	ResyncInterval time.Duration
	Now            func() time.Time
}

func (r *SopsTenantReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler.
func (r *SopsTenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tenant sopsv1alpha1.SopsTenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	reason, message, err := r.reconcileKey(ctx, &tenant)
	if err != nil {
		return ctrl.Result{}, err
	}
	var users sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &users, client.MatchingFields{IndexTenantRef: TenantRefKey(tenant.Namespace, tenant.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	status := metav1.ConditionFalse
	if reason == sopsv1alpha1.ReasonKeyLoaded || reason == sopsv1alpha1.ReasonKeyGenerated {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&tenant.Status.Conditions, metav1.Condition{
		Type:               sopsv1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: tenant.Generation,
	})
	tenant.Status.ObservedGeneration = tenant.Generation
	tenant.Status.UsedBy = int32(len(users.Items))
	if err := r.Status().Update(ctx, &tenant); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

// reconcileKey returns the Ready reason and message for the tenant key. Only a 404 on the key
// Secret leads to generation; the tenant identity cannot modify or delete an existing key.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace)
	if err != nil {
		return "", "", err
	}
	var key corev1.Secret
	err = tc.Get(ctx, client.ObjectKeyFromObject(t), &key)
	switch {
	case err == nil:
		if _, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField]); err != nil {
			return sopsv1alpha1.ReasonKeyInvalid, err.Error(), nil
		}
		return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " +
			"the cluster admin must onboard this tenant", nil
	case !apierrors.IsNotFound(err):
		return "", "", err
	}

	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, t.Name), nil
	}
	keyFile, _, err := crypto.GenerateKeyFile(r.now())
	if err != nil {
		return "", "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
			Labels:    map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if err := tc.Create(ctx, secret); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " +
				"the cluster admin must onboard this tenant", nil
		}
		// AlreadyExists: a key appeared since the read; the retry loads it.
		return "", "", err
	}
	r.Recorder.Eventf(t, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated,
		"generated a post-quantum key in Secret %s", t.Name)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
}

// SetupWithManager registers the controller.
func (r *SopsTenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsTenant{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&sopsv1alpha1.SopsSecret{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
				ref := o.(*sopsv1alpha1.SopsSecret).Spec.TenantRef
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}}}
			}),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("sopstenant").
		Complete(r)
}
```

- [ ] **Step 6: Wire the manager in cmd/main.go**

In `cmd/main.go`:

1. Add imports `"context"` (if missing), `"time"` and `"github.com/stakater/sops-operator/internal/identity"` (the `controller` import already exists).
2. Next to the other `flag.…Var` calls, add:

```go
	var resyncInterval time.Duration
	flag.DurationVar(&resyncInterval, "resync-interval", 10*time.Minute,
		"How often tenants and SopsSecrets are re-checked (key changes, revoked grants, drift).")
```

3. Replace the scaffolded `SopsTenantReconciler` setup block (the `if err = (&controller.SopsTenantReconciler{ … }).SetupWithManager(mgr); err != nil { … }` block) with:

```go
	if err := controller.SetupIndexes(context.Background(), mgr); err != nil {
		setupLog.Error(err, "unable to set up field indexes")
		os.Exit(1)
	}
	identities := identity.NewFactory(mgr.GetConfig(), mgr.GetScheme())
	recorder := mgr.GetEventRecorderFor("sops-operator")
	if err := (&controller.SopsTenantReconciler{
		Client:         mgr.GetClient(),
		Identities:     identities,
		Recorder:       recorder,
		ResyncInterval: resyncInterval,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SopsTenant")
		os.Exit(1)
	}
```

- [ ] **Step 7: Run tests and build**

Run: `go build ./... && go test ./internal/controller/ -run Tenant -v`
Expected: build succeeds (the scaffolded `SopsSecretReconciler` still compiles unchanged); PASS (6 tests).

- [ ] **Step 8: Commit**

```bash
git add internal/controller/ cmd/main.go
git commit -m "feat(controller): SopsTenant key loading and post-quantum key generation"
```

---

### Task 12: SopsSecret controller

**Files:**
- Modify (replace contents): `internal/controller/sopssecret_controller.go`
- Modify: `internal/controller/main_test.go` (register the reconciler), `cmd/main.go`
- Test: `internal/controller/sopssecret_controller_test.go`

**Interfaces:**
- Consumes: `document.Canonical`, `document.ParsePlain`, `document.ScopeFor` (Task 8); `crypto.Decrypt`, `crypto.ParseKeyFile`, `crypto.ErrNotRecipient`, `crypto.KeyFileField`, `crypto.GenerateKeyFile` (Tasks 4–5); `identity.Factory`, `identity.CanWriteSecrets` (Task 9); `secretwriter.Write`, `secretwriter.ErrConflict` (Task 10); `IndexTenantRef`, `TenantRefKey` and test helpers (Task 11).
- Produces: `type controller.SopsSecretReconciler struct { client.Client; Identities *identity.Factory; Recorder record.EventRecorder; ResyncInterval time.Duration; Now func() time.Time }` with `Reconcile` and `SetupWithManager(mgr ctrl.Manager) error`.

- [ ] **Step 1: Register the reconciler in the test manager**

In `internal/controller/main_test.go`, after the `SopsTenantReconciler` setup in `startManager`, add:

```go
	if err := (&controller.SopsSecretReconciler{
		Client: mgr.GetClient(), Identities: ids, Recorder: recorder, ResyncInterval: resync,
	}).SetupWithManager(mgr); err != nil {
		return err
	}
```

- [ ] **Step 2: Write the failing tests**

`internal/controller/sopssecret_controller_test.go`:

```go
package controller_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

func create(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	if err := env.Admin.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func outputSecret(t *testing.T, ns, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s); err != nil {
		t.Fatalf("get output Secret: %v", err)
	}
	return &s
}

func assertNoSecret(t *testing.T, ns, name string) {
	t.Helper()
	err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Secret %s/%s must not exist: %v", ns, name, err)
	}
}

func TestSopsSecretDecrypts(t *testing.T) {
	prod := env.Namespace(t, "prod")
	tenantNS, recipient := onboardedTenant(t, prod)
	s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "hunter2"})
	s.Spec.Template.Metadata.Labels = map[string]string{"app": "billing", "argocd.argoproj.io/instance": "x"}
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

	out := outputSecret(t, prod, "db")
	if string(out.Data["password"]) != "hunter2" {
		t.Fatal("output Secret has the wrong value")
	}
	if out.Labels["app"] != "billing" || out.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
		t.Fatalf("labels = %v", out.Labels)
	}
	if _, ok := out.Labels["argocd.argoproj.io/instance"]; ok {
		t.Fatal("GitOps tracking label was copied")
	}
	if len(out.OwnerReferences) != 1 || out.OwnerReferences[0].UID != s.UID ||
		out.OwnerReferences[0].BlockOwnerDeletion == nil || *out.OwnerReferences[0].BlockOwnerDeletion {
		t.Fatalf("ownerReferences = %+v", out.OwnerReferences)
	}
	if s.Status.SecretUID != out.UID {
		t.Fatal("status.secretUID does not match the output Secret")
	}
}

func TestSopsSecretUpdatePropagatesAndDriftIsRepaired(t *testing.T) {
	ctx := context.Background()
	prod := env.Namespace(t, "prod")
	tenantNS, recipient := onboardedTenant(t, prod)
	s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

	next := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v2"})
	s.Spec, s.Sops = next.Spec, next.Sops
	if err := env.Admin.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(string(outputSecret(t, prod, "db").Data["password"])).To(Equal("v2"))
	}).WithTimeout(20 * time.Second).Should(Succeed())

	drifted := outputSecret(t, prod, "db")
	drifted.Data["password"] = []byte("tampered")
	if err := env.Admin.Update(ctx, drifted); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(string(outputSecret(t, prod, "db").Data["password"])).To(Equal("v2"))
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestSopsSecretFailures(t *testing.T) {
	prod := env.Namespace(t, "prod")
	dev := env.Namespace(t, "dev")
	ungranted := env.Namespace(t, "ungranted")
	tenantNS, recipient := onboardedTenant(t, prod, dev)
	_, otherRecipient, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"password": "hunter2"}

	cases := []struct {
		name   string
		build  func() *sopsv1alpha1.SopsSecret
		reason string
	}{
		{"tenant not found", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "nf", prod+"/nf", value)
			s.Spec.TenantRef.Name = "missing"
			return s
		}, sopsv1alpha1.ReasonTenantNotFound},
		{"namespace not granted", func() *sopsv1alpha1.SopsSecret {
			return encryptedSopsSecret(t, recipient, tenantNS, ungranted, "ad", ungranted+"/ad", value)
		}, sopsv1alpha1.ReasonAccessDenied},
		{"not a recipient", func() *sopsv1alpha1.SopsSecret {
			return encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "nr", prod+"/nr", value)
		}, sopsv1alpha1.ReasonNotRecipient},
		{"tampered", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "tp", prod+"/tp", value)
			s.Sops.LastModified = "2020-01-01T00:00:00Z"
			return s
		}, sopsv1alpha1.ReasonDecryptFailed},
		{"copied to another namespace", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "cp", prod+"/cp", value)
			s.Namespace = dev
			return s
		}, sopsv1alpha1.ReasonScopeMismatch},
		{"copied under another name", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "orig", prod+"/orig", value)
			s.Name = "renamed"
			return s
		}, sopsv1alpha1.ReasonScopeMismatch},
		{"tls without required keys", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "tls", prod+"/tls", value)
			s.Spec.Type = corev1.SecretTypeTLS
			return s
		}, sopsv1alpha1.ReasonApplyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.build()
			create(t, s)
			eventuallyReason(t, s, tc.reason)
			assertNoSecret(t, s.Namespace, s.Name)
		})
	}
}

func TestSopsSecretDoesNotTouchForeignSecret(t *testing.T) {
	ctx := context.Background()
	prod := env.Namespace(t, "prod")
	tenantNS, recipient := onboardedTenant(t, prod)
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: prod},
		Data:       map[string][]byte{"password": []byte("foreign")},
	}
	if err := env.Admin.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "mine"})
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonConflict)
	if string(outputSecret(t, prod, "db").Data["password"]) != "foreign" {
		t.Fatal("foreign Secret was overwritten")
	}
}

func TestRetainedSecretIsNotReclaimedByRecreatedSopsSecret(t *testing.T) {
	ctx := context.Background()
	prod := env.Namespace(t, "prod")
	tenantNS, recipient := onboardedTenant(t, prod)
	build := func() *sopsv1alpha1.SopsSecret {
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.DeletionPolicy = sopsv1alpha1.DeletionPolicyRetain
		return s
	}
	first := build()
	create(t, first)
	eventuallyReason(t, first, sopsv1alpha1.ReasonDecrypted)
	if refs := outputSecret(t, prod, "db").OwnerReferences; len(refs) != 0 {
		t.Fatalf("Retain must not set ownerReferences, got %+v", refs)
	}

	if err := env.Admin.Delete(ctx, first); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func() bool {
		return apierrors.IsNotFound(env.Admin.Get(ctx, client.ObjectKeyFromObject(first), &sopsv1alpha1.SopsSecret{}))
	}).WithTimeout(20 * time.Second).Should(BeTrue())

	second := build()
	create(t, second)
	eventuallyReason(t, second, sopsv1alpha1.ReasonConflict)
}

func TestSuspendedSopsSecretIsNotApplied(t *testing.T) {
	prod := env.Namespace(t, "prod")
	tenantNS, recipient := onboardedTenant(t, prod)
	s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "x"})
	s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
	if c := readyCondition(s); c.Status != metav1.ConditionUnknown {
		t.Fatalf("suspended Ready status = %s, want Unknown", c.Status)
	}
	assertNoSecret(t, prod, "db")
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/controller/ -run SopsSecret -v`
Expected: FAIL — compile error: unknown fields `Identities`, `Recorder`, `ResyncInterval` in `controller.SopsSecretReconciler`.

- [ ] **Step 4: Implement the reconciler**

`internal/controller/sopssecret_controller.go` (replace the whole file):

```go
package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwriter"
)

// trackingPrefixes are GitOps tracking label/annotation prefixes never copied to output Secrets.
var trackingPrefixes = []string{"argocd.argoproj.io/", "kustomize.toolkit.fluxcd.io/", "helm.toolkit.fluxcd.io/"}

// SopsSecretReconciler decrypts SopsSecrets into Secrets, acting as the referenced tenant identity.
type SopsSecretReconciler struct {
	client.Client
	Identities     *identity.Factory
	Recorder       record.EventRecorder
	ResyncInterval time.Duration
	Now            func() time.Time
}

type outcome struct {
	reason  string
	message string
	uid     types.UID
}

func (r *SopsSecretReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler.
func (r *SopsSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var s sopsv1alpha1.SopsSecret
	if err := r.Get(ctx, req.NamespacedName, &s); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !s.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	o := outcome{reason: sopsv1alpha1.ReasonSuspended, message: "reconciliation is suspended"}
	if s.Annotations[sopsv1alpha1.AnnotationSuspend] != "true" {
		var err error
		if o, err = r.sync(ctx, &s); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.updateStatus(ctx, &s, o); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

// sync runs the checks of DESIGN.md §6.2 in order. Policy failures are returned as outcomes;
// only transient errors are returned as errors.
func (r *SopsSecretReconciler) sync(ctx context.Context, s *sopsv1alpha1.SopsSecret) (outcome, error) {
	ref := s.Spec.TenantRef
	tenantName := TenantRefKey(ref.Namespace, ref.Name)

	var tenant sopsv1alpha1.SopsTenant
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return outcome{reason: sopsv1alpha1.ReasonTenantNotFound, message: fmt.Sprintf("SopsTenant %s not found", tenantName)}, nil
		}
		return outcome{}, err
	}
	if !meta.IsStatusConditionTrue(tenant.Status.Conditions, sopsv1alpha1.ConditionReady) {
		return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("SopsTenant %s is not ready", tenantName)}, nil
	}

	allowed, err := identity.CanWriteSecrets(ctx, r.Client, ref.Namespace, s.Namespace)
	if err != nil {
		return outcome{}, err
	}
	if !allowed {
		return outcome{reason: sopsv1alpha1.ReasonAccessDenied,
			message: fmt.Sprintf("tenant %s is not granted Secret write in namespace %s", tenantName, s.Namespace)}, nil
	}

	tc, err := r.Identities.ClientFor(ref.Namespace)
	if err != nil {
		return outcome{}, err
	}
	var key corev1.Secret
	if err := tc.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &key); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("key of tenant %s is not readable", tenantName)}, nil
		}
		return outcome{}, err
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("key of tenant %s is invalid", tenantName)}, nil
	}

	doc, err := document.Canonical(s)
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	plain, err := crypto.Decrypt(doc, keys)
	switch {
	case errors.Is(err, crypto.ErrNotRecipient):
		return outcome{reason: sopsv1alpha1.ReasonNotRecipient,
			message: fmt.Sprintf("the document is not encrypted for the key of tenant %s", tenantName)}, nil
	case err != nil:
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	payload, err := document.ParsePlain(plain)
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	if want := document.ScopeFor(s.Namespace, s.Name); payload.Scope != want {
		return outcome{reason: sopsv1alpha1.ReasonScopeMismatch,
			message: fmt.Sprintf("the document is scoped to %q, not %q", payload.Scope, want)}, nil
	}

	uid, err := secretwriter.Write(ctx, tc, desiredSecret(s, payload), s.Status.SecretUID)
	switch {
	case errors.Is(err, secretwriter.ErrConflict):
		return outcome{reason: sopsv1alpha1.ReasonConflict,
			message: fmt.Sprintf("Secret %s/%s exists and is not managed by this SopsSecret", s.Namespace, s.Name)}, nil
	case apierrors.IsForbidden(err):
		return outcome{reason: sopsv1alpha1.ReasonAccessDenied,
			message: fmt.Sprintf("tenant %s is not granted Secret write in namespace %s", tenantName, s.Namespace)}, nil
	case apierrors.IsInvalid(err), apierrors.IsBadRequest(err), apierrors.IsRequestEntityTooLargeError(err):
		return outcome{reason: sopsv1alpha1.ReasonApplyFailed, message: err.Error()}, nil
	case err != nil:
		return outcome{}, err
	}
	return outcome{reason: sopsv1alpha1.ReasonDecrypted, message: "Secret is up to date", uid: uid}, nil
}

func desiredSecret(s *sopsv1alpha1.SopsSecret, p *document.Payload) *corev1.Secret {
	labels := withoutTracking(s.Spec.Template.Metadata.Labels)
	labels[sopsv1alpha1.LabelManagedBy] = sopsv1alpha1.ManagedByValue
	labels[sopsv1alpha1.LabelSopsSecret] = s.Name
	secretType := s.Spec.Type
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}
	out := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        s.Name,
			Namespace:   s.Namespace,
			Labels:      labels,
			Annotations: withoutTracking(s.Spec.Template.Metadata.Annotations),
		},
		Type: secretType,
		Data: p.Data,
	}
	if s.Spec.DeletionPolicy != sopsv1alpha1.DeletionPolicyRetain {
		out.OwnerReferences = []metav1.OwnerReference{{
			APIVersion:         sopsv1alpha1.GroupVersion.String(),
			Kind:               "SopsSecret",
			Name:               s.Name,
			UID:                s.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(false),
		}}
	}
	return out
}

func withoutTracking(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		tracked := false
		for _, p := range trackingPrefixes {
			if strings.HasPrefix(k, p) {
				tracked = true
				break
			}
		}
		if !tracked {
			out[k] = v
		}
	}
	return out
}

func (r *SopsSecretReconciler) updateStatus(ctx context.Context, s *sopsv1alpha1.SopsSecret, o outcome) error {
	status := metav1.ConditionFalse
	switch o.reason {
	case sopsv1alpha1.ReasonDecrypted:
		status = metav1.ConditionTrue
		now := metav1.NewTime(r.now())
		s.Status.LastSyncTime = &now
		s.Status.SecretUID = o.uid
	case sopsv1alpha1.ReasonSuspended:
		status = metav1.ConditionUnknown
	}
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               sopsv1alpha1.ConditionReady,
		Status:             status,
		Reason:             o.reason,
		Message:            o.message,
		ObservedGeneration: s.Generation,
	})
	s.Status.ObservedGeneration = s.Generation
	return r.Status().Update(ctx, s)
}

// SetupWithManager registers the controller. Status updates do not retrigger reconciliation;
// tenant changes reconcile every SopsSecret that references the tenant.
func (r *SopsSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsSecret{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Watches(&sopsv1alpha1.SopsTenant{}, handler.EnqueueRequestsFromMapFunc(r.sopsSecretsOfTenant)).
		Named("sopssecret").
		Complete(r)
}

func (r *SopsSecretReconciler) sopsSecretsOfTenant(ctx context.Context, o client.Object) []reconcile.Request {
	var list sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &list, client.MatchingFields{IndexTenantRef: TenantRefKey(o.GetNamespace(), o.GetName())}); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, s := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&s)})
	}
	return reqs
}
```

- [ ] **Step 5: Wire the reconciler in cmd/main.go**

Replace the scaffolded `SopsSecretReconciler` setup block with:

```go
	if err := (&controller.SopsSecretReconciler{
		Client:         mgr.GetClient(),
		Identities:     identities,
		Recorder:       recorder,
		ResyncInterval: resyncInterval,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SopsSecret")
		os.Exit(1)
	}
```

- [ ] **Step 6: Run tests**

Run: `go build ./... && go test ./internal/controller/ -v`
Expected: PASS for all tenant and SopsSecret tests (the failure table has 7 subtests).

- [ ] **Step 7: Commit**

```bash
git add internal/controller/ cmd/main.go
git commit -m "feat(controller): decrypt SopsSecrets as the tenant identity with scope binding"
```

---

### Task 13: Full verification and samples

**Files:**
- Modify (replace contents): `config/samples/sops_v1alpha1_sopstenant.yaml`
- Delete: `config/samples/sops_v1alpha1_sopssecret.yaml` and its entry in `config/samples/kustomization.yaml` (an encrypted sample needs a real key; plan 2 adds an e2e-generated one)

**Interfaces:**
- Consumes: everything above.
- Produces: a green `make test lint build`.

- [ ] **Step 1: Replace the tenant sample**

`config/samples/sops_v1alpha1_sopstenant.yaml`:

```yaml
apiVersion: sops.stakater.com/v1alpha1
kind: SopsTenant
metadata:
  name: solar
  namespace: solar-system
spec:
  generateKey: true
```

Remove the `sops_v1alpha1_sopssecret.yaml` line from `config/samples/kustomization.yaml` and delete the file.

- [ ] **Step 2: Run the full suite, lint and build**

Run: `make manifests generate && git diff --exit-code config/ api/ && make test lint build`
Expected: no diff in generated files; all packages PASS; lint reports no issues; `bin/manager` built.

If lint reports issues, fix them in place (no `//nolint` unless the linter is wrong, with a comment saying why), rerun, and include the fixes in this commit.

- [ ] **Step 3: Confirm the operator role and tool versions**

Run: `grep -n "secrets" config/rbac/role.yaml || echo "no secrets permissions"; bin/operator-sdk version; bin/opm version`
Expected: `no secrets permissions`; operator-sdk `v1.42.3`; opm `v1.74.0`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: tenant sample and full verification"
```

---

## Self-Review Notes

- Spec coverage: §4.1 (Tasks 7, 11), §4.2 (Tasks 4, 11), §4.3 (Tasks 7, 8, 12), §5.1 flow order (Task 12 `sync`), §5.2 roles (Task 6), §5.3 operator permissions (Task 6, verified Task 13), §6.2 enforcement points 2–6 (Tasks 9, 10, 12), §9 tools (Tasks 2, 3), D18 (Task 11), D22 (Task 12), D28 (Task 10), D29 (Tasks 1, 5), D33 (Task 2). OLM bundle/catalog (using `bin/opm`), e2e, CI and docs are plans 2 and 3.
- The operator never reads Secrets with its own identity; the manager cache would fail with Forbidden if a reconciler did, so the controller tests catch regressions.
