# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before 1.0.0 may contain breaking changes;
they are marked **Breaking** with the steps to take.

## [0.0.5] - 2026-11-10

### Added

- Each tenant key is an immutable Secret `<tenant>-sops-keys-<index>` (0, 1, …) holding `age.agekey` and the
  public key of its primary identity in `age.pub`. The highest index is the current key; it must carry the label
  `sops.stakater.com/enabled: "true"` and hold a valid key, otherwise the tenant reports `KeyMissing` or
  `KeyInvalid` naming the Secret, with no fall-back to a lower index. Every labelled key Secret with a valid key
  decrypts, so a file encrypted for any of them keeps working. A key Secret the tenant admin brings is made
  immutable, with `age.pub` added, once it carries the label. Key Secrets have no owner: they survive the deletion
  of the `SopsTenant`, and a `SopsTenant` created again uses them.
- `SopsTenant` `status.publicKey`: the public key of the current key for `.sops.yaml`, a copy of its `age.pub`.
- Output Secrets are watched (metadata only) as the tenant identity: a deleted or changed output Secret, its values,
  labels or annotations, is restored at once instead of at the next resync, in place (same UID). Key Secrets are
  watched the same way, so a new or changed key Secret is picked up at once.
- `scripts/encrypt.sh` encrypts a plaintext `SopsSecret` file in a GitOps directory; a scope already in the file is
  kept.
- `make test-e2e E2E_RUN='<regex>'` runs a subset of the e2e tests.
- `make images` builds the operator, bundle and catalog images of one build: `TAG`, the version it releases (by
  default `make next-version`), and `PR_TAG`, which marks a pre-release build of it. Every pull request builds them
  once, tests them on kind and publishes them as `v<version>-pr-<number>-<sha7>`; its catalog has the release's
  upgrade graph with the build in place of the version. `build` takes `MANAGER_BIN`, and `docker-build`, `bundle-build` and
  `catalog-build` take `DOCKER_BUILD_ARGS`; the release workflow uses them instead of its own commands.

### Changed

- **Breaking:** the ClusterRole `sops-tenant-secret-reconciler` (`create`, `update`, `delete`, `list`, `watch` on
  Secrets) replaces `sops-secret-writer`. Until a namespace binds the new role, its `SopsSecret`s report
  `AccessDenied` naming the role and the verbs it checks (`create`, `update`, `list`, `watch`), and existing
  Secrets stay as they are.
  **Action:** in each application namespace, bind `sops-tenant-secret-reconciler` to `<tenant>-sops-tenant`
  (see the README, onboarding step 2c), then delete the bindings to `sops-secret-writer`.
- **Breaking:** the key Secret is renamed from `<tenant>-sops-keys` to `<tenant>-sops-keys-0`, and
  `status.keySecretName` names the current (highest-indexed) key Secret. On upgrade, the operator moves the key of
  `<tenant>-sops-keys` into `<tenant>-sops-keys-0` only once `<tenant>-sops-keys` carries the label
  `sops.stakater.com/enabled: "true"`, also when 0.0.4 generated it; until then the tenant reports `KeyMissing`
  naming the label. The old Secret is left in place.
  **Action:** label the key Secret of each tenant:
  `kubectl label secret <tenant>-sops-keys -n <tenant-namespace> sops.stakater.com/enabled=true`. Point tooling
  that reads `<tenant>-sops-keys` at `<tenant>-sops-keys-0`, or at the highest index. Delete `<tenant>-sops-keys`
  once `<tenant>-sops-keys-0` exists.
- A generated `age.agekey` has no comment lines; the public key is in the key Secret's `age.pub`. An immutable key
  Secret whose `age.pub` does not match its `age.agekey` reports `KeyInvalid`.
- **Breaking:** labels and annotations in a `SopsSecret`'s `spec.template.metadata` are copied as written.
  `argocd.argoproj.io/`, `kustomize.toolkit.fluxcd.io/` and `helm.toolkit.fluxcd.io/` keys in the template are no
  longer dropped; keys starting with `sops.stakater.com/` are. The `SopsSecret`'s own labels and annotations, where
  GitOps tools put their tracking keys, are still never copied.
  **Action:** remove GitOps tracking keys from `spec.template.metadata` if you put them there, or the GitOps tool
  may claim or prune the output Secret.
- **Breaking:** a Secret belongs to a `SopsSecret` when it has the `SopsSecret`'s name and namespace and carries the
  label `sops.stakater.com/enabled: "true"`, instead of matching a UID recorded in status; `status.secretUID` is
  removed. There are no exceptions: a Secret with the same name without the label, an output Secret written by
  0.0.4 included, is never changed or deleted, and the `SopsSecret` reports `Conflict` naming the label. A
  `SopsSecret` whose status is lost, or that is recreated or restored, keeps managing its Secret, and a Secret kept
  by `deletionPolicy: Retain` is taken over by the next `SopsSecret` with the same name.
  **Action:** label each output Secret written by 0.0.4, for example per namespace:
  `kubectl label secret -n <namespace> -l app.kubernetes.io/managed-by=sops-operator sops.stakater.com/enabled=true`.
  Before applying a `SopsSecret` with the name of a retained Secret, make sure that Secret may be overwritten.
- **Breaking:** output Secrets have no owner reference, in any mode, so no UID ties a Secret to its `SopsSecret`.
  Owner references written by 0.0.4 are removed on the next write. Argo CD no longer shows the output Secret as a
  child of the `SopsSecret` in its resource tree.
  **Action:** none, unless tooling relies on the owner reference; select output Secrets by the label
  `sops.stakater.com/enabled: "true"` and the annotation `sops.stakater.com/sopssecret` instead.
- With `deletionPolicy: Delete` (default), the operator keeps the finalizer `sops.stakater.com/output-secret` on the
  `SopsSecret`. When the `SopsSecret` is deleted, it deletes the labelled Secret with the same name as the tenant
  identity, at the version it just read, then removes the finalizer. A deletion the tenant may not make, for
  example in a namespace being deleted with its grant or after the grant was revoked, does not block: the
  finalizer is removed and the Secret is left. `deletionPolicy: Retain` adds no finalizer; changing the policy adds
  or removes it. `sops-tenant-secret-reconciler` gains `delete` on Secrets for this; the operator's ClusterRole
  gains `update` and `patch` on `sopssecrets` and `update` on `sopssecrets/finalizers`.
- Every Secret the operator manages (output Secrets and key Secrets) carries the label
  `sops.stakater.com/enabled: "true"`.
- The operator never reads status to decide anything; it rebuilds status on every reconcile from spec and the
  objects it manages; `status.publicKey` and `status.keySecretName` are set only when a current key is found. A
  `SopsSecret` no longer waits for its tenant's `Ready` condition: it reads the tenant's key Secrets as the tenant
  identity and reports `TenantNotReady` when none is labelled with a valid key, or they cannot be read.
- A key is generated only when there is no key Secret `<tenant>-sops-keys-<index>` and no 0.0.4 key Secret,
  `generateKey` is not `false`, and no `SopsSecret` references the tenant; otherwise the tenant reports
  `KeyMissing` with the number of `SopsSecret`s.
- `sops-key-owner` also grants `list`, `watch` and `update` on Secrets in the tenant namespace, for finding the key
  Secrets, the key watch, and making a brought key Secret immutable with `age.pub`. Existing bindings need no
  change.
- Output Secrets are written after a metadata-only list by name, updated at the version that was read; the
  operator never reads Secret data.
- envtest test runs stop the `etcd` and `kube-apiserver` processes a killed test run left behind, and stop envtest
  on SIGINT and SIGTERM.

### Removed

- The ClusterRole `sops-secret-writer`.
- `SopsSecret` `status.secretUID`.

### Security

- With `list` and `watch` in `sops-tenant-secret-reconciler`, the tenant identity, and the operator acting as it,
  can read the Secrets in the namespaces granted to it. The operator requests metadata only and never logs Secret
  contents. Grant only namespaces the tenant may see.
- A `SopsSecret` can no longer set `sops.stakater.com/` labels or annotations on its output Secret, so an output
  Secret cannot be marked for the operator by its template.
- A `SopsSecret` named like a key Secret in the tenant namespace cannot change it: key Secrets are immutable, the
  API server rejects the write, and the `SopsSecret` reports `ApplyFailed`.
- Accepted risk: anyone who can label Secrets in a namespace can hand a Secret to a `SopsSecret` of the same name,
  which then overwrites it and, with `deletionPolicy: Delete`, deletes it. Labelling needs `update` on that Secret,
  which already allows changing it.
- Accepted risk: a `SopsSecret` deleted after its tenant lost the namespace grant leaves its Secret behind for the
  admin; the deletion is not blocked.
- Accepted risk: the tenant admin can delete a key Secret, which loses that key. Cluster backups cover it. While
  `SopsSecret`s use the tenant, no new key is generated in its place.

## [0.0.4] - 2026-10-14

### Changed

- **Breaking:** the tenant key Secret is named `<tenant>-sops-keys` instead of `<tenant>`, and reported in
  `SopsTenant` `status.keySecretName`.
  **Action:** before upgrading from 0.0.3, copy the Secret `<tenant>` to `<tenant>-sops-keys` in the tenant
  namespace; otherwise the operator generates a new key and files encrypted for the old key no longer decrypt.

## [0.0.3] - 2026-10-14

### Added

- The operator creates each tenant's ServiceAccount, `<tenant>-sops-tenant`, and reports it in
  `status.serviceAccountName`.
- The ClusterRole `sops-operator-tenant` (`create`, `impersonate` on ServiceAccounts), bound to the operator in
  each tenant namespace.

### Changed

- **Breaking:** onboarding is RoleBindings only, per tenant: `sops-operator-tenant` to the operator and
  `sops-key-owner` to `<tenant>-sops-tenant` in the tenant namespace, and `sops-secret-writer` to
  `<tenant>-sops-tenant` in each namespace the tenant may write to. The operator has no cluster-wide
  ServiceAccount permissions.
  **Action:** onboard each tenant again with these bindings.
- The tenant admin may create the two tenant-namespace RoleBindings; namespace grants stay with the cluster
  admin.
- Tenant names are limited to 63 characters.

## [0.0.2] - 2026-10-14

### Added

- Upgrade tests along the channel graph of the catalog.

### Changed

- Events are recorded through the `events.k8s.io` API.
- Releases never overwrite a published image tag, and each catalog publish gets an immutable tag.

## [0.0.1] - 2026-10-12

### Added

- `SopsTenant` and `SopsSecret` custom resources, installed through OLM.
- Decryption of SOPS files in the cluster with a post-quantum age key per tenant, generated by the operator or
  brought by the tenant admin.
- Zero standing privileges: every key read and Secret write is an impersonated call as the tenant's identity.
- Ciphertext bound to its destination: the encrypted scope must match the `SopsSecret`'s namespace and name.
- Write-only output Secrets, tracked by the UID of the Secret the operator created.

[0.0.5]: https://github.com/stakater/sops-operator/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/stakater/sops-operator/compare/1612367...v0.0.4
[0.0.3]: https://github.com/stakater/sops-operator/compare/v0.0.2...1612367
[0.0.2]: https://github.com/stakater/sops-operator/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/stakater/sops-operator/releases/tag/v0.0.1
