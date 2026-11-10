# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before 1.0.0 may contain breaking changes;
they are marked **Breaking** with the steps to take.

## [0.0.5] - 2026-11-10

### Added

- Immutable backups of the tenant key, `<tenant>-sops-keys-<YYYYMMDD-HHMMSS>` (UTC), with the labels
  `sops.stakater.com/enabled` and `sops.stakater.com/key-backup` and the public key in the annotation
  `sops.stakater.com/public-key`. Outside a rotation, a deleted or changed key Secret is restored from the backup
  of the recorded key, with a Warning event `KeyRestored`. A key is generated only for a tenant that never had one,
  and a `SopsTenant` recreated without status restores the newest backup.
- GitOps key rotation. `SopsTenant` `spec.startRotation: true` starts a rotation once every `SopsSecret` of the
  tenant is `Decrypted`. With `generateKey: true` the operator generates the new key; with `false` the tenant admin
  replaces the key Secret with it. The key Secret then holds the new key and the old key stays in its backup.
  Setting the flag back to `false` completes the rotation once every `SopsSecret` decrypts with the new key, and
  deletes the old key's backup; while no `SopsSecret` does, it abandons the rotation and restores the old key.
- `SopsTenant` status: `publicKey`, `rotation` (`phase`, `startedAt`, `previousPublicKey`, `migrated`, `pending`,
  `pendingSecrets`) and `lastRotation` (`startedAt`, `completedAt`, `previousPublicKey`), and the `LAST ROTATED`
  printer column.
- `SopsTenant` condition `Rotated` with reasons `RotationRefused`, `WaitingForKey`, `RotationPending`,
  `RotationBlocked`, `RotationComplete` and `RotationAbandoned`.
- `SopsTenant` reason `KeyMismatch`: the key Secret holds another key than `status.publicKey` and there is no
  backup of the recorded key.
- `SopsSecret` `status.rotation`: during a rotation, the `sops.age` entry that adds the new key to the file.
- `SopsSecret` reason `NextKeyRequired`: during a rotation, a new or changed file must be encrypted for the new key.
- `scripts/encrypt.sh` encrypts a plaintext `SopsSecret` file in a GitOps directory.
- `scripts/rotate.sh` adds the operator-prepared entry for the new key to every `SopsSecret` file of a tenant and
  the new key to the `.sops.yaml` rules that list the old key, and removes the old key after the rotation
  completed.
- Output Secrets are watched (metadata only) as the tenant identity: a deleted or changed output Secret, its values,
  labels or annotations, is restored at once instead of at the next resync.

### Changed

- **Breaking:** the ClusterRole `sops-tenant-secret-reconciler` (`create`, `update`, `list`, `watch` on Secrets)
  replaces `sops-secret-writer`. Until a namespace binds the new role, its `SopsSecret`s report `AccessDenied`
  naming the role, and existing Secrets stay as they are.
  **Action:** in each application namespace, bind `sops-tenant-secret-reconciler` to `<tenant>-sops-tenant`
  (see the README, onboarding step 2c), then delete the bindings to `sops-secret-writer`.
- **Breaking:** a key Secret `<tenant>-sops-keys` you brought yourself is used only when it carries the label
  `sops.stakater.com/enabled: "true"`; otherwise the tenant reports `KeyMissing` naming the label. Key Secrets the
  operator generated are labelled automatically.
  **Action:** add the label `sops.stakater.com/enabled: "true"` to every key Secret you created yourself.
- **Breaking:** the key Secret holds only the private key: a generated `age.agekey` has no comment lines and
  `age.pub` is no longer written, and an existing `age.pub` field is ignored. Read the public key from
  `SopsTenant` `status.publicKey`.
  **Action:** if tooling reads `age.pub` from the key Secret, read `status.publicKey` instead.
- Every Secret the operator manages (output Secrets, key Secrets and key backups) carries the label
  `sops.stakater.com/enabled: "true"`. Labels and annotations starting with `sops.stakater.com/` in a
  `SopsSecret`'s `spec.template.metadata` are dropped.
- `sops-key-owner` also grants `list`, `watch`, `update` and `delete` on Secrets in the tenant namespace, for key
  backups, the key watch, restores and rotations. Existing bindings need no change.
- `AccessDenied` on a `SopsSecret` names the ClusterRole to bind and the Secret verbs it needs.
- A tenant whose recorded key is missing and has no backup reports `KeyMissing` instead of generating a new key.
- On upgrade, each tenant gets `status.publicKey` and the backup of its key at its first reconcile; a generated key
  Secret keeps its `age.pub` field, which is ignored. Existing output Secrets get the `enabled` label and are
  watched after their first write by v0.0.5, which needs the `sops-tenant-secret-reconciler` binding.
- envtest test runs stop the `etcd` and `kube-apiserver` processes a killed test run left behind.

### Removed

- The ClusterRole `sops-secret-writer`.
- The `KeyInvalid` check for an `age.pub` field that does not match the key file.

### Security

- With `list` and `watch` in `sops-tenant-secret-reconciler`, the tenant identity, and the operator acting as it,
  can read the Secrets in the namespaces granted to it. The operator requests metadata only and never logs Secret
  contents. Grant only namespaces the tenant may see.
- A `SopsSecret` can no longer set `sops.stakater.com/` labels or annotations on its output Secret, so an output
  Secret cannot pose as a key backup or be marked for the operator by its template.
- Accepted risk: the tenant admin can delete both the key Secret and its backup, which loses the key. Cluster
  backups cover it.

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
