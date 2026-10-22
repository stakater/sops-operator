# Scripts for SopsSecrets

[`encrypt.sh`](encrypt.sh) encrypts a `SopsSecret` file in your GitOps repository, so it can be committed.
Copy it into your GitOps repository, for example to `scripts/`.

It only changes the file. You commit it and your GitOps tool, for example Argo CD, applies it; nothing is
changed in the cluster directly.

## Before you start

Install:

- [sops](https://github.com/getsops/sops)
- [yq](https://github.com/mikefarah/yq) (the Go version by mikefarah)

Your GitOps repository needs a `.sops.yaml` that says which keys to encrypt for. sops uses the first
`.sops.yaml` it finds in the file's directory or a directory above it, for example one at the top of the
repository:

```text
gitops/
  .sops.yaml
  environments/
    stage/
      team-a/
        db-credentials.sops.yaml
```

```yaml
# gitops/.sops.yaml
creation_rules:
  - path_regex: ^environments/stage/.*\.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age:
      - age1pq1...   # public key of tenant team-a
```

Ask your tenant admin for the public key of the tenant, or read it from the cluster:

```bash
oc extract secret/team-a-sops-keys -n team-a-system --keys=age.pub --to=-
```

## Encrypt a secret

**Step 1.** Write the secret as a plaintext `SopsSecret`. Quote every value.

```yaml
# environments/stage/team-a/db-credentials.sops.yaml
apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: db-credentials
  namespace: team-a-stage
spec:
  tenantRef:
    name: team-a
    namespace: team-a-system
  stringData:
    username: "app"
    password: "s3cr3t"
```

**Step 2.** Encrypt it:

```bash
scripts/encrypt.sh environments/stage/team-a/db-credentials.sops.yaml
```

```console
Encrypted environments/stage/team-a/db-credentials.sops.yaml
```

The script sets `spec.scope` to `<namespace>/<name>`, sorts the keys and runs `sops encrypt`. Each step is
explained in the script.

**Step 3.** Check that the values are encrypted. Every value starts with `ENC[`:

```bash
yq '.spec.stringData' environments/stage/team-a/db-credentials.sops.yaml
```

**Step 4.** Commit and push. Argo CD applies the file, and the operator creates the Secret
`team-a-stage/db-credentials`:

```bash
oc get sopssecret db-credentials -n team-a-stage
```

> [!NOTE]
> - Never commit a file before it is encrypted.
> - You cannot decrypt the file again. To change a value, write the whole file in plaintext again and run
>   `encrypt.sh`.
> - If sops reports `no matching creation rules found`, no rule in `.sops.yaml` covers the file's path.

## Rotate the tenant key

[`rotate.sh`](rotate.sh) moves the `SopsSecret` files of a tenant to the tenant's next key during a key
rotation, and removes the old key afterwards. Like `encrypt.sh` it only changes files; you commit them and
your GitOps tool applies them.

It needs no private key, so it cannot decrypt anything. It only reads the `SopsTenant` and the
`SopsSecret`s from the cluster, so you need `oc` logged in with read access to them. For each file the
operator has prepared the entry that lets the file decrypt with the next key, and the script adds that
entry to the file's `sops.age`. Nothing else in the file changes.

**Step 1.** The tenant admin starts the rotation by setting `startRotation: true` in the `SopsTenant` file,
and commits it.

```yaml
# environments/stage/team-a-system/tenant.yaml
spec:
  startRotation: true
```

**Step 2.** Each team adds the next key to its files. Give the `SopsTenant` file and the GitOps directory
the files are in:

```bash
scripts/rotate.sh environments/stage/team-a-system/tenant.yaml environments/stage
```

```console
Added the next key to environments/stage/team-a/db-credentials.sops.yaml
Done. Review the changes and commit them.
```

The script also adds the next key to the tenant's rule in every `.sops.yaml` in the directory, so files
you encrypt from now on can be decrypted with both keys. Other recipients, such as break-glass keys, stay.
It changes no file if one is not in the cluster yet, or the operator has not prepared the entry for its
latest change yet, so let your GitOps tool apply every file first and run it again a little later.

**Step 3.** Review the changes with `git diff`, then commit and push.

**Step 4.** When every team has applied its files, the tenant admin sets `startRotation: false` and
commits. The rotation completes once every file is applied.

```yaml
# environments/stage/team-a-system/tenant.yaml
spec:
  startRotation: false
```

**Step 5.** Each team runs the same script again. It now removes the old key from the files and from the
`.sops.yaml`. Commit and push.

```bash
scripts/rotate.sh environments/stage/team-a-system/tenant.yaml environments/stage
```

```console
Removed the old key from environments/stage/team-a/db-credentials.sops.yaml
Done. Review the changes and commit them.
```

> [!NOTE]
> - The script is safe to run again: files that are already up to date stay unchanged.
> - It lists the tenant's `SopsSecret`s that have no file in the directory, so you can find the ones in
>   another directory.
