/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
