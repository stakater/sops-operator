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

package crypto

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/json"
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
	// ErrScopeMismatch reports a document whose encrypted scope is not the expected one.
	ErrScopeMismatch = errors.New("scope mismatch")
)

func newStore() *json.Store { return json.NewStore(&config.JSONStoreConfig{}) }

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
	keys := make([]*sopsage.MasterKey, 0, len(tree.Metadata.KeyGroups[0]))
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

// scopePath is where the encrypted scope lives; SOPS authenticates each value with its path.
var scopePath = []string{"spec", "scope"}

// Decrypt decrypts a SOPS-encrypted JSON document (as returned by the Kubernetes API, keys
// sorted byte-wise) with the given keys and returns the plaintext JSON document. Identities are
// applied in memory to this document only.
//
// The encrypted scope is decrypted and compared with wantScope before any other value, so a
// document copied elsewhere is rejected without decrypting its values. Errors never contain
// decrypted values: SOPS does not authenticate a value's type tag, and its parse errors quote
// the plaintext.
func Decrypt(doc []byte, keys *KeySet, wantScope string) ([]byte, error) {
	tree, err := load(doc)
	if err != nil {
		return nil, err
	}
	dataKey, err := unwrapDataKey(tree, keys)
	if err != nil {
		return nil, err
	}

	cipher := aes.NewCipher()
	if err := checkScope(tree, cipher, dataKey, wantScope); err != nil {
		return nil, err
	}
	computed, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("%w: a value could not be decrypted", ErrDecrypt)
	}
	stored, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339))
	if s, ok := stored.(string); err != nil || !ok || s != computed {
		return nil, fmt.Errorf("%w: MAC mismatch; the file was modified, or its keys were not sorted "+
			"(yq -i 'sort_keys(..)') before encryption", ErrDecrypt)
	}
	plain, err := newStore().EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("%w: the decrypted document could not be rendered", ErrDecrypt)
	}
	return plain, nil
}

// unwrapDataKey returns the data key of tree, unwrapped with the first of keys that the tree is
// encrypted for.
func unwrapDataKey(tree sops.Tree, keys *KeySet) ([]byte, error) {
	fileKeys, err := ageKeys(tree)
	if err != nil {
		return nil, err
	}
	ids := sopsage.ParsedIdentities(keys.Identities)
	matched := false
	for _, k := range fileKeys {
		if !slices.Contains(keys.Recipients, k.Recipient) {
			continue
		}
		matched = true
		ids.ApplyToMasterKey(k)
		if dk, err := k.Decrypt(); err == nil {
			return dk, nil
		}
	}
	if !matched {
		return nil, ErrNotRecipient
	}
	return nil, fmt.Errorf("%w: the data key could not be unwrapped", ErrDecrypt)
}

// AgeEntry is one entry of a SOPS file's sops.age list: the file's data key wrapped for Recipient.
type AgeEntry struct {
	Recipient string
	Enc       string
}

// WrapDataKey unwraps the data key of doc with keys and wraps it for recipient. Appending the
// result to sops.age lets recipient's identity decrypt doc; the encrypted values, the MAC and
// lastmodified do not depend on sops.age and stay valid. The entry contains no plaintext and no
// private key. Errors never contain key material.
func WrapDataKey(doc []byte, keys *KeySet, recipient string) (AgeEntry, error) {
	tree, err := load(doc)
	if err != nil {
		return AgeEntry{}, err
	}
	dataKey, err := unwrapDataKey(tree, keys)
	if err != nil {
		return AgeEntry{}, err
	}
	mk, err := sopsage.MasterKeyFromRecipient(recipient)
	if err != nil {
		return AgeEntry{}, fmt.Errorf("%w: %q is not a valid age recipient", ErrUnsupported, recipient)
	}
	if err := mk.Encrypt(dataKey); err != nil {
		return AgeEntry{}, fmt.Errorf("wrap the data key: %w", err)
	}
	return AgeEntry{Recipient: mk.Recipient, Enc: mk.EncryptedKey}, nil
}

// checkScope decrypts only the scope value and compares it with want.
func checkScope(tree sops.Tree, cipher sops.Cipher, dataKey []byte, want string) error {
	raw, ok := lookup(tree.Branches, scopePath)
	ciphertext, isString := raw.(string)
	if !ok || !isString {
		return fmt.Errorf("%w: the document has no encrypted scope", ErrDecrypt)
	}
	v, err := cipher.Decrypt(ciphertext, dataKey, strings.Join(scopePath, ":")+":")
	got, isString := v.(string)
	if err != nil || !isString {
		return fmt.Errorf("%w: the scope could not be decrypted as a string", ErrDecrypt)
	}
	if got != want {
		// The decrypted scope is not repeated: error messages never contain decrypted values.
		return fmt.Errorf("%w: the document is scoped to a different namespace or name than %q", ErrScopeMismatch, want)
	}
	return nil
}

// lookup returns the value at path in the first branch of a tree.
func lookup(branches sops.TreeBranches, path []string) (any, bool) {
	if len(branches) == 0 {
		return nil, false
	}
	var current any = branches[0]
	for _, key := range path {
		branch, ok := current.(sops.TreeBranch)
		if !ok {
			return nil, false
		}
		found := false
		for _, item := range branch {
			if k, ok := item.Key.(string); ok && k == key {
				current, found = item.Value, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return current, true
}
