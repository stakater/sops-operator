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
	"bytes"
	"encoding/base64"
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
	"github.com/getsops/sops/v3/stores/yaml"
)

var (
	// ErrMalformed reports a value that is not a base64-encoded SOPS file.
	ErrMalformed = errors.New("malformed SOPS file")
	// ErrUnencrypted reports a SOPS file with values that sops left in plaintext.
	ErrUnencrypted = errors.New("unencrypted value")
	// ErrUnsupported reports SOPS key configurations other than age recipients in one key group.
	ErrUnsupported = errors.New("unsupported SOPS key configuration")
	// ErrNotRecipient reports a document that is not encrypted for any of the given keys.
	ErrNotRecipient = errors.New("document is not encrypted for this key")
	// ErrDecrypt reports a document that fails decryption or MAC verification.
	ErrDecrypt = errors.New("decryption failed")
	// ErrScopeMismatch reports a document whose encrypted scope is not the expected one.
	ErrScopeMismatch = errors.New("scope mismatch")
)

// load reads a SOPS file written as JSON (--output-type json) or YAML.
func load(raw []byte) (sops.Tree, error) {
	var store interface {
		LoadEncryptedFile([]byte) (sops.Tree, error)
	} = yaml.NewStore(&config.YAMLStoreConfig{})
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		store = json.NewStore(&config.JSONStoreConfig{})
	}
	tree, err := store.LoadEncryptedFile(raw)
	if err != nil {
		return sops.Tree{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(tree.Branches) == 0 {
		return sops.Tree{}, fmt.Errorf("%w: the file holds no document", ErrMalformed)
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

// scopePath is where the encrypted scope lives; SOPS authenticates each value with its path.
var scopePath = []string{"scope"}

// DecryptValue decrypts a SopsSecret value: a SOPS file as JSON text, usually compacted to one line
// (`sops encrypt --output-type json <file> | jq -c .`), or any SOPS file in base64. The file is read
// as sops wrote it, so the MAC covers exactly what sops encrypted; whitespace between JSON tokens and
// in base64 does not matter. It returns the plaintext document as JSON. Identities are applied in
// memory to this file only.
//
// Every value must be encrypted. The encrypted scope is decrypted and compared with wantScope before
// any other value, so a file copied elsewhere is rejected without decrypting its values. Errors never
// contain decrypted values: SOPS does not authenticate a value's type tag, and its parse errors quote
// the plaintext.
func DecryptValue(encoded string, keys *KeySet, wantScope string) ([]byte, error) {
	raw := []byte(strings.TrimSpace(encoded))
	if !bytes.HasPrefix(raw, []byte("{")) {
		var err error
		if raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), "")); err != nil {
			return nil, fmt.Errorf("%w: the value is neither a SOPS JSON file nor base64", ErrMalformed)
		}
	}
	tree, err := load(raw)
	if err != nil {
		return nil, err
	}
	if err := checkEncrypted(tree.Branches[0], ""); err != nil {
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
		return nil, fmt.Errorf("%w: MAC mismatch; the file was modified", ErrDecrypt)
	}
	plain, err := json.NewStore(&config.JSONStoreConfig{}).EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("%w: the decrypted document could not be rendered", ErrDecrypt)
	}
	return plain, nil
}

// checkEncrypted returns ErrUnencrypted for the first value under branch that sops left in plaintext,
// for example because of encrypted_regex. Errors name the path, never the value.
func checkEncrypted(branch sops.TreeBranch, prefix string) error {
	for _, item := range branch {
		key, ok := item.Key.(string)
		if !ok {
			continue // comments
		}
		if err := checkValue(item.Value, prefix+key); err != nil {
			return err
		}
	}
	return nil
}

func checkValue(v any, path string) error {
	switch v := v.(type) {
	case sops.TreeBranch:
		return checkEncrypted(v, path+".")
	case []any:
		for i, e := range v {
			if err := checkValue(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case string:
		if strings.HasPrefix(v, "ENC[") {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not encrypted; encrypt every value (no encrypted_regex or unencrypted_suffix "+
		"in the creation rule)", ErrUnencrypted, path)
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
