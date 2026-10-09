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
