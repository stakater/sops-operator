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
	"io"
	"strings"

	"filippo.io/age"
)

var (
	// ErrMalformed reports a value that is not a base64-encoded age file.
	ErrMalformed = errors.New("malformed age file")
	// ErrNotRecipient reports a file that is not encrypted for any of the given keys.
	ErrNotRecipient = errors.New("file is not encrypted for this key")
	// ErrDecrypt reports a file that fails decryption or authentication.
	ErrDecrypt = errors.New("decryption failed")
)

// header starts every binary age file.
const header = "age-encryption.org/v1\n"

// DecryptValue decrypts a base64-encoded binary age file (`age ... | base64`) with the given keys and
// returns the plaintext. Whitespace, including line breaks from wrapping base64 encoders, is
// ignored. age authenticates the whole file, so a modified file fails with ErrDecrypt. Errors never
// contain decrypted data.
func DecryptValue(encoded string, keys *KeySet) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return nil, fmt.Errorf("%w: the value is not valid base64", ErrMalformed)
	}
	if !bytes.HasPrefix(raw, []byte(header)) {
		return nil, fmt.Errorf("%w: the value is not a binary age file encoded in base64", ErrMalformed)
	}
	r, err := age.Decrypt(bytes.NewReader(raw), keys.Identities...)
	var noMatch *age.NoIdentityMatchError
	switch {
	case errors.As(err, &noMatch):
		return nil, ErrNotRecipient
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: the file was modified or truncated", ErrDecrypt)
	}
	return plain, nil
}
