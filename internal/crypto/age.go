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
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

var (
	// ErrMalformed reports a value that is not an ASCII-armored age file.
	ErrMalformed = errors.New("malformed age file")
	// ErrNotRecipient reports a file that is not encrypted for any of the given keys.
	ErrNotRecipient = errors.New("file is not encrypted for this key")
	// ErrDecrypt reports a file that fails decryption or authentication.
	ErrDecrypt = errors.New("decryption failed")
)

// Decrypt decrypts an ASCII-armored age file with the given keys and returns the plaintext.
// Surrounding whitespace is ignored. age authenticates the whole file, so a modified file fails
// with ErrDecrypt. Errors never contain decrypted data.
func Decrypt(armored string, keys *KeySet) ([]byte, error) {
	armored = strings.TrimSpace(armored)
	if !strings.HasPrefix(armored, armor.Header) {
		return nil, fmt.Errorf("%w: the value does not start with %q", ErrMalformed, armor.Header)
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), keys.Identities...)
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
