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

// Package document reads the decrypted values of a SopsSecret.
package document

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrScopeMismatch reports a value whose scope line is not the expected one.
var ErrScopeMismatch = errors.New("scope mismatch")

// ScopeFor returns the scope line a value under key of a SopsSecret named name in namespace must
// start with. Object names and Secret keys cannot contain "/", so the line is unambiguous.
func ScopeFor(namespace, name, key string) string { return namespace + "/" + name + "/" + key }

// Value checks that a decrypted value starts with the line wantScope and returns the bytes after
// it, so a value copied to another namespace, name or key is rejected. A CR before the line feed
// is ignored. Errors never contain decrypted data.
func Value(plain []byte, wantScope string) ([]byte, error) {
	line, value, found := bytes.Cut(plain, []byte("\n"))
	if !found || string(bytes.TrimSuffix(line, []byte("\r"))) != wantScope {
		// The decrypted line is not repeated: error messages never contain decrypted values.
		return nil, fmt.Errorf("%w: the decrypted value does not start with the line %q; it was encrypted for "+
			"another namespace, name or key, or without its scope line", ErrScopeMismatch, wantScope)
	}
	return value, nil
}
