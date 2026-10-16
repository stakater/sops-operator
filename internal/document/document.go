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

// Package document reads the decrypted payload of a SopsSecret.
package document

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"
)

// ErrScopeMismatch reports a payload whose scope is not the expected one.
var ErrScopeMismatch = errors.New("scope mismatch")

// Payload is the decrypted content of a SopsSecret.
type Payload struct {
	Scope string
	Data  map[string][]byte
}

// ScopeFor returns the scope value a SopsSecret named name in namespace must carry.
func ScopeFor(namespace, name string) string { return namespace + "/" + name }

// Parse reads a decrypted payload, a YAML document with the fields scope, data and stringData,
// and checks its scope is wantScope before reading any value, so a file copied elsewhere is
// rejected for that reason alone. stringData values must be quoted strings: YAML parses unquoted
// scalars (0123 becomes 83), so they are refused instead of being converted. Errors name keys but
// never values.
func Parse(plain []byte, wantScope string) (*Payload, error) {
	raw, err := yaml.YAMLToJSON(plain)
	if err != nil {
		return nil, errors.New("the decrypted payload is not valid YAML")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, errors.New("the decrypted payload must be a YAML mapping")
	}
	var scope string
	if err := json.Unmarshal(fields["scope"], &scope); err != nil {
		return nil, errors.New("the decrypted payload must hold a string scope")
	}
	if scope != wantScope {
		// The decrypted scope is not repeated: error messages never contain decrypted values.
		return nil, fmt.Errorf("%w: the document is scoped to a different namespace or name than %q", ErrScopeMismatch, wantScope)
	}
	// Field names are matched exactly: encoding/json would also accept a misspelt "stringdata".
	var doc struct {
		Data       map[string]any
		StringData map[string]any
	}
	for name, value := range fields {
		var into *map[string]any
		switch name {
		case "scope":
			continue
		case "data":
			into = &doc.Data
		case "stringData":
			into = &doc.StringData
		default:
			return nil, fmt.Errorf("the decrypted payload has the unknown field %q; only scope, data and stringData are allowed", name)
		}
		if err := json.Unmarshal(value, into); err != nil {
			return nil, fmt.Errorf("%s in the decrypted payload must be a mapping of keys to strings", name)
		}
	}
	if len(doc.Data) == 0 && len(doc.StringData) == 0 {
		return nil, errors.New("the decrypted payload must hold data or stringData")
	}
	p := &Payload{Scope: scope, Data: map[string][]byte{}}
	for k, v := range doc.Data {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("data.%s must be a base64 string", k)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("data.%s is not valid base64", k)
		}
		p.Data[k] = b
	}
	for k, v := range doc.StringData {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("stringData.%s must be a quoted string", k)
		}
		if _, dup := p.Data[k]; dup {
			return nil, fmt.Errorf("key %s appears in both data and stringData", k)
		}
		p.Data[k] = []byte(s)
	}
	return p, nil
}
