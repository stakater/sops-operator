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

// Package document reads the decrypted content of a SopsSecret.
package document

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Payload is the decrypted content of a SopsSecret.
type Payload struct {
	Scope string
	Data  map[string][]byte
}

// ScopeFor returns the scope value a SopsSecret named name in namespace must carry.
func ScopeFor(namespace, name string) string { return namespace + "/" + name }

// ParsePlain reads a decrypted document (JSON): scope, data and stringData, and no other field.
// stringData values must be quoted strings: SOPS parses unquoted scalars before encrypting (0123
// becomes 83), so they are refused instead of being converted. Errors name keys but never values.
func ParsePlain(plain []byte) (*Payload, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil {
		return nil, errors.New("the decrypted document must be a mapping")
	}
	p := &Payload{Data: map[string][]byte{}}
	// Field names are matched exactly: encoding/json would also accept a misspelt "stringdata".
	var data, stringData map[string]any
	for name, value := range fields {
		var err error
		switch name {
		case "scope":
			err = json.Unmarshal(value, &p.Scope)
		case "data":
			err = json.Unmarshal(value, &data)
		case "stringData":
			err = json.Unmarshal(value, &stringData)
		default:
			return nil, fmt.Errorf("the decrypted document has the unknown field %q; only scope, data and stringData are allowed", name)
		}
		if err != nil {
			return nil, fmt.Errorf("%s in the decrypted document has the wrong type", name)
		}
	}
	if len(data) == 0 && len(stringData) == 0 {
		return nil, errors.New("the decrypted document must hold data or stringData")
	}
	for k, v := range data {
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
	for k, v := range stringData {
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
