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

// Package document converts between SopsSecret objects and the YAML documents SOPS works on.
package document

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Canonical renders the encrypted part of a SopsSecret (spec and sops) as the JSON document
// SOPS decrypts. JSON encoding sorts keys byte-wise at every level, matching the Kubernetes
// API and files prepared with `yq 'sort_keys(..)'`; the SOPS MAC depends on that order.
// Encrypted values keep their paths (spec:…), which SOPS uses as authenticated data.
func Canonical(s *sopsv1alpha1.SopsSecret) ([]byte, error) {
	spec, err := toMap(s.Spec)
	if err != nil {
		return nil, fmt.Errorf("render spec: %w", err)
	}
	meta, err := toMap(s.Sops)
	if err != nil {
		return nil, fmt.Errorf("render sops metadata: %w", err)
	}
	return json.Marshal(map[string]any{"spec": spec, "sops": meta})
}

func toMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Payload is the decrypted content of a SopsSecret.
type Payload struct {
	Scope string
	Data  map[string][]byte
}

// ScopeFor returns the scope value a SopsSecret named name in namespace must carry.
func ScopeFor(namespace, name string) string { return namespace + "/" + name }

// ParsePlain extracts the scope and values from a decrypted document. stringData values must be
// quoted strings: SOPS parses unquoted scalars before encrypting (0123 becomes 83), so they are
// refused instead of being converted. Errors name keys but never values.
func ParsePlain(plain []byte) (*Payload, error) {
	raw, err := yaml.YAMLToJSON(plain)
	if err != nil {
		return nil, fmt.Errorf("decrypted document is not valid YAML")
	}
	var doc struct {
		Spec struct {
			Scope      string         `json:"scope"`
			Data       map[string]any `json:"data"`
			StringData map[string]any `json:"stringData"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decrypted document does not match the SopsSecret schema")
	}
	p := &Payload{Scope: doc.Spec.Scope, Data: map[string][]byte{}}
	for k, v := range doc.Spec.Data {
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
	for k, v := range doc.Spec.StringData {
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
