// Package document converts between SopsSecret objects and the YAML documents SOPS works on.
package document

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Canonical renders the encrypted part of a SopsSecret (spec and sops) as the YAML document
// SOPS decrypts. Keys are sorted at every level, matching the Kubernetes API's JSON encoding
// and files prepared with `yq 'sort_keys(..)'`. Encrypted values keep their paths (spec:…),
// which SOPS uses as authenticated data.
func Canonical(s *sopsv1alpha1.SopsSecret) ([]byte, error) {
	spec, err := toMap(s.Spec)
	if err != nil {
		return nil, fmt.Errorf("render spec: %w", err)
	}
	meta, err := toMap(s.Sops)
	if err != nil {
		return nil, fmt.Errorf("render sops metadata: %w", err)
	}
	return yaml.Marshal(map[string]any{"spec": spec, "sops": meta})
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

// ParsePlain extracts the scope and values from a decrypted document. stringData scalars are
// converted to strings the way kubectl does. Errors name keys but never values.
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
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
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
		s, ok := scalar(v)
		if !ok {
			return nil, fmt.Errorf("stringData.%s must be a string, number or boolean", k)
		}
		if _, dup := p.Data[k]; dup {
			return nil, fmt.Errorf("key %s appears in both data and stringData", k)
		}
		p.Data[k] = []byte(s)
	}
	return p, nil
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}
