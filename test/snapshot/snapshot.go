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

// Package snapshot renders Kubernetes objects as stable YAML for golden-file tests. Values that
// change on every run are replaced by placeholders (timestamps are validated first), secret values
// and ciphertext are redacted, and objects containing age private keys are refused.
package snapshot

import (
	"bytes"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/yaml"
)

// Placeholders written in place of volatile or secret values.
const (
	UID             = "<uid>"
	ResourceVersion = "<resourceVersion>"
	Timestamp       = "<timestamp>"
	Redacted        = "<redacted>"
	Encrypted       = "<encrypted>"
)

// YAML returns obj as normalized YAML with keys sorted. UIDs found in known (UID → label such as
// "secret/db-creds") are written as <uid:label>, so a golden file shows which object a reference
// points to; other UIDs become <uid>.
func YAML(obj runtime.Object, scheme *runtime.Scheme, known map[string]string) ([]byte, error) {
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		return nil, err
	}
	obj = obj.DeepCopyObject()
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	if err := normalize(u, known); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(u)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(out, []byte("AGE-SECRET-KEY")) {
		return nil, fmt.Errorf("refusing to snapshot an object that contains an age private key")
	}
	return out, nil
}

func normalize(u map[string]any, known map[string]string) error {
	uid := func(m map[string]any, key string) {
		v, ok := m[key].(string)
		if !ok {
			return
		}
		if label, found := known[v]; found {
			m[key] = "<uid:" + label + ">"
			return
		}
		m[key] = UID
	}
	metadata, _ := u["metadata"].(map[string]any)
	if metadata != nil {
		delete(metadata, "managedFields")
		uid(metadata, "uid")
		setIfPresent(metadata, "resourceVersion", ResourceVersion)
		if err := timestamp(metadata, "creationTimestamp", "metadata.creationTimestamp", true); err != nil {
			return err
		}
		refs, _ := metadata["ownerReferences"].([]any)
		for _, r := range refs {
			if ref, ok := r.(map[string]any); ok {
				uid(ref, "uid")
			}
		}
	}

	// Secret values: keep the keys, never the values.
	redact(u, "data")
	redact(u, "stringData")
	if spec, ok := u["spec"].(map[string]any); ok {
		setIfPresent(spec, "encrypted", Encrypted)
	}

	if status, ok := u["status"].(map[string]any); ok {
		uid(status, "secretUID")
		if err := timestamp(status, "lastSyncTime", "status.lastSyncTime", false); err != nil {
			return err
		}
		conditions, _ := status["conditions"].([]any)
		for i, c := range conditions {
			if cond, ok := c.(map[string]any); ok {
				path := fmt.Sprintf("status.conditions[%d].lastTransitionTime", i)
				if err := timestamp(cond, "lastTransitionTime", path, true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func setIfPresent(m map[string]any, key, value string) {
	if v, ok := m[key]; ok && v != nil {
		m[key] = value
	}
}

func redact(m map[string]any, key string) {
	values, ok := m[key].(map[string]any)
	if !ok {
		return
	}
	for k := range values {
		values[k] = Redacted
	}
}

// timestamp replaces an RFC 3339 timestamp with a placeholder after checking it is valid.
func timestamp(m map[string]any, key, path string, required bool) error {
	v, ok := m[key]
	if !ok || v == nil {
		if required {
			return fmt.Errorf("%s is missing", path)
		}
		return nil
	}
	s, isString := v.(string)
	if !isString {
		return fmt.Errorf("%s is not a string", path)
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return fmt.Errorf("%s is not an RFC 3339 timestamp: %q", path, s)
	}
	m[key] = Timestamp
	return nil
}
