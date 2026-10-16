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

package document_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stakater/sops-operator/internal/document"
)

const scope = "my-app-prod/db-creds"

func TestPayload(t *testing.T) {
	t.Run("shall read the scope, data and stringData", func(t *testing.T) {
		p, err := document.Parse([]byte(`scope: my-app-prod/db-creds
data:
  cert: AAEC # bytes 0x00 0x01 0x02
stringData:
  password: "hunter2"
`), scope)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if p.Scope != scope {
			t.Fatalf("scope = %q", p.Scope)
		}
		if string(p.Data["password"]) != "hunter2" || string(p.Data["cert"]) != "\x00\x01\x02" {
			t.Fatal("payload values do not match the plaintext")
		}
	})

	t.Run("shall check the scope before other values", func(t *testing.T) {
		// A copied file with an invalid value is rejected by scope, without naming the decrypted scope.
		_, err := document.Parse([]byte("scope: my-app-prod/db-creds\nstringData:\n  port: 5432\n"), "my-app-dev/db-creds")
		if !errors.Is(err, document.ErrScopeMismatch) {
			t.Fatalf("got %v, want ErrScopeMismatch", err)
		}
		if strings.Contains(err.Error(), "my-app-prod") {
			t.Fatalf("error reveals the decrypted scope: %q", err)
		}
	})

	t.Run("shall reject unquoted scalars", func(t *testing.T) {
		// YAML parses unquoted scalars (0123 becomes 83): refuse them instead of converting.
		for name, value := range map[string]string{"port": "5432", "pin": "0123", "enabled": "true"} {
			t.Run(name, func(t *testing.T) {
				_, err := document.Parse([]byte("scope: "+scope+"\nstringData:\n  "+name+": "+value+"\n"), scope)
				if err == nil || !strings.Contains(err.Error(), "stringData."+name) || !strings.Contains(err.Error(), "quoted") {
					t.Fatalf("want an error asking to quote stringData.%s, got %v", name, err)
				}
			})
		}
	})

	t.Run("shall name the key of invalid base64 without its value", func(t *testing.T) {
		const secretValue = "not-base64!"
		_, err := document.Parse([]byte("scope: "+scope+"\ndata:\n  token: "+secretValue+"\n"), scope)
		if err == nil || !strings.Contains(err.Error(), "data.token") || strings.Contains(err.Error(), secretValue) {
			t.Fatalf("want an error naming data.token without its value, got %v", err)
		}
	})

	t.Run("shall reject nested values", func(t *testing.T) {
		_, err := document.Parse([]byte("scope: "+scope+"\nstringData:\n  nested:\n    x: y\n"), scope)
		if err == nil || !strings.Contains(err.Error(), "nested") {
			t.Fatalf("want an error naming the nested key, got %v", err)
		}
	})

	t.Run("shall reject a key in both data and stringData", func(t *testing.T) {
		_, err := document.Parse([]byte("scope: "+scope+"\ndata:\n  k: AAEC\nstringData:\n  k: v\n"), scope)
		if err == nil || !strings.Contains(err.Error(), "both") {
			t.Fatalf("want an error naming the duplicate key, got %v", err)
		}
	})

	t.Run("shall reject unknown fields", func(t *testing.T) {
		// A misspelt field would otherwise deliver an empty Secret.
		_, err := document.Parse([]byte("scope: "+scope+"\nstringdata:\n  k: v\n"), scope)
		if err == nil || !strings.Contains(err.Error(), "stringdata") {
			t.Fatalf("want an error naming the unknown field, got %v", err)
		}
	})

	t.Run("shall require data or stringData", func(t *testing.T) {
		_, err := document.Parse([]byte("scope: "+scope+"\n"), scope)
		if err == nil || !strings.Contains(err.Error(), "data or stringData") {
			t.Fatalf("want an error asking for data or stringData, got %v", err)
		}
	})
}
