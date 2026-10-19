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

func TestValue(t *testing.T) {
	scope := document.ScopeFor("my-app-prod", "db-creds", "password")

	t.Run("shall name the namespace, name and key", func(t *testing.T) {
		if scope != "my-app-prod/db-creds/password" {
			t.Fatalf("scope = %q", scope)
		}
	})

	t.Run("shall return the bytes after the scope line", func(t *testing.T) {
		for name, value := range map[string]string{
			"text":       "hunter2",
			"multi-line": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			"binary":     "\x00\x01\n\x02",
			"empty":      "",
		} {
			t.Run(name, func(t *testing.T) {
				got, err := document.Value([]byte(scope+"\n"+value), scope)
				if err != nil {
					t.Fatalf("Value: %v", err)
				}
				if string(got) != value {
					t.Fatal("value does not match the plaintext")
				}
			})
		}
	})

	t.Run("shall accept a scope line ending in CRLF", func(t *testing.T) {
		got, err := document.Value([]byte(scope+"\r\nhunter2"), scope)
		if err != nil || string(got) != "hunter2" {
			t.Fatalf("got %q, %v; want hunter2", got, err)
		}
	})

	t.Run("shall reject a value scoped elsewhere without naming that scope", func(t *testing.T) {
		for name, other := range map[string]string{
			"namespace": "my-app-dev/db-creds/password",
			"name":      "my-app-prod/renamed/password",
			"key":       "my-app-prod/db-creds/username",
		} {
			t.Run(name, func(t *testing.T) {
				_, err := document.Value([]byte(other+"\nhunter2"), scope)
				if !errors.Is(err, document.ErrScopeMismatch) {
					t.Fatalf("got %v, want ErrScopeMismatch", err)
				}
				if strings.Contains(err.Error(), other) {
					t.Fatalf("error reveals the decrypted scope: %q", err)
				}
			})
		}
	})

	t.Run("shall ask for the scope line when it is missing", func(t *testing.T) {
		_, err := document.Value([]byte("hunter2"), scope)
		if err == nil || !strings.Contains(err.Error(), scope) || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("want an error naming the expected scope line without the value, got %v", err)
		}
	})
}
