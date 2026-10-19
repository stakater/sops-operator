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

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigLookup(t *testing.T) {
	t.Run("shall use the nearest .sops.yaml above the file, not the working directory", func(t *testing.T) {
		repo := t.TempDir()
		write(t, filepath.Join(repo, ".sops.yaml"), "creation_rules:\n  - age: age1root\n")
		stage := write(t, filepath.Join(repo, "envs", "stage", ".sops.yaml"), "creation_rules:\n  - age: age1stage\n")
		file := write(t, filepath.Join(repo, "envs", "stage", "app", "s.yaml"), "")
		t.Chdir(repo)

		got, err := findConfig(file, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != stage {
			t.Fatalf("found %s, want %s", got, stage)
		}
	})

	t.Run("shall prefer --config, then SOPS_CONFIG", func(t *testing.T) {
		dir := t.TempDir()
		file := write(t, filepath.Join(dir, "s.yaml"), "")
		write(t, filepath.Join(dir, ".sops.yaml"), "")
		flag := write(t, filepath.Join(dir, "flag.yaml"), "")
		env := write(t, filepath.Join(dir, "env.yaml"), "")
		t.Setenv("SOPS_CONFIG", env)

		if got, _ := findConfig(file, flag); got != flag {
			t.Fatalf("with --config found %s", got)
		}
		if got, _ := findConfig(file, ""); got != env {
			t.Fatalf("with SOPS_CONFIG found %s", got)
		}
	})

	t.Run("shall report a missing .sops.yaml", func(t *testing.T) {
		t.Setenv("SOPS_CONFIG", "")
		file := write(t, filepath.Join(t.TempDir(), "s.yaml"), "")
		if _, err := findConfig(file, ""); err == nil || !strings.Contains(err.Error(), ".sops.yaml") {
			t.Fatalf("want an error naming .sops.yaml, got %v", err)
		}
	})
}

func TestCreationRules(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadConfig(write(t, filepath.Join(dir, ".sops.yaml"), `creation_rules:
  - path_regex: ^prod/
    age:
      - age1prod
      - age1breakglass
  - path_regex: \.sops\.ya?ml$
    age: age1dev, age1breakglass
  - age: age1default
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file string
		want       []string
	}{
		{"shall match path_regex against the path relative to .sops.yaml, with an age list", "prod/db.yaml", []string{"age1prod", "age1breakglass"}},
		{"shall take the first matching rule, with comma-separated age", "prod-like/db.sops.yaml", []string{"age1dev", "age1breakglass"}},
		{"shall match a rule without path_regex", "other/db.yaml", []string{"age1default"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cfg.recipients(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("recipients = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("shall report when no rule matches", func(t *testing.T) {
		cfg, err := loadConfig(write(t, filepath.Join(t.TempDir(), ".sops.yaml"), "creation_rules:\n  - path_regex: ^prod/\n    age: age1prod\n"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.recipients(filepath.Join(filepath.Dir(cfg.path), "dev", "db.yaml"))
		if err == nil || !strings.Contains(err.Error(), "dev/db.yaml") {
			t.Fatalf("want an error naming the file, got %v", err)
		}
	})

	t.Run("shall reject a rule without age recipients", func(t *testing.T) {
		cfg, err := loadConfig(write(t, filepath.Join(t.TempDir(), ".sops.yaml"), "creation_rules:\n  - path_regex: .*\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.recipients(filepath.Join(filepath.Dir(cfg.path), "db.yaml")); err == nil || !strings.Contains(err.Error(), "age") {
			t.Fatalf("want an error about missing age recipients, got %v", err)
		}
	})

	t.Run("shall reject an invalid path_regex", func(t *testing.T) {
		if _, err := loadConfig(write(t, filepath.Join(t.TempDir(), ".sops.yaml"), "creation_rules:\n  - path_regex: '('\n    age: a\n")); err == nil {
			t.Fatal("want an error for an invalid path_regex")
		}
	})
}
