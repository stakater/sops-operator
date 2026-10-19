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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// configName is the file sops reads its creation rules from.
const configName = ".sops.yaml"

// config holds the creation rules of a .sops.yaml. Only path_regex and age are used; other fields,
// such as encrypted_regex, are ignored, so files written for sops keep working.
type config struct {
	path  string
	rules []rule
}

type rule struct {
	pathRegex  *regexp.Regexp // nil matches every file
	recipients []string
}

// findConfig returns the .sops.yaml for file: flag if set, else $SOPS_CONFIG, else the nearest
// .sops.yaml in the file's directory or a parent. Unlike sops, the search starts at the file, not
// at the working directory.
func findConfig(file, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv("SOPS_CONFIG"); env != "" {
		return env, nil
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, configName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if parent := filepath.Dir(dir); parent == dir {
			return "", fmt.Errorf("no %s in the directory of %s or a parent; pass --config", configName, file)
		}
	}
}

// loadConfig reads the creation rules of a .sops.yaml.
func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		CreationRules []struct {
			PathRegex string    `yaml:"path_regex"`
			Age       yaml.Node `yaml:"age"`
		} `yaml:"creation_rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c := &config{path: abs}
	for i, r := range doc.CreationRules {
		var out rule
		if r.PathRegex != "" {
			if out.pathRegex, err = regexp.Compile(r.PathRegex); err != nil {
				return nil, fmt.Errorf("%s: creation rule %d: path_regex: %w", path, i+1, err)
			}
		}
		// age is a list or a comma-separated string, as sops accepts.
		var list []string
		switch r.Age.Kind {
		case yaml.SequenceNode:
			if err := r.Age.Decode(&list); err != nil {
				return nil, fmt.Errorf("%s: creation rule %d: age: %w", path, i+1, err)
			}
		case yaml.ScalarNode:
			list = strings.Split(r.Age.Value, ",")
		}
		for _, recipient := range list {
			if recipient = strings.TrimSpace(recipient); recipient != "" {
				out.recipients = append(out.recipients, recipient)
			}
		}
		c.rules = append(c.rules, out)
	}
	return c, nil
}

// recipients returns the age recipients of the first creation rule whose path_regex matches file's
// path relative to the directory of the .sops.yaml.
func (c *config) recipients(file string) ([]string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(filepath.Dir(c.path), abs)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(rel)
	for i, r := range c.rules {
		if r.pathRegex != nil && !r.pathRegex.MatchString(rel) {
			continue
		}
		if len(r.recipients) == 0 {
			return nil, fmt.Errorf("%s: creation rule %d matches %s but has no age recipients", c.path, i+1, rel)
		}
		return r.recipients, nil
	}
	return nil, fmt.Errorf("%s: no creation rule matches %s", c.path, rel)
}
