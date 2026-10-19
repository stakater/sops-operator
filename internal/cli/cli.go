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

// Package cli implements the sopssecret command line: it encrypts plaintext SopsSecret files with
// the recipients of .sops.yaml, and re-encrypts them for new recipients.
package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
)

const usage = `usage:
  sopssecret encrypt [-i] [--config FILE] PATH...
      Encrypt stringData and data of SopsSecrets into encryptedData, for the age recipients of the
      .sops.yaml creation rule that matches each file. Without -i, prints the result of one file.
  sopssecret rotate --identity KEYFILE [--config FILE] PATH...
      Decrypt every value with the identities in KEYFILE and encrypt it again for the recipients
      .sops.yaml lists now. Files are changed in place.

A PATH that is a directory is searched for *.yaml and *.yml files; files that are not valid YAML,
such as Helm templates, are skipped with a warning. .sops.yaml is looked up from each file's
directory upwards, unless --config or $SOPS_CONFIG is set.
`

// errUsage marks command-line mistakes, reported with exit code 2.
var errUsage = errors.New("usage")

// secretKey is the format of a Secret data key.
var secretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)

// Run executes the command line args (without the program name) and returns the exit code: 0 on
// success, 1 when a file failed, 2 on a usage error.
func Run(args []string, stdout, stderr io.Writer) int {
	err := execute(args, stdout, stderr)
	switch {
	case errors.Is(err, errUsage):
		logf(stderr, "%v\n\n%s", err, usage)
		return 2
	case err != nil:
		logf(stderr, "%v\n", err)
		return 1
	}
	return 0
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: missing command", errUsage)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFlag := flags.String("config", "", "path of the .sops.yaml to use")
	r := &runner{stderr: stderr, configs: map[string]*config{}}
	switch args[0] {
	case "encrypt":
		inPlace := flags.Bool("i", false, "write the result to the file")
		if err := flags.Parse(args[1:]); err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
		r.configFlag = *configFlag
		paths := flags.Args()
		switch {
		case len(paths) == 0:
			return fmt.Errorf("%w: no files", errUsage)
		case !*inPlace && len(paths) != 1:
			return fmt.Errorf("%w: without -i, give exactly one file", errUsage)
		case !*inPlace:
			out, _, err := r.edit(paths[0], r.encrypt)
			if err != nil {
				return fmt.Errorf("%s: %w", paths[0], err)
			}
			_, err = stdout.Write(out)
			return err
		}
		return r.each(paths, r.encrypt, "encrypted")
	case "rotate":
		identity := flags.String("identity", "", "age identity file holding the current private key")
		if err := flags.Parse(args[1:]); err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
		r.configFlag = *configFlag
		if *identity == "" {
			return fmt.Errorf("%w: --identity is required", errUsage)
		}
		if flags.NArg() == 0 {
			return fmt.Errorf("%w: no files", errUsage)
		}
		raw, err := os.ReadFile(*identity)
		if err != nil {
			return err
		}
		if r.keys, err = crypto.ParseKeyFile(raw); err != nil {
			return fmt.Errorf("%s: %w", *identity, err)
		}
		return r.each(flags.Args(), r.rotate, "re-encrypted")
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
}

type runner struct {
	stderr     io.Writer
	configFlag string
	configs    map[string]*config
	keys       *crypto.KeySet
}

// editFunc changes one SopsSecret document of file and returns how many values it encrypted.
type editFunc func(file string, root *yaml.Node) (int, error)

// each applies edit to every file under paths in place. It goes on after a failed file and returns
// an error if any failed.
func (r *runner) each(paths []string, edit editFunc, verb string) error {
	failed := 0
	apply := func(file string, explicit bool) {
		out, n, err := r.edit(file, edit)
		var parseErr *parseError
		switch {
		case errors.As(err, &parseErr) && !explicit:
			logf(r.stderr, "%s: skipped: not valid YAML\n", file)
		case err != nil:
			logf(r.stderr, "%s: %v\n", file, err)
			failed++
		case n > 0:
			if err := writeFile(file, out); err != nil {
				logf(r.stderr, "%s: %v\n", file, err)
				failed++
				return
			}
			logf(r.stderr, "%s: %s %d values\n", file, verb, n)
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			apply(path, true)
			continue
		}
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != path && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
				if d.Name() != configName {
					apply(p, false)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d files failed", failed)
	}
	return nil
}

type parseError struct{ err error }

func (e *parseError) Error() string { return "not valid YAML: " + e.err.Error() }

// edit applies fn to every SopsSecret document of file and returns the new content and the number of
// values encrypted. Other documents are kept; the file is re-encoded only when a value changed.
func (r *runner) edit(file string, fn editFunc) ([]byte, int, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, 0, err
	}
	var docs []*yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, 0, &parseError{err}
		}
		docs = append(docs, &doc)
	}
	total := 0
	for _, doc := range docs {
		if len(doc.Content) == 0 || !isSopsSecret(doc.Content[0]) {
			continue
		}
		n, err := fn(file, doc.Content[0])
		if err != nil {
			return nil, 0, err
		}
		total += n
	}
	if total == 0 {
		return raw, 0, nil
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	for _, doc := range docs {
		if err := enc.Encode(doc); err != nil {
			return nil, 0, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), total, nil
}

func isSopsSecret(root *yaml.Node) bool {
	kind, apiVersion := get(root, "kind"), get(root, "apiVersion")
	return kind != nil && kind.Value == "SopsSecret" && apiVersion != nil &&
		strings.HasPrefix(apiVersion.Value, sopsv1alpha1.GroupVersion.Group+"/")
}

// recipients returns the recipients .sops.yaml lists for file.
func (r *runner) recipients(file string) ([]string, error) {
	path, err := findConfig(file, r.configFlag)
	if err != nil {
		return nil, err
	}
	c, ok := r.configs[path]
	if !ok {
		if c, err = loadConfig(path); err != nil {
			return nil, err
		}
		r.configs[path] = c
	}
	return c.recipients(file)
}

// plainValue is a value from stringData or data, in file order.
type plainValue struct {
	key   string
	value []byte
}

// encrypt moves the values of stringData and data into encryptedData, each encrypted with its scope
// line. Values already in encryptedData are kept unless the same key is given in plaintext.
func (r *runner) encrypt(file string, root *yaml.Node) (int, error) {
	namespace, name, spec, err := target(root)
	if err != nil {
		return 0, err
	}
	values, err := plaintext(spec)
	if err != nil || len(values) == 0 {
		return 0, err
	}
	recipients, err := r.recipients(file)
	if err != nil {
		return 0, err
	}
	encrypted := get(spec, "encryptedData")
	if encrypted == nil {
		// Put encryptedData where the plaintext was.
		encrypted = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		at := keyIndex(spec, "stringData")
		if at < 0 {
			at = keyIndex(spec, "data")
		}
		spec.Content = append(spec.Content[:at], append([]*yaml.Node{str("encryptedData"), encrypted}, spec.Content[at:]...)...)
	}
	for _, v := range values {
		enc, err := crypto.EncryptValue(document.Plaintext(document.ScopeFor(namespace, name, v.key), v.value), recipients)
		if err != nil {
			return 0, fmt.Errorf("%s/%s: %w", "spec.stringData", v.key, err)
		}
		set(encrypted, v.key, enc)
	}
	remove(spec, "stringData")
	remove(spec, "data")
	return len(values), nil
}

// rotate encrypts any plaintext values, then decrypts every value of encryptedData with the
// runner's identities, checks its scope line, and encrypts it again for the current recipients.
func (r *runner) rotate(file string, root *yaml.Node) (int, error) {
	if _, err := r.encrypt(file, root); err != nil {
		return 0, err
	}
	namespace, name, spec, err := target(root)
	if err != nil {
		return 0, err
	}
	encrypted := get(spec, "encryptedData")
	if encrypted == nil || encrypted.Kind != yaml.MappingNode {
		return 0, nil
	}
	recipients, err := r.recipients(file)
	if err != nil {
		return 0, err
	}
	for i := 0; i+1 < len(encrypted.Content); i += 2 {
		key, value := encrypted.Content[i].Value, encrypted.Content[i+1]
		scope := document.ScopeFor(namespace, name, key)
		plain, err := crypto.DecryptValue(value.Value, r.keys)
		if err != nil {
			return 0, fmt.Errorf("encryptedData.%s: %w", key, err)
		}
		v, err := document.Value(plain, scope)
		if err != nil {
			return 0, fmt.Errorf("encryptedData.%s: %w", key, err)
		}
		enc, err := crypto.EncryptValue(document.Plaintext(scope, v), recipients)
		if err != nil {
			return 0, fmt.Errorf("encryptedData.%s: %w", key, err)
		}
		*value = *str(enc)
	}
	return len(encrypted.Content) / 2, nil
}

// target returns the namespace and name of a SopsSecret document, which form its scope, and its spec.
func target(root *yaml.Node) (string, string, *yaml.Node, error) {
	meta := get(root, "metadata")
	name, namespace := get(meta, "name"), get(meta, "namespace")
	if name == nil || name.Value == "" {
		return "", "", nil, errors.New("metadata.name is required")
	}
	if namespace == nil || namespace.Value == "" {
		return "", "", nil, fmt.Errorf("SopsSecret %s: metadata.namespace is required: each value is encrypted for "+
			"<namespace>/<name>/<key>; write the namespace even if kustomize or Helm sets it", name.Value)
	}
	spec := get(root, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return "", "", nil, fmt.Errorf("SopsSecret %s: spec is missing", name.Value)
	}
	return namespace.Value, name.Value, spec, nil
}

// plaintext returns the values of stringData and data. Errors name keys, never values.
func plaintext(spec *yaml.Node) ([]plainValue, error) {
	var out []plainValue
	seen := map[string]bool{}
	for _, field := range []string{"stringData", "data"} {
		m := get(spec, field)
		if m == nil {
			continue
		}
		if m.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("spec.%s must be a mapping", field)
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			key, value := m.Content[i].Value, m.Content[i+1]
			switch {
			case !secretKey.MatchString(key):
				return nil, fmt.Errorf("spec.%s.%s is not a valid Secret key", field, key)
			case seen[key]:
				return nil, fmt.Errorf("key %s appears in both stringData and data", key)
			case value.Kind != yaml.ScalarNode || value.Tag == "!!null":
				return nil, fmt.Errorf("spec.%s.%s must be a string", field, key)
			}
			seen[key] = true
			b := []byte(value.Value)
			if field == "data" {
				var err error
				if b, err = base64.StdEncoding.DecodeString(value.Value); err != nil {
					return nil, fmt.Errorf("spec.data.%s is not valid base64", key)
				}
			}
			out = append(out, plainValue{key: key, value: b})
		}
	}
	return out, nil
}

func get(m *yaml.Node, key string) *yaml.Node {
	if i := keyIndex(m, key); i >= 0 {
		return m.Content[i+1]
	}
	return nil
}

func keyIndex(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func set(m *yaml.Node, key, value string) {
	if v := get(m, key); v != nil {
		*v = *str(value)
		return
	}
	m.Content = append(m.Content, str(key), str(value))
}

func remove(m *yaml.Node, key string) {
	if i := keyIndex(m, key); i >= 0 {
		m.Content = append(m.Content[:i], m.Content[i+2:]...)
	}
}

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

// writeFile replaces file with data, keeping its permissions.
func writeFile(file string, data []byte) error {
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, info.Mode().Perm())
}

// logf writes a message for the user; a failed write to stderr cannot be reported anywhere.
func logf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
