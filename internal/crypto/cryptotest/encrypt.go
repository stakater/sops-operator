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

// Package cryptotest encrypts values the way the documented `age -R <recipients> | base64` command
// does. It is used by tests only.
package cryptotest

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
)

// Encrypt encrypts plain for the given age recipients and returns the binary age file in base64.
func Encrypt(plain []byte, recipients ...string) (string, error) {
	rs, err := age.ParseRecipients(strings.NewReader(strings.Join(recipients, "\n")))
	if err != nil {
		return "", fmt.Errorf("parse recipients: %w", err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rs...)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}
