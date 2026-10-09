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

// Package crypto handles tenant age keys and SOPS decryption.
package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/age"
)

// KeyFileField is the field of a tenant key Secret that holds the age identities.
const KeyFileField = "age.agekey"

// ErrKeyInvalid reports a key file that is empty or contains an unsupported or corrupt identity.
var ErrKeyInvalid = errors.New("invalid key file")

// KeySet holds the identities of a tenant key file and their recipients, in file order.
// The first identity is the primary one.
type KeySet struct {
	Identities []age.Identity
	Recipients []string
}

// ParseKeyFile parses an age identity file. Only X25519 and post-quantum hybrid identities
// are accepted. Errors never contain key material.
func ParseKeyFile(data []byte) (*KeySet, error) {
	ks := &KeySet{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			id, err := age.ParseHybridIdentity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d is not a valid post-quantum age identity", ErrKeyInvalid, n)
			}
			ks.Identities = append(ks.Identities, id)
			ks.Recipients = append(ks.Recipients, id.Recipient().String())
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d is not a valid X25519 age identity", ErrKeyInvalid, n)
			}
			ks.Identities = append(ks.Identities, id)
			ks.Recipients = append(ks.Recipients, id.Recipient().String())
		default:
			return nil, fmt.Errorf("%w: line %d is not an X25519 or post-quantum age identity", ErrKeyInvalid, n)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	if len(ks.Identities) == 0 {
		return nil, fmt.Errorf("%w: no identities", ErrKeyInvalid)
	}
	return ks, nil
}

// GenerateKeyFile generates a post-quantum hybrid age identity and renders it in the
// age-keygen file format.
func GenerateKeyFile(now time.Time) (keyFile []byte, recipient string, err error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, "", fmt.Errorf("generate age identity: %w", err)
	}
	recipient = id.Recipient().String()
	var b bytes.Buffer
	fmt.Fprintf(&b, "# created: %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# public key: %s\n", recipient)
	fmt.Fprintf(&b, "%s\n", id.String())
	return b.Bytes(), recipient, nil
}
