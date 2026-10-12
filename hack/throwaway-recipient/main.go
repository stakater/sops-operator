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
// Command throwaway-recipient prints the public key of a fresh post-quantum age key and discards
// the private key, so nothing encrypted for it can ever be decrypted. hack/generate-samples.sh
// uses it to encrypt the SopsSecret sample.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/stakater/sops-operator/internal/crypto"
)

func main() {
	_, recipient, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(recipient)
}
