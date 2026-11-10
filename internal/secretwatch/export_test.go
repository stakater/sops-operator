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

// Package secretwatch watches the operator's Secrets as the tenant identity, so a deleted or changed one
// is restored at once instead of at the next resync: output Secrets, reported as their SopsSecret, and
// tenant key Secrets, reported as their SopsTenant.
package secretwatch

// Watching returns the number of running watches.
func (w *Watches) Watching() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watches)
}

// Stop stops every watch.
func (w *Watches) Stop() { w.cancel() }
