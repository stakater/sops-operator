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

package controller

import (
	"context"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// SyncForTest runs the checks and the write of one reconcile and returns the Ready reason.
func (r *SopsSecretReconciler) SyncForTest(ctx context.Context, s *sopsv1alpha1.SopsSecret) (string, error) {
	o, err := r.sync(ctx, s)
	return o.reason, err
}
