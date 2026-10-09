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

	"k8s.io/apimachinery/pkg/types"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// RecordDecryptedForTest records a successful write, as Reconcile does after Write succeeds.
func (r *SopsSecretReconciler) RecordDecryptedForTest(ctx context.Context, s *sopsv1alpha1.SopsSecret, uid types.UID) error {
	return r.updateStatus(ctx, s, outcome{reason: sopsv1alpha1.ReasonDecrypted, message: "Secret is up to date", uid: uid})
}
