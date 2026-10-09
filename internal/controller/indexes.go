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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// IndexTenantRef indexes SopsSecrets by the tenant they reference.
const IndexTenantRef = "spec.tenantRef"

// TenantRefKey is the IndexTenantRef value of a tenant.
func TenantRefKey(namespace, name string) string { return namespace + "/" + name }

// SetupIndexes registers the field indexes the controllers use.
func SetupIndexes(ctx context.Context, mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(ctx, &sopsv1alpha1.SopsSecret{}, IndexTenantRef,
		func(o client.Object) []string {
			s := o.(*sopsv1alpha1.SopsSecret)
			return []string{TenantRefKey(s.Spec.TenantRef.Namespace, s.Spec.TenantRef.Name)}
		})
}
