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

// Package identity provides clients that act as a tenant's ServiceAccount, <tenant>-sops in the
// tenant namespace.
package identity

import (
	"context"
	"fmt"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// UserName returns the user name of the identity of the tenant named tenant in tenantNamespace.
func UserName(tenantNamespace, tenant string) string {
	return "system:serviceaccount:" + tenantNamespace + ":" + sopsv1alpha1.TenantServiceAccountName(tenant)
}

func groups(tenantNamespace string) []string {
	return []string{"system:serviceaccounts", "system:serviceaccounts:" + tenantNamespace, "system:authenticated"}
}

// Factory creates and caches one impersonating client per tenant.
type Factory struct {
	base    *rest.Config
	scheme  *runtime.Scheme
	mu      sync.Mutex
	clients map[string]client.Client
}

// NewFactory returns a Factory that impersonates tenant identities using base credentials.
func NewFactory(base *rest.Config, scheme *runtime.Scheme) *Factory {
	return &Factory{base: base, scheme: scheme, clients: map[string]client.Client{}}
}

// ClientFor returns an uncached client acting as the identity of the tenant named tenant in
// tenantNamespace.
func (f *Factory) ClientFor(tenantNamespace, tenant string) (client.Client, error) {
	user := UserName(tenantNamespace, tenant)
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[user]; ok {
		return c, nil
	}
	cfg := rest.CopyConfig(f.base)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		return nil, fmt.Errorf("client for %s: %w", user, err)
	}
	f.clients[user] = c
	return c, nil
}

// CanWriteSecrets reports whether the identity of the tenant named tenant in tenantNamespace may
// create Secrets in namespace. It is an early check; the API server enforces the same rule on
// every write.
func CanWriteSecrets(ctx context.Context, c client.Client, tenantNamespace, tenant, namespace string) (bool, error) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   UserName(tenantNamespace, tenant),
			Groups: groups(tenantNamespace),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "create",
				Resource:  "secrets",
			},
		},
	}
	if err := c.Create(ctx, sar); err != nil {
		return false, fmt.Errorf("subject access review: %w", err)
	}
	return sar.Status.Allowed, nil
}
