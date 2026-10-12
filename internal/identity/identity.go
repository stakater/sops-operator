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

// Package identity provides clients that act as a tenant's "sops" ServiceAccount.
package identity

import (
	"context"
	"fmt"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceAccountName is the name of every tenant identity's ServiceAccount.
const ServiceAccountName = "sops"

// UserName returns the user name of the tenant identity of tenantNamespace.
func UserName(tenantNamespace string) string {
	return "system:serviceaccount:" + tenantNamespace + ":" + ServiceAccountName
}

func groups(tenantNamespace string) []string {
	return []string{"system:serviceaccounts", "system:serviceaccounts:" + tenantNamespace, "system:authenticated"}
}

// Factory creates and caches one impersonating client per tenant namespace.
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

// ClientFor returns an uncached client acting as the tenant identity of tenantNamespace.
func (f *Factory) ClientFor(tenantNamespace string) (client.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[tenantNamespace]; ok {
		return c, nil
	}
	cfg := rest.CopyConfig(f.base)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: UserName(tenantNamespace)}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		return nil, fmt.Errorf("client for tenant identity in %s: %w", tenantNamespace, err)
	}
	f.clients[tenantNamespace] = c
	return c, nil
}

// CanWriteSecrets reports whether the tenant identity of tenantNamespace may create Secrets in
// namespace. It is an early check; the API server enforces the same rule on every write.
func CanWriteSecrets(ctx context.Context, c client.Client, tenantNamespace, namespace string) (bool, error) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   UserName(tenantNamespace),
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
