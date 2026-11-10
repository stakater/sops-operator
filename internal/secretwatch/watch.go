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

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// syncTimeout bounds the initial list of a new watch.
const syncTimeout = 30 * time.Second

// Watches runs one metadata-only watch of enabled Secrets per tenant and namespace, as the tenant
// identity, while an owner holds it. A deleted or changed Secret is reported on the events channel as
// the object ownerOf returns for it, which restores it; Secrets without one are ignored.
type Watches struct {
	configFor func(tenantNamespace, tenant string) *rest.Config
	ownerOf   func(m *metav1.PartialObjectMetadata) client.Object
	events    chan event.GenericEvent
	ctx       context.Context
	cancel    context.CancelFunc

	mu      sync.Mutex
	watches map[key]*watch
	owners  map[types.NamespacedName]key
}

type key struct {
	tenant    types.NamespacedName
	namespace string
}

type watch struct {
	cancel context.CancelFunc
	owners int
}

// New returns Watches of output Secrets that act as the identity configFor returns. Owners are
// SopsSecrets; a changed output Secret is reported as the SopsSecret named in its annotation, which
// writes its values, labels and annotations again.
func New(configFor func(tenantNamespace, tenant string) *rest.Config) *Watches {
	return newWatches(configFor, sopsSecretOf)
}

// NewForKeys returns Watches of tenant key Secrets that act as the identity configFor returns. Owners
// are SopsTenants, watching their own namespace; a changed key Secret <tenant>-sops-keys is reported
// as the SopsTenant <tenant>, which restores it from its backup. Key backups and output Secrets are
// ignored.
func NewForKeys(configFor func(tenantNamespace, tenant string) *rest.Config) *Watches {
	return newWatches(configFor, sopsTenantOf)
}

func newWatches(configFor func(tenantNamespace, tenant string) *rest.Config,
	ownerOf func(m *metav1.PartialObjectMetadata) client.Object) *Watches {
	ctx, cancel := context.WithCancel(context.Background())
	return &Watches{
		configFor: configFor, ownerOf: ownerOf, events: make(chan event.GenericEvent, 100), ctx: ctx, cancel: cancel,
		watches: map[key]*watch{}, owners: map[types.NamespacedName]key{},
	}
}

// sopsSecretOf returns the SopsSecret an output Secret was written from, or nil for any other Secret.
func sopsSecretOf(m *metav1.PartialObjectMetadata) client.Object {
	name := m.Annotations[sopsv1alpha1.AnnotationSopsSecret]
	if name == "" {
		return nil
	}
	return &sopsv1alpha1.SopsSecret{ObjectMeta: metav1.ObjectMeta{Namespace: m.Namespace, Name: name}}
}

// sopsTenantOf returns the SopsTenant whose key Secret m is, or nil for a key backup, an output Secret
// or any other Secret.
func sopsTenantOf(m *metav1.PartialObjectMetadata) client.Object {
	if _, output := m.Annotations[sopsv1alpha1.AnnotationSopsSecret]; output ||
		m.Labels[sopsv1alpha1.LabelKeyBackup] == "true" {
		return nil
	}
	tenant, ok := strings.CutSuffix(m.Name, sopsv1alpha1.KeySecretSuffix)
	if !ok || tenant == "" {
		return nil
	}
	return &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Namespace: m.Namespace, Name: tenant}}
}

// Events returns the channel on which the owners of changed Secrets are reported.
func (w *Watches) Events() <-chan event.GenericEvent { return w.events }

// Start implements manager.Runnable: it stops every watch when ctx is done.
func (w *Watches) Start(ctx context.Context) error {
	<-ctx.Done()
	w.cancel()
	return nil
}

// Holds reports whether owner holds a watch.
func (w *Watches) Holds(owner types.NamespacedName) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.owners[owner]
	return ok
}

// Watch makes owner hold the watch of tenant's Secrets in owner's namespace, starting it if needed,
// and releases any watch owner held before.
func (w *Watches) Watch(ctx context.Context, owner, tenant types.NamespacedName) error {
	k := key{tenant: tenant, namespace: owner.Namespace}
	w.mu.Lock()
	defer w.mu.Unlock()
	if held, ok := w.owners[owner]; ok && held == k {
		return nil
	}
	w.releaseLocked(owner)
	if running, ok := w.watches[k]; ok {
		running.owners++
		w.owners[owner] = k
		return nil
	}
	cancel, err := w.start(ctx, k)
	if err != nil {
		return err
	}
	w.watches[k] = &watch{cancel: cancel, owners: 1}
	w.owners[owner] = k
	return nil
}

// Release drops owner's hold; the watch stops when no owner holds it.
func (w *Watches) Release(owner types.NamespacedName) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.releaseLocked(owner)
}

func (w *Watches) releaseLocked(owner types.NamespacedName) {
	k, ok := w.owners[owner]
	if !ok {
		return
	}
	delete(w.owners, owner)
	if running := w.watches[k]; running != nil {
		if running.owners--; running.owners == 0 {
			running.cancel()
			delete(w.watches, k)
		}
	}
}

// start runs the watch for k and waits for its initial list.
func (w *Watches) start(ctx context.Context, k key) (context.CancelFunc, error) {
	mc, err := metadata.NewForConfig(w.configFor(k.tenant.Namespace, k.tenant.Name))
	if err != nil {
		return nil, err
	}
	selector := labels.Set{sopsv1alpha1.LabelEnabled: sopsv1alpha1.EnabledValue}.String()
	informer := metadatainformer.NewFilteredMetadataInformer(mc, corev1.SchemeGroupVersion.WithResource("secrets"),
		k.namespace, 0, cache.Indexers{}, func(o *metav1.ListOptions) { o.LabelSelector = selector }).Informer()
	wctx, cancel := context.WithCancel(w.ctx)
	report := func(obj any) {
		if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			obj = d.Obj
		}
		m, ok := obj.(*metav1.PartialObjectMetadata)
		if !ok {
			return
		}
		owner := w.ownerOf(m)
		if owner == nil {
			return
		}
		select {
		case w.events <- event.GenericEvent{Object: owner}:
		case <-wctx.Done():
		}
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, cur any) {
			o, okOld := old.(*metav1.PartialObjectMetadata)
			c, okCur := cur.(*metav1.PartialObjectMetadata)
			if okOld && okCur && o.ResourceVersion != c.ResourceVersion {
				report(cur)
			}
		},
		DeleteFunc: report,
	}); err != nil {
		cancel()
		return nil, err
	}
	go informer.RunWithContext(wctx)
	syncCtx, done := context.WithTimeout(ctx, syncTimeout)
	defer done()
	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		cancel()
		return nil, fmt.Errorf("watch Secrets of tenant %s in namespace %s: not synced within %s",
			k.tenant, k.namespace, syncTimeout)
	}
	return cancel, nil
}
