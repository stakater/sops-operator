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

// Package secretwatch watches output Secrets as the tenant identity, so a deleted or changed one is
// restored at once instead of at the next resync (DESIGN.md D28).
package secretwatch

import (
	"context"
	"fmt"
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
	"sigs.k8s.io/controller-runtime/pkg/event"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// syncTimeout bounds the initial list of a new watch.
const syncTimeout = 30 * time.Second

// Watches runs one metadata-only watch of output Secrets per tenant and namespace, as the tenant
// identity, while a SopsSecret of the tenant in that namespace holds it. A deleted or changed output
// Secret is reported on the events channel as the SopsSecret named in its annotation, which writes its
// values, labels and annotations again.
type Watches struct {
	configFor func(tenantNamespace, tenant string) *rest.Config
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

// New returns Watches that act as the identity configFor returns.
func New(configFor func(tenantNamespace, tenant string) *rest.Config) *Watches {
	ctx, cancel := context.WithCancel(context.Background())
	return &Watches{
		configFor: configFor, events: make(chan event.GenericEvent, 100), ctx: ctx, cancel: cancel,
		watches: map[key]*watch{}, owners: map[types.NamespacedName]key{},
	}
}

// Events returns the channel on which SopsSecrets whose output Secret changed are reported.
func (w *Watches) Events() <-chan event.GenericEvent { return w.events }

// Start implements manager.Runnable: it stops every watch when ctx is done.
func (w *Watches) Start(ctx context.Context) error {
	<-ctx.Done()
	w.Stop()
	return nil
}

// Stop stops every watch.
func (w *Watches) Stop() { w.cancel() }

// Watching returns the number of running watches.
func (w *Watches) Watching() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watches)
}

// Watch makes the SopsSecret owner hold the watch of tenant's output Secrets in owner's namespace,
// starting it if needed, and releases any watch owner held before.
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

// Release drops owner's hold; the watch stops when no SopsSecret holds it.
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
	selector := labels.Set{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue}.String()
	informer := metadatainformer.NewFilteredMetadataInformer(mc, corev1.SchemeGroupVersion.WithResource("secrets"),
		k.namespace, 0, cache.Indexers{}, func(o *metav1.ListOptions) { o.LabelSelector = selector }).Informer()
	wctx, cancel := context.WithCancel(w.ctx)
	report := func(obj any) {
		if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			obj = d.Obj
		}
		m, ok := obj.(*metav1.PartialObjectMetadata)
		if !ok || m.Annotations[sopsv1alpha1.AnnotationSopsSecret] == "" {
			return
		}
		owner := &sopsv1alpha1.SopsSecret{ObjectMeta: metav1.ObjectMeta{
			Namespace: m.Namespace, Name: m.Annotations[sopsv1alpha1.AnnotationSopsSecret]}}
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
		return nil, fmt.Errorf("watch output Secrets of tenant %s in namespace %s: not synced within %s",
			k.tenant, k.namespace, syncTimeout)
	}
	return cancel, nil
}

