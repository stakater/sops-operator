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

// Package secretwriter writes Secrets without reading their data (DESIGN.md D28).
package secretwriter

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrConflict reports a Secret with the desired name that the writer does not own.
var ErrConflict = errors.New("a Secret with this name exists and is not managed by this SopsSecret")

// Write creates desired, or updates the Secret with its name and namespace when owns reports that
// the Secret is the writer's. Any other Secret is never changed: Write returns ErrConflict. It reads
// only the existing Secret's metadata, with a list by name, and updates it only at the version it
// read, so a Secret replaced in between is not overwritten.
// existing returns the metadata of the Secret name in namespace, or nil when there is none. It lists by
// name, so it reads no Secret data.
func existing(ctx context.Context, c client.Client, namespace, name string) (*metav1.PartialObjectMetadata, error) {
	var list metav1.PartialObjectMetadataList
	list.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("SecretList"))
	if err := c.List(ctx, &list, client.InNamespace(namespace),
		client.MatchingFieldsSelector{Selector: fields.OneTermEqualSelector("metadata.name", name)}); err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, nil
	}
	return &list.Items[0], nil
}

func Write(ctx context.Context, c client.Client, desired *corev1.Secret,
	owns func(*metav1.PartialObjectMetadata) bool) error {
	current, err := existing(ctx, c, desired.Namespace, desired.Name)
	if err != nil {
		return err
	}
	obj := desired.DeepCopy()
	if current == nil {
		obj.UID, obj.ResourceVersion = "", ""
		return c.Create(ctx, obj)
	}
	if !owns(current) {
		return ErrConflict
	}
	obj.UID, obj.ResourceVersion = current.UID, current.ResourceVersion
	return c.Update(ctx, obj)
}

// Delete deletes the Secret name in namespace when owns reports that it is the writer's, at the
// version it read; any other Secret is left alone. A missing Secret is no error.
func Delete(ctx context.Context, c client.Client, namespace, name string,
	owns func(*metav1.PartialObjectMetadata) bool) error {
	current, err := existing(ctx, c, namespace, name)
	if err != nil || current == nil || !owns(current) {
		return err
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	return client.IgnoreNotFound(c.Delete(ctx, secret, client.Preconditions{
		UID: &current.UID, ResourceVersion: &current.ResourceVersion,
	}))
}
