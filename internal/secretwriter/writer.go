// Package secretwriter writes Secrets without reading them (DESIGN.md D28).
package secretwriter

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrConflict reports a Secret with the desired name that this writer did not create.
var ErrConflict = errors.New("a Secret with this name exists and is not managed by this SopsSecret")

// Write creates or replaces desired. knownUID is the UID returned by the previous successful
// Write for this Secret, or "" if there was none. An update carries knownUID as a precondition,
// so the API server rejects it (409) when the Secret is gone or was replaced by someone else; it
// cannot tell the two apart without a read. Write then creates the Secret: that succeeds when it
// was deleted and fails with AlreadyExists (ErrConflict) when someone else's Secret holds the
// name, so a foreign Secret is never overwritten. It returns the UID of the written Secret.
func Write(ctx context.Context, c client.Client, desired *corev1.Secret, knownUID types.UID) (types.UID, error) {
	if knownUID != "" {
		obj := desired.DeepCopy()
		obj.UID = knownUID
		obj.ResourceVersion = ""
		err := c.Update(ctx, obj)
		switch {
		case err == nil:
			return obj.UID, nil
		case !apierrors.IsConflict(err) && !apierrors.IsNotFound(err):
			return "", err
		}
	}
	obj := desired.DeepCopy()
	obj.UID = ""
	obj.ResourceVersion = ""
	if err := c.Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return "", ErrConflict
		}
		return "", err
	}
	return obj.UID, nil
}
