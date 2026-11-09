package admission_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	sopsadmission "github.com/stakater/sops-operator/internal/admission"
	"github.com/stakater/sops-operator/internal/controller"
	"github.com/stakater/sops-operator/internal/identity"
)

const (
	tenantNS = "team-a-system"
	user     = "jane@example.com"
)

func validator(t *testing.T) *sopsadmission.SecretValidator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	linked := &sopsv1alpha1.SopsSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
		Spec:       sopsv1alpha1.SopsSecretSpec{TenantRef: sopsv1alpha1.TenantReference{Name: "team-a", Namespace: tenantNS}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(linked).
		WithIndex(&sopsv1alpha1.SopsSecret{}, controller.IndexTenantRef, func(o client.Object) []string {
			ref := o.(*sopsv1alpha1.SopsSecret).Spec.TenantRef
			return []string{controller.TenantRefKey(ref.Namespace, ref.Name)}
		}).Build()
	return &sopsadmission.SecretValidator{Client: c, Decoder: admission.NewDecoder(scheme)}
}

func tenantSecret(namespace, name, tenant string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{
			sopsv1alpha1.LabelTenant: tenant, sopsv1alpha1.LabelTenantNamespace: tenantNS,
		}},
		Data: map[string][]byte{"value": []byte("v1")},
	}
}

func outputSecret() *corev1.Secret {
	s := tenantSecret("prod", "db", "team-a")
	s.Labels[sopsv1alpha1.LabelManagedBy] = sopsv1alpha1.ManagedByValue
	s.Annotations = map[string]string{sopsv1alpha1.AnnotationSopsSecret: "db"}
	return s
}

func request(t *testing.T, op admissionv1.Operation, username string, old, cur *corev1.Secret) admission.Request {
	t.Helper()
	raw := func(s *corev1.Secret) runtime.RawExtension {
		if s == nil {
			return runtime.RawExtension{}
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return runtime.RawExtension{Raw: b}
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, Namespace: old.Namespace, Name: old.Name,
		OldObject: raw(old), Object: raw(cur), UserInfo: authenticationv1.UserInfo{Username: username},
	}}
}

func edited(s *corev1.Secret) *corev1.Secret {
	e := s.DeepCopy()
	e.Data["value"] = []byte("edited")
	return e
}

func TestSecretValidator(t *testing.T) {
	tenantIdentity := identity.UserName(tenantNS, "team-a")
	key := tenantSecret(tenantNS, sopsv1alpha1.TenantKeySecretName("team-a"), "team-a")
	next := tenantSecret(tenantNS, sopsv1alpha1.TenantNextKeySecretName("team-a"), "team-a")
	unusedKey := tenantSecret(tenantNS, sopsv1alpha1.TenantKeySecretName("team-b"), "team-b")
	unlabelled := outputSecret()
	unlabelled.Labels = nil

	cases := []struct {
		name    string
		req     admission.Request
		allowed bool
		reason  string
	}{
		{"shall refuse a user's change to an output Secret",
			request(t, admissionv1.Update, user, outputSecret(), edited(outputSecret())), false, "SopsSecret db"},
		{"shall refuse a user's deletion of an output Secret",
			request(t, admissionv1.Delete, user, outputSecret(), nil), false, "SopsSecret db"},
		{"shall refuse a user's removal of the labels of an output Secret",
			request(t, admissionv1.Update, user, outputSecret(), unlabelled), false, "SopsSecret db"},
		{"shall allow the tenant identity to write an output Secret",
			request(t, admissionv1.Update, tenantIdentity, outputSecret(), edited(outputSecret())), true, ""},
		{"shall allow the garbage collector to delete an output Secret",
			request(t, admissionv1.Delete, "system:serviceaccount:kube-system:generic-garbage-collector", outputSecret(), nil), true, ""},
		{"shall allow the namespace controller to delete an output Secret",
			request(t, admissionv1.Delete, "system:serviceaccount:kube-system:namespace-controller", outputSecret(), nil), true, ""},
		{"shall refuse a user's change to the key of a tenant with SopsSecrets",
			request(t, admissionv1.Update, user, key, edited(key)), false, "startRotation"},
		{"shall refuse a user's deletion of the key of a tenant with SopsSecrets",
			request(t, admissionv1.Delete, user, key, nil), false, "startRotation"},
		{"shall refuse a user's deletion of the next key of a tenant with SopsSecrets",
			request(t, admissionv1.Delete, user, next, nil), false, "startRotation"},
		{"shall allow the tenant identity to replace the key in a rotation",
			request(t, admissionv1.Update, tenantIdentity, key, edited(key)), true, ""},
		{"shall allow a user to change the key of a tenant without SopsSecrets",
			request(t, admissionv1.Update, user, unusedKey, edited(unusedKey)), true, ""},
		{"shall allow a user to change another Secret with tenant labels",
			request(t, admissionv1.Update, user, tenantSecret("prod", "other", "team-a"), edited(tenantSecret("prod", "other", "team-a"))), true, ""},
	}
	v := validator(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := v.Handle(context.Background(), c.req)
			if resp.Allowed != c.allowed {
				t.Fatalf("allowed = %v, want %v (%v)", resp.Allowed, c.allowed, resp.Result)
			}
			if !c.allowed && !strings.Contains(resp.Result.Message, c.reason) {
				t.Fatalf("message %q does not mention %q", resp.Result.Message, c.reason)
			}
		})
	}
}
