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

package controller_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/controller"
)

func TestHealthy(t *testing.T) {
	decrypted := func(generation, conditionGeneration, observedGeneration int64) *sopsv1alpha1.SopsSecret {
		s := &sopsv1alpha1.SopsSecret{}
		s.Generation = generation
		s.Status.ObservedGeneration = observedGeneration
		s.Status.Conditions = []metav1.Condition{{
			Type: sopsv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: sopsv1alpha1.ReasonDecrypted,
			ObservedGeneration: conditionGeneration,
		}}
		return s
	}
	cases := []struct {
		name string
		s    *sopsv1alpha1.SopsSecret
		want bool
	}{
		{"current generation decrypted", decrypted(3, 3, 3), true},
		{"condition from an earlier generation", decrypted(3, 2, 3), false},
		{"status from an earlier generation", decrypted(3, 3, 2), false},
		{"nothing observed yet", decrypted(3, 2, 2), false},
	}
	for _, c := range cases {
		t.Run("shall report "+c.name+" as healthy="+map[bool]string{true: "true", false: "false"}[c.want], func(t *testing.T) {
			if got := controller.HealthyForTest(c.s); got != c.want {
				t.Fatalf("healthy = %v, want %v", got, c.want)
			}
		})
	}
}
