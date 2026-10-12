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

// Operator permissions (DESIGN.md §5.3). The operator has no permission on Secrets; it reads
// tenant keys and writes Secrets only by impersonating tenant identities.
//
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants;sopssecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants/status;sopssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=impersonate,resourceNames=sops
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups="";events.k8s.io,resources=events,verbs=create;patch
