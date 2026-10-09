package controller

// Operator permissions (DESIGN.md §5.3). The operator has no permission on Secrets; it reads
// tenant keys and writes Secrets only by impersonating tenant identities.
//
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants;sopssecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=sops.stakater.com,resources=sopstenants/status;sopssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=impersonate,resourceNames=sops
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
// +kubebuilder:rbac:groups="";events.k8s.io,resources=events,verbs=create;patch
