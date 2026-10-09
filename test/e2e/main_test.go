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

// Package e2e runs the operator image on a Kind cluster and compares the resources it produces
// with committed golden files (testdata/). Run it with `make test-e2e`; it is skipped when KIND_CLUSTER is unset.
package e2e

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

const operatorNamespace = "sops-operator-system"

var (
	// kubeContext is passed explicitly to every kubectl call and to the client, so the tests
	// never act on whatever cluster the current kubeconfig context points to.
	kubeContext string
	scheme      = runtime.NewScheme()
	k8s         client.Client
)

func TestMain(m *testing.M) {
	cluster := os.Getenv("KIND_CLUSTER")
	if cluster == "" {
		fmt.Println("KIND_CLUSTER is not set; skipping e2e tests (run make test-e2e)")
		os.Exit(0)
	}
	kubeContext = "kind-" + cluster
	if err := setup(cluster); err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	if code == 0 && flag.Lookup("test.run").Value.String() == "" {
		if obsolete := obsoleteGoldenFiles(); len(obsolete) > 0 {
			fmt.Fprintf(os.Stderr, "golden files no test compares any more (delete them):\n  %s\n",
				strings.Join(obsolete, "\n  "))
			code = 1
		}
	}
	os.Exit(code)
}

// setup builds the operator image, loads it into Kind and deploys the operator with its CRDs
// and the tenant-facing ClusterRoles.
func setup(cluster string) error {
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := sopsv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	image := envOr("E2E_IMG", "sops-operator:e2e")
	if os.Getenv("E2E_SKIP_BUILD") != "true" {
		if _, err := run("", "docker", "build", "-t", image, "."); err != nil {
			return err
		}
	}
	if _, err := run("", envOr("KIND", "kind"), "load", "docker-image", image, "--name", cluster); err != nil {
		return err
	}
	manifests, err := run("", envOr("KUSTOMIZE", "kustomize"), "build", "config/default")
	if err != nil {
		return err
	}
	if !strings.Contains(manifests, "image: controller:latest") {
		return fmt.Errorf("config/default no longer uses the controller:latest image placeholder")
	}
	manifests = strings.ReplaceAll(manifests, "image: controller:latest", "image: "+image)
	if _, err := run(manifests, "kubectl", "--context", kubeContext, "apply", "--server-side", "-f", "-"); err != nil {
		return err
	}
	if _, err := run("", "kubectl", "--context", kubeContext,
		"apply", "--server-side", "-k", "config/tenant-rbac"); err != nil {
		return err
	}
	// The image tag does not change between runs, so restart to pick up a freshly loaded image.
	if _, err := run("", "kubectl", "--context", kubeContext, "-n", operatorNamespace,
		"rollout", "restart", "deployment/sops-operator-controller-manager"); err != nil {
		return err
	}
	if _, err := run("", "kubectl", "--context", kubeContext, "-n", operatorNamespace,
		"rollout", "status", "deployment/sops-operator-controller-manager", "--timeout=180s"); err != nil {
		return err
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext},
	).ClientConfig()
	if err != nil {
		return err
	}
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	// Fail early if the context points at the wrong cluster.
	return k8s.List(context.Background(), &sopsv1alpha1.SopsTenantList{})
}

// run executes a command from the repository root, feeding stdin when given. Errors include
// the command output.
func run(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = repoRoot()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

// obsoleteGoldenFiles lists files under testdata that no test compared in this run.
func obsoleteGoldenFiles() []string {
	var obsolete []string
	_ = filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if name, _ := filepath.Rel("testdata", path); !usedGolden[name] {
			obsolete = append(obsolete, path)
		}
		return nil
	})
	return obsolete
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("go.mod not found above the working directory")
		}
		dir = parent
	}
}
