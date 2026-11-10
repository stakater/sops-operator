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

package testenv

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// controlPlaneBinaries are the processes envtest starts for a test API server.
var controlPlaneBinaries = []string{"etcd", "kube-apiserver"}

// orphanedControlPlane returns the PIDs in ps (output of `ps -A -o pid=,ppid=,command=`) of envtest control
// plane processes from the assets directory whose test is gone: their parent is PID 1. Processes of a
// running test, whose parent is alive, are never selected.
func orphanedControlPlane(ps, assets string) []int {
	if assets == "" {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(ps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "1" {
			continue
		}
		dir, binary := filepath.Split(fields[2])
		if filepath.Clean(dir) != filepath.Clean(assets) || !slices.Contains(controlPlaneBinaries, binary) {
			continue
		}
		if pid, err := strconv.Atoi(fields[0]); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// stopOrphanedControlPlane stops the control plane processes a test left behind when it died without
// stopping envtest, for example on a timeout or SIGKILL.
func stopOrphanedControlPlane() {
	out, err := exec.Command("ps", "-A", "-o", "pid=,ppid=,command=").Output()
	if err != nil {
		return
	}
	pids := orphanedControlPlane(string(out), os.Getenv("KUBEBUILDER_ASSETS"))
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range pids {
		for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// stopOnSignal stops te when the test is interrupted, so the control plane does not outlive it.
func stopOnSignal(te *envtest.Environment) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		_ = te.Stop()
		os.Exit(1)
	}()
}
