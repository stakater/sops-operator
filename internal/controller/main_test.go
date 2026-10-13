package controller_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/stakater/sops-operator/internal/controller"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/testenv"
)

const resync = 2 * time.Second

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := startManager(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = env.Stop()
		os.Exit(1)
	}
	code := m.Run()
	cancel()
	_ = env.Stop()
	os.Exit(code)
}

// startManager runs the controllers as the non-admin operator user.
func startManager(ctx context.Context) error {
	mgr, err := ctrl.NewManager(env.OperatorConfig, ctrl.Options{
		Scheme:                 env.Scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		return err
	}
	if err := controller.SetupIndexes(ctx, mgr); err != nil {
		return err
	}
	ids := identity.NewFactory(env.OperatorConfig, env.Scheme)
	recorder := mgr.GetEventRecorder("sops-operator")
	if err := (&controller.SopsTenantReconciler{
		Client: mgr.GetClient(), Identities: ids, Recorder: recorder, ResyncInterval: resync,
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	if err := (&controller.SopsSecretReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Identities: ids, ResyncInterval: resync,
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()
	return nil
}
