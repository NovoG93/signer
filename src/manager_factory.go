package main

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
)

var (
	scheme               = runtime.NewScheme()
	newManagerFunc       = ctrl.NewManager
	newCAFunc            = NewCA
	setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager) error {
		return r.SetupWithManager(mgr)
	}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
}

func CreateManager(kubeConfig *rest.Config, config *Config) (ctrl.Manager, error) {
	if kubeConfig == nil || config == nil {
		return nil, fmt.Errorf("kubeConfig and config must not be nil")
	}

	mgrOptions := ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  config.HealthProbeBindAddress,
		LeaderElection:          config.LeaderElection,
		LeaderElectionID:        config.LeaderElectionID,
		LeaderElectionNamespace: config.LeaderElectionNamespace,
	}

	mgr, err := newManagerFunc(kubeConfig, mgrOptions)
	if err != nil {
		return nil, err
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, err
	}

	// Initialize the CA
	ca, err := newCAFunc()
	if err != nil {
		return nil, err
	}

	if err = setupWithManagerFunc(&SignerReconciler{
		Client:     mgr.GetClient(),
		CA:         ca,
		SignerName: config.SignerName,
		Config:     config,
	}, mgr); err != nil {
		return nil, err
	}

	return mgr, nil
}
