package main

import (
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

func CreateManager(config *rest.Config, signerName string) (ctrl.Manager, error) {
	mgr, err := newManagerFunc(config, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8081",
	})
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
		SignerName: signerName,
	}, mgr); err != nil {
		return nil, err
	}

	return mgr, nil
}
