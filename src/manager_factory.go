package main

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

var (
	scheme               = runtime.NewScheme()
	newManagerFunc       = ctrl.NewManager
	newCAFunc            = NewCA
	setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager) error {
		return r.SetupWithManager(mgr)
	}
	setupSecretWatcherFunc = func(mgr ctrl.Manager, ca *CAHelper, config *Config) error {
		return ctrl.NewControllerManagedBy(mgr).
			Named("ca-secret-watcher").
			For(&corev1.Secret{}).
			WithEventFilter(predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					return e.ObjectNew.GetName() == config.CASecretName &&
						e.ObjectNew.GetNamespace() == config.CASecretNamespace
				},
				CreateFunc: func(e event.CreateEvent) bool {
					return e.Object.GetName() == config.CASecretName &&
						e.Object.GetNamespace() == config.CASecretNamespace
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					return false // Ignore Secret deletes; reloads only on Create/Update events
				},
			}).
			Complete(&SecretReconciler{
				Client: mgr.GetClient(),
				CA:     ca,
				Config: config,
			})
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
	var ca *CAHelper

	if config.CASecretName != "" {
		ctx := context.Background()
		// Use APIReader to bypass manager cache during initialization.
		// The manager's cache is not yet synced at this point (only syncs on mgr.Start()),
		// but APIReader provides live cluster lookups via the API server.
		ca, err = NewCAFromSecret(ctx, mgr.GetAPIReader(), config.CASecretName, config.CASecretNamespace, config.CACertKey, config.CAKeyKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA from secret: %w", err)
		}

		// Add Secret Watcher
		if err := setupSecretWatcherFunc(mgr, ca, config); err != nil {
			return nil, fmt.Errorf("failed to setup CA secret watcher: %w", err)
		}

	} else {
		ca, err = newCAFunc()
		if err != nil {
			return nil, err
		}
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

// SecretReconciler reloads CA when secret changes
type SecretReconciler struct {
	client.Client
	CA     *CAHelper
	Config *Config
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Detected CA Secret change, reloading...", "secret", req.NamespacedName)

	err := r.CA.LoadFromSecret(ctx, r.Client, r.Config.CASecretName, r.Config.CASecretNamespace, r.Config.CACertKey, r.Config.CAKeyKey)
	if err != nil {
		log.Error(err, "Failed to reload CA from secret")
		// Backoff might be good, return error
		return ctrl.Result{}, err
	}

	log.Info("CA successfully reloaded from secret")
	return ctrl.Result{}, nil
}
