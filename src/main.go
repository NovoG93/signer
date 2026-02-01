package main

import (
	"log"
	"os"

	"go.uber.org/zap/zapcore"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// Register the PCR type so the client understands it
	utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
}

func main() {
	logLevel := os.Getenv("LOG_LEVEL")
	var level zapcore.Level
	if logLevel == "debug" {
		level = zapcore.DebugLevel
	} else {
		level = zapcore.InfoLevel
	}

	opts := zap.Options{
		Development: false,
		Level:       level,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		log.Fatal(err, "unable to start manager")
	}

	// Initialize the CA
	// TODO: Load from a secret
	ca, err := NewCA()
	if err != nil {
		log.Fatal(err, "failed to init CA")
	}

	// Get signer name from environment variable with default fallback
	signerName := os.Getenv("SIGNER_NAME")
	if signerName == "" {
		signerName = "novog93.ghcr/signer" // Default signer name
	}
	log.Printf("Using signer name: %s", signerName)

	if err = (&SignerReconciler{
		Client:     mgr.GetClient(),
		CA:         ca,
		SignerName: signerName,
	}).SetupWithManager(mgr); err != nil {
		log.Fatal(err, "unable to create controller")
	}

	log.Println("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatal(err, "problem running manager")
	}
}
