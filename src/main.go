package main

import (
	"log"
	"os"

	"go.uber.org/zap/zapcore"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

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

	// Get signer name from environment variable with default fallback
	signerName := os.Getenv("SIGNER_NAME")
	if signerName == "" {
		signerName = "novog93.ghcr/signer" // Default signer name
	}
	log.Printf("Using signer name: %s", signerName)

	mgr, err := CreateManager(ctrl.GetConfigOrDie(), signerName)
	if err != nil {
		log.Fatal(err, "unable to start manager")
	}

	log.Println("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatal(err, "problem running manager")
	}
}
