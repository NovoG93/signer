package main

import (
	"log"
	"os"

	"go.uber.org/zap/zapcore"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type Config struct {
	SignerName string
	LogLevel   zapcore.Level
}

func LoadConfig(getEnv func(string) string) *Config {
	logLevel := getEnv("LOG_LEVEL")
	var level zapcore.Level
	if logLevel == "debug" {
		level = zapcore.DebugLevel
	} else {
		level = zapcore.InfoLevel
	}

	signerName := getEnv("SIGNER_NAME")
	if signerName == "" {
		signerName = "novog93.ghcr/signer"
	}

	return &Config{
		SignerName: signerName,
		LogLevel:   level,
	}
}

func main() {
	config := LoadConfig(os.Getenv)

	opts := zap.Options{
		Development: false,
		Level:       config.LogLevel,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	log.Printf("Using signer name: %s", config.SignerName)

	mgr, err := CreateManager(ctrl.GetConfigOrDie(), config.SignerName)
	if err != nil {
		log.Fatal(err, "unable to start manager")
	}

	log.Println("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatal(err, "problem running manager")
	}
}
