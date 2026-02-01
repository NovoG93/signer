package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap/zapcore"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type Config struct {
	SignerName             string
	LogLevel               zapcore.Level
	LeaderElection         bool
	LeaderElectionID       string
	MetricsBindAddress     string
	HealthProbeBindAddress string
	CertValidity           time.Duration
	CertRefreshBefore      time.Duration
	CASecretName           string
	CASecretNamespace      string
	CACertKey              string
	CAKeyKey               string
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

	// Parse LeaderElection (default: true)
	leaderElection := true
	if leaderElectionStr := getEnv("LEADER_ELECTION"); leaderElectionStr != "" {
		leaderElection, _ = strconv.ParseBool(leaderElectionStr)
	}

	// Parse LeaderElectionID (default: "signer-controller")
	leaderElectionID := getEnv("LEADER_ELECTION_ID")
	if leaderElectionID == "" {
		leaderElectionID = "signer-controller"
	}

	// Parse MetricsBindAddress (default: ":8080")
	metricsBindAddress := getEnv("METRICS_BIND_ADDRESS")
	if metricsBindAddress == "" {
		metricsBindAddress = ":8080"
	}

	// Parse HealthProbeBindAddress (default: ":8081")
	healthProbeBindAddress := getEnv("HEALTH_PROBE_BIND_ADDRESS")
	if healthProbeBindAddress == "" {
		healthProbeBindAddress = ":8081"
	}

	// Parse CertValidity (default: "1h")
	certValidityStr := getEnv("CERT_VALIDITY")
	if certValidityStr == "" {
		certValidityStr = "1h"
	}
	certValidity, _ := time.ParseDuration(certValidityStr)

	// Parse CertRefreshBefore (default: "30m")
	certRefreshBeforeStr := getEnv("CERT_REFRESH_BEFORE")
	if certRefreshBeforeStr == "" {
		certRefreshBeforeStr = "30m"
	}
	certRefreshBefore, _ := time.ParseDuration(certRefreshBeforeStr)

	// Parse CASecretName (default: "" = in-memory CA)
	caSecretName := getEnv("CA_SECRET_NAME")

	// Parse CASecretNamespace (default: "" = controller namespace)
	caSecretNamespace := getEnv("CA_SECRET_NAMESPACE")

	// Parse CACertKey (default: "ca.crt")
	caCertKey := getEnv("CA_CERT_KEY")
	if caCertKey == "" {
		caCertKey = "ca.crt"
	}

	// Parse CAKeyKey (default: "ca.key")
	caKeyKey := getEnv("CA_KEY_KEY")
	if caKeyKey == "" {
		caKeyKey = "ca.key"
	}

	return &Config{
		SignerName:             signerName,
		LogLevel:               level,
		LeaderElection:         leaderElection,
		LeaderElectionID:       leaderElectionID,
		MetricsBindAddress:     metricsBindAddress,
		HealthProbeBindAddress: healthProbeBindAddress,
		CertValidity:           certValidity,
		CertRefreshBefore:      certRefreshBefore,
		CASecretName:           caSecretName,
		CASecretNamespace:      caSecretNamespace,
		CACertKey:              caCertKey,
		CAKeyKey:               caKeyKey,
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
	log.Printf("Leader election: %v (ID: %s)", config.LeaderElection, config.LeaderElectionID)
	log.Printf("Metrics: %s, Health probes: %s", config.MetricsBindAddress, config.HealthProbeBindAddress)

	mgr, err := CreateManager(ctrl.GetConfigOrDie(), config)
	if err != nil {
		log.Fatal(err, "unable to start manager")
	}

	log.Println("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Fatal(err, "problem running manager")
	}
}
