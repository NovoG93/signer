package main

import (
	"testing"
	"time"
)

func TestLoadConfig_Defaults_Extended(t *testing.T) {
	// Empty env
	getEnv := func(key string) string { return "" }
	config := LoadConfig(getEnv)

	if config.LeaderElection != true {
		t.Errorf("expected LeaderElection true, got %v", config.LeaderElection)
	}
	if config.LeaderElectionID != "signer-controller" {
		t.Errorf("expected LeaderElectionID 'signer-controller', got %q", config.LeaderElectionID)
	}
	if config.MetricsBindAddress != ":8080" {
		t.Errorf("expected MetricsBindAddress ':8080', got %q", config.MetricsBindAddress)
	}
	if config.HealthProbeBindAddress != ":8081" {
		t.Errorf("expected HealthProbeBindAddress ':8081', got %q", config.HealthProbeBindAddress)
	}
	if config.CertValidity != time.Hour {
		t.Errorf("expected CertValidity 1h, got %v", config.CertValidity)
	}
	if config.CertRefreshBefore != 30*time.Minute {
		t.Errorf("expected CertRefreshBefore 30m, got %v", config.CertRefreshBefore)
	}
	if config.CASecretName != "" {
		t.Errorf("expected CASecretName empty, got %q", config.CASecretName)
	}
	if config.CASecretNamespace != "" {
		t.Errorf("expected CASecretNamespace empty, got %q", config.CASecretNamespace)
	}
	if config.CACertKey != "ca.crt" {
		t.Errorf("expected CACertKey 'ca.crt', got %q", config.CACertKey)
	}
	if config.CAKeyKey != "ca.key" {
		t.Errorf("expected CAKeyKey 'ca.key', got %q", config.CAKeyKey)
	}
}

func TestLoadConfig_Overrides_Extended(t *testing.T) {
	env := map[string]string{
		"LEADER_ELECTION":           "false",
		"LEADER_ELECTION_ID":        "my-id",
		"METRICS_BIND_ADDRESS":      ":9090",
		"HEALTH_PROBE_BIND_ADDRESS": ":9091",
		"CERT_VALIDITY":             "2h",
		"CERT_REFRESH_BEFORE":       "45m",
		"CA_SECRET_NAME":            "my-ca",
		"CA_SECRET_NAMESPACE":       "my-ns",
		"CA_CERT_KEY":               "cert.pem",
		"CA_KEY_KEY":                "key.pem",
	}
	getEnv := func(key string) string { return env[key] }

	config := LoadConfig(getEnv)

	if config.LeaderElection != false {
		t.Errorf("expected LeaderElection false, got %v", config.LeaderElection)
	}
	if config.LeaderElectionID != "my-id" {
		t.Errorf("expected LeaderElectionID 'my-id', got %q", config.LeaderElectionID)
	}
	if config.MetricsBindAddress != ":9090" {
		t.Errorf("expected MetricsBindAddress ':9090', got %q", config.MetricsBindAddress)
	}
	if config.HealthProbeBindAddress != ":9091" {
		t.Errorf("expected HealthProbeBindAddress ':9091', got %q", config.HealthProbeBindAddress)
	}
	if config.CertValidity != 2*time.Hour {
		t.Errorf("expected CertValidity 2h, got %v", config.CertValidity)
	}
	if config.CertRefreshBefore != 45*time.Minute {
		t.Errorf("expected CertRefreshBefore 45m, got %v", config.CertRefreshBefore)
	}
	if config.CASecretName != "my-ca" {
		t.Errorf("expected CASecretName 'my-ca', got %q", config.CASecretName)
	}
	if config.CASecretNamespace != "my-ns" {
		t.Errorf("expected CASecretNamespace 'my-ns', got %q", config.CASecretNamespace)
	}
	if config.CACertKey != "cert.pem" {
		t.Errorf("expected CACertKey 'cert.pem', got %q", config.CACertKey)
	}
	if config.CAKeyKey != "key.pem" {
		t.Errorf("expected CAKeyKey 'key.pem', got %q", config.CAKeyKey)
	}
}
