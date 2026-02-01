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
	if config.LeaderElectionNamespace != "" {
		t.Errorf("expected LeaderElectionNamespace empty, got %q", config.LeaderElectionNamespace)
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
		"LEADER_ELECTION_NAMESPACE": "my-ns",
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
	if config.LeaderElectionNamespace != "my-ns" {
		t.Errorf("expected LeaderElectionNamespace 'my-ns', got %q", config.LeaderElectionNamespace)
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

func TestLoadConfig_PodNamespaceFallback(t *testing.T) {
	env := map[string]string{
		"POD_NAMESPACE": "fallback-ns",
	}
	getEnv := func(key string) string { return env[key] }

	config := LoadConfig(getEnv)

	if config.LeaderElectionNamespace != "fallback-ns" {
		t.Errorf("expected LeaderElectionNamespace 'fallback-ns', got %q", config.LeaderElectionNamespace)
	}

	// Verify priority
	env["LEADER_ELECTION_NAMESPACE"] = "explicit-ns"
	config = LoadConfig(getEnv)
	if config.LeaderElectionNamespace != "explicit-ns" {
		t.Errorf("expected LeaderElectionNamespace 'explicit-ns', got %q", config.LeaderElectionNamespace)
	}
}

func TestLoadConfig_CASecretDefaults(t *testing.T) {
	getEnv := func(key string) string { return "" }
	config := LoadConfig(getEnv)

	if config.CASecretName != "" {
		t.Errorf("expected CASecretName empty, got %q", config.CASecretName)
	}
}

func TestLoadConfig_CASecretOverrides(t *testing.T) {
	env := map[string]string{
		"CA_SECRET_NAME":      "my-secret",
		"CA_SECRET_NAMESPACE": "my-ns",
		"CA_CERT_KEY":         "my.crt",
		"CA_KEY_KEY":          "my.key",
	}
	getEnv := func(key string) string { return env[key] }
	config := LoadConfig(getEnv)

	if config.CASecretName != "my-secret" {
		t.Errorf("expected CASecretName 'my-secret', got %q", config.CASecretName)
	}
	if config.CASecretNamespace != "my-ns" {
		t.Errorf("expected CASecretNamespace 'my-ns', got %q", config.CASecretNamespace)
	}
	if config.CACertKey != "my.crt" {
		t.Errorf("expected CACertKey 'my.crt', got %q", config.CACertKey)
	}
	if config.CAKeyKey != "my.key" {
		t.Errorf("expected CAKeyKey 'my.key', got %q", config.CAKeyKey)
	}
}
