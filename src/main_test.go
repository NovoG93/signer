package main

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		env            map[string]string
		expectedSigner string
		expectedLevel  zapcore.Level
	}{
		{
			name:           "Defaults",
			env:            map[string]string{},
			expectedSigner: "novog93.ghcr/signer",
			expectedLevel:  zapcore.InfoLevel,
		},
		{
			name: "Overrides",
			env: map[string]string{
				"SIGNER_NAME": "custom/signer",
				"LOG_LEVEL":   "debug",
			},
			expectedSigner: "custom/signer",
			expectedLevel:  zapcore.DebugLevel,
		},
		{
			name: "InvalidLogLevel",
			env: map[string]string{
				"LOG_LEVEL": "invalid",
			},
			expectedSigner: "novog93.ghcr/signer",
			expectedLevel:  zapcore.InfoLevel, // Falls back to info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getEnv := func(key string) string {
				return tt.env[key]
			}

			config := LoadConfig(getEnv)

			if config.SignerName != tt.expectedSigner {
				t.Errorf("expected signer %q, got %q", tt.expectedSigner, config.SignerName)
			}
			if config.LogLevel != tt.expectedLevel {
				t.Errorf("expected log level %v, got %v", tt.expectedLevel, config.LogLevel)
			}
		})
	}
}
