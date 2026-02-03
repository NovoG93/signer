package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// IssuedCounter tracks successfully issued certificates
	IssuedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_certificates_issued_total",
			Help: "The total number of certificates issued",
		},
		[]string{"validity_duration"},
	)

	// FailedCounter tracks failed certificate requests
	FailedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "signer_certificates_failed_total",
			Help: "The total number of failed certificate requests",
		},
		[]string{"reason"},
	)

	// ActiveCertificatesGauge tracks unsigned PodCertificateRequests
	ActiveCertificatesGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "signer_certificates_active",
			Help: "The number of currently unsigned PodCertificateRequest objects",
		},
	)

	// ReconciliationDuration tracks reconciliation timing
	ReconciliationDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "signer_reconciliation_duration_seconds",
			Help:    "Duration of reconciliation operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
)

func init() {
	// Register metrics with controller-runtime metrics registry
	metrics.Registry.MustRegister(
		IssuedCounter,
		FailedCounter,
		ActiveCertificatesGauge,
		ReconciliationDuration,
	)
}
