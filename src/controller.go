package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SignerReconciler watches PCRs
type SignerReconciler struct {
	client.Client
	CA         *CAHelper
	SignerName string
	Config     *Config
}

// Reconcile is the loop. It receives a Name/Namespace and decides what to do.
func (r *SignerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		ReconciliationDuration.Observe(duration)
	}()

	log := log.FromContext(ctx)

	var pcr certificatesv1beta1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &pcr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 1. Filter: Is this for us?
	if pcr.Spec.SignerName != r.SignerName {
		log.V(1).Info("Ignoring request for different signer", "signer", pcr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	// 2. Filter: Is it already signed?
	if len(pcr.Status.CertificateChain) > 0 {
		log.V(1).Info("Certificate already exists", "name", req.Name)
		return ctrl.Result{}, nil
	}

	// 3. Parse the Public Key from the PCR
	log.V(1).Info("Parsing public key...", "name", req.Name)

	// Parse the DER-encoded PKIX public key directly
	pub, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		log.Error(err, "Failed to parse PKIX public key")
		// Set Failed condition and update status
		r.setFailedCondition(ctx, &pcr, "InvalidPublicKey", fmt.Sprintf("Failed to parse public key: %v", err), req)
		return ctrl.Result{}, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	// Validate public key type (RSA or ECDSA)
	switch pub.(type) {
	case *rsa.PublicKey:
	case *ecdsa.PublicKey:
	default:
		errMsg := fmt.Sprintf("unsupported public key type: %T", pub)
		log.Error(fmt.Errorf("unsupported key type"), errMsg)
		r.setFailedCondition(ctx, &pcr, "UnsupportedKeyType", errMsg, req)
		return ctrl.Result{}, fmt.Errorf("%s", errMsg)
	}

	// NOTE: According to KEP-4317, "Signer implementations do not need to verify
	// any proof of possession; this is handled by kube-apiserver."
	// kube-apiserver validates the POP during admission before the PCR reaches us.
	// We can safely proceed without additional validation.

	// 4. Create the Certificate (Go Crypto)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Calculate Timings
	now := time.Now()
	validity := time.Hour
	refreshBefore := 30 * time.Minute

	if r.Config != nil {
		if r.Config.CertValidity > 0 {
			validity = r.Config.CertValidity
		}
		if r.Config.CertRefreshBefore > 0 {
			refreshBefore = r.Config.CertRefreshBefore
		}
	}

	// Validate minimum cert validity (must be >= 1h per Kubernetes PCR API spec)
	const minValidity = time.Hour
	if validity < minValidity {
		log.Info("WARN: CertValidity too low, using minimum", "configured", validity, "minimum", minValidity)
		validity = minValidity
	}

	// Validate minimum refresh time (should be >= 30m to be practical)
	const minRefresh = 30 * time.Minute
	if refreshBefore < minRefresh {
		log.Info("WARN: CertRefreshBefore too low, using minimum", "configured", refreshBefore, "minimum", minRefresh)
		refreshBefore = minRefresh
	}

	// Cap by MaxExpirationSeconds if present
	if pcr.Spec.MaxExpirationSeconds != nil {
		maxValidity := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
		if maxValidity < validity {
			validity = maxValidity
		}
	}

	notAfter := now.Add(validity)
	refreshAt := notAfter.Add(-refreshBefore)

	// RefreshAt must be between NotBefore (now) and NotAfter
	if refreshAt.Before(now) {
		refreshAt = now
	}

	// SANs and Key Usage
	dnsName := fmt.Sprintf("%s.pod.cluster.local", pcr.Spec.PodName)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:  []string{dnsName},
		NotBefore: now,
		NotAfter:  notAfter,
		// usually serverAuth + clientAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// For RSA keys, we might want to add KeyEncipherment as well,
	// but the requirement only specified DigitalSignature.
	if _, ok := pub.(*rsa.PublicKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// Check if CA is initialized
	if r.CA == nil {
		errMsg := "CA not initialized"
		log.Error(fmt.Errorf("nil CA"), errMsg)
		r.setFailedCondition(ctx, &pcr, "SigningFailed", errMsg, req)
		return ctrl.Result{}, fmt.Errorf("%s", errMsg)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, r.CA.GetCert(), pub, r.CA.GetKey())
	if err != nil {
		log.Error(err, "Failed to create certificate")
		r.setFailedCondition(ctx, &pcr, "SigningFailed", fmt.Sprintf("Failed to create certificate: %v", err), req)
		return ctrl.Result{}, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// 5. Update Status
	// Note: status.certificateChain expects RAW PEM string, not base64 encoded
	pcr.Status.CertificateChain = string(certPEM)

	// Set the required time fields
	metaNow := metav1.NewTime(now)
	metaRefresh := metav1.NewTime(refreshAt)
	metaAfter := metav1.NewTime(notAfter)

	pcr.Status.NotBefore = &metaNow
	pcr.Status.NotAfter = &metaAfter
	pcr.Status.BeginRefreshAt = &metaRefresh

	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               "Issued",
			Status:             metav1.ConditionTrue,
			Reason:             "IssuedByGoController",
			Message:            "Signed by NovoG93 Signer Controller",
			LastTransitionTime: metav1.Now(),
		},
	}

	// Use retry for conflict handling
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return r.Status().Update(ctx, &pcr)
	})
	if err != nil {
		log.Error(err, "Failed to update status")
		// If we get a conflict error, requeue
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, err
		}
		return ctrl.Result{}, err
	}

	log.Info("Certificate issued", "pod", req.Name, "node", pcr.Spec.NodeName)

	// Record metrics
	validityStr := validity.String()
	IssuedCounter.WithLabelValues(validityStr).Inc()

	return ctrl.Result{}, nil
}

// setFailedCondition sets a Failed condition on the PCR and updates its status
func (r *SignerReconciler) setFailedCondition(ctx context.Context, pcr *certificatesv1beta1.PodCertificateRequest, reason, message string, req ctrl.Request) {
	log := log.FromContext(ctx)

	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               "Issued",
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: metav1.Now(),
		},
	}

	if err := r.Status().Update(ctx, pcr); err != nil {
		log.Error(err, "Failed to update status with error condition", "reason", reason)
	}

	// Record metrics
	FailedCounter.WithLabelValues(reason).Inc()
}

// Boilerplate to setup the watch
func (r *SignerReconciler) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1beta1.PodCertificateRequest{}).
		WithOptions(options).
		Complete(r)
}
