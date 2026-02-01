package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	// The Go client library automatically decodes the base64 JSON string into pcr.Spec.PKIXPublicKey ([]byte).
	// The resulting bytes are in DER format (raw PKIX).
	// This matches how the kubelet sends the key.

	log.V(1).Info("Parsing public key...", "name", req.Name)

	// Parse the DER-encoded PKIX public key directly
	pub, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	// Validate public key type (RSA or ECDSA)
	switch pub.(type) {
	case *rsa.PublicKey:
	case *ecdsa.PublicKey:
	default:
		return ctrl.Result{}, fmt.Errorf("unsupported public key type: %T", pub)
	}

	// Phase 6: Validate Proof of Possession
	if err := validateProofOfPossession(string(pcr.Spec.ProofOfPossession), pub, pcr.Spec.PKIXPublicKey); err != nil {
		log.Error(err, "POP validation failed", "name", req.Name)
		return ctrl.Result{}, err
	}

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

	// Phase 5: SANs and Key Usage
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

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, r.CA.GetCert(), pub, r.CA.GetKey())
	if err != nil {
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

	if err := r.Status().Update(ctx, &pcr); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Certificate issued", "pod", req.Name, "node", pcr.Spec.NodeName)
	return ctrl.Result{}, nil
}

// Boilerplate to setup the watch
func (r *SignerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1beta1.PodCertificateRequest{}).
		Complete(r)
}

func validateProofOfPossession(popStr string, pubKey interface{}, pkixPublicKeyBytes []byte) error {
	if popStr == "" {
		return fmt.Errorf("empty proof of possession")
	}

	// Decode the base64-encoded signature
	signature, err := base64.StdEncoding.DecodeString(popStr)
	if err != nil {
		return fmt.Errorf("failed to decode POP as base64: %w", err)
	}

	if len(signature) == 0 {
		return fmt.Errorf("empty POP signature")
	}

	// Hash the public key bytes (this is what the kubelet signs to prove possession)
	hash := sha256.Sum256(pkixPublicKeyBytes)

	// Verify based on key type
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		// Verify RSA PKCS#1 v1.5 signature
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], signature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		// ECDSA signature in raw format (r|s concatenation)
		if len(signature)%2 != 0 {
			return fmt.Errorf("invalid ECDSA signature length (must be even)")
		}
		half := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:half])
		s := new(big.Int).SetBytes(signature[half:])
		if !ecdsa.Verify(k, hash[:], r, s) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}
