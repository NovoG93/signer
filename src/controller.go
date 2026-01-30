package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	SignerName = "novog93/signer"
)

// CAHelper holds our Authority
type CAHelper struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// SignerReconciler watches PCRs
type SignerReconciler struct {
	client.Client
	CA *CAHelper
}

// Reconcile is the loop. It receives a Name/Namespace and decides what to do.
func (r *SignerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr certificatesv1beta1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &pcr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 1. Filter: Is this for us?
	if pcr.Spec.SignerName != SignerName {
		return ctrl.Result{}, nil
	}

	// 2. Filter: Is it already signed?
	if len(pcr.Status.CertificateChain) > 0 {
		return ctrl.Result{}, nil
	}

	// 3. Parse the Public Key from the PCR
	block, _ := pem.Decode([]byte(pcr.Spec.PKIXPublicKey))
	if block == nil {
		return ctrl.Result{}, fmt.Errorf("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 4. Create the Certificate (Go Crypto)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Calculate Timings (matching your script's logic)
	now := time.Now()
	// TODO: Set timings via ENV variables and helm values
	notAfter := now.Add(time.Hour * 1) // 1 Hour Validity
	refreshAt := now.Add(time.Minute * 30)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s.pod.cluster.local", pcr.Spec.PodName),
		},
		NotBefore: now,
		NotAfter:  notAfter,
		// Usually serverAuth + clientAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, r.CA.Cert, pub, r.CA.Key)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// 5. Update Status
	// Note: status.certificateChain expects RAW PEM string, not base64 encoded
	pcr.Status.CertificateChain = string(certPEM)

	// Set the required time fields (The fields you debugged!)
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

	fmt.Printf("✅ Issued cert for %s\n", req.Name)
	return ctrl.Result{}, nil
}

// Boilerplate to setup the watch
func (r *SignerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1beta1.PodCertificateRequest{}).
		Complete(r)
}
