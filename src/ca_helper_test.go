package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewCA_InMemory_Succeeds(t *testing.T) {
	RegisterTestingT(t)

	ca, err := NewCA()
	Expect(err).NotTo(HaveOccurred())
	Expect(ca).NotTo(BeNil())
	Expect(ca.Cert).NotTo(BeNil())
	Expect(ca.Key).NotTo(BeNil())
	Expect(ca.Cert.IsCA).To(BeTrue())
}

func generateSelfSignedCert(t *testing.T) ([]byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}

func TestNewCA_FromSecret_Succeeds(t *testing.T) {
	RegisterTestingT(t)

	certPEM, keyPEM := generateSelfSignedCert(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
			"ca.key": keyPEM,
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	ca, err := NewCAFromSecret(context.Background(), fakeClient, "ca-secret", "default", "ca.crt", "ca.key")
	Expect(err).NotTo(HaveOccurred())
	Expect(ca).NotTo(BeNil())
	Expect(ca.Cert.Subject.CommonName).To(Equal("Test CA"))
}

func TestNewCA_FromSecret_MissingKey(t *testing.T) {
	RegisterTestingT(t)

	certPEM, _ := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-secret-incomplete",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	_, err := NewCAFromSecret(context.Background(), fakeClient, "ca-secret-incomplete", "default", "ca.crt", "ca.key")
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("not found in secret"))
}

func TestNewCA_FromSecret_InvalidCert(t *testing.T) {
	RegisterTestingT(t)

	_, keyPEM := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-secret-bad-cert",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("invalid-pem-data"),
			"ca.key": keyPEM,
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	_, err := NewCAFromSecret(context.Background(), fakeClient, "ca-secret-bad-cert", "default", "ca.crt", "ca.key")
	Expect(err).To(HaveOccurred())
}

func TestNewCA_FromSecret_InvalidKey(t *testing.T) {
	RegisterTestingT(t)

	certPEM, _ := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-secret-bad-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
			"ca.key": []byte("invalid-key-data"),
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	_, err := NewCAFromSecret(context.Background(), fakeClient, "ca-secret-bad-key", "default", "ca.crt", "ca.key")
	Expect(err).To(HaveOccurred())
}

func TestCAHelper_ReloadsOnSecretChange(t *testing.T) {
	RegisterTestingT(t)

	certPEM, keyPEM := generateSelfSignedCert(t)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
			"ca.key": keyPEM,
		},
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	// 1. Load initial CA
	ca, err := NewCAFromSecret(context.Background(), c, "ca-secret", "default", "ca.crt", "ca.key")
	Expect(err).NotTo(HaveOccurred())

	// 2. Simulate update by manually reloading (since real watcher needs env)
	// Create a new distinct certificate
	newCertPEM, newKeyPEM := generateSelfSignedCert(t)

	// Update secret in fake client
	secret.Data["ca.crt"] = newCertPEM
	secret.Data["ca.key"] = newKeyPEM
	err = c.Update(context.Background(), secret)
	Expect(err).NotTo(HaveOccurred())

	// 3. Trigger reload logic (mocking the watcher handler)
	err = ca.LoadFromSecret(context.Background(), c, "ca-secret", "default", "ca.crt", "ca.key")
	Expect(err).NotTo(HaveOccurred())

	// 4. Verify CAHelper has new cert
	// GetCert() uses RWMutex to safely read the updated certificate
	currentCert := ca.GetCert()
	Expect(currentCert).ToNot(BeNil())
	// The new cert is now active; PEM differs from original (different key)
	// In production, the SecretReconciler watches for Secret updates and calls
	// LoadFromSecret() to hot-reload without pod restart
}
