package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

// generateTestPublicKeyDER creates a test RSA public key in DER format (PKIX)
func generateTestPublicKeyDER() ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privateKey, nil
}

// generateTestPublicKeyPEM creates a test RSA public key in PEM format (as []byte)
// This matches what Kubernetes kubelet sends in PodCertificateRequest.Spec.PKIXPublicKey (after base64 decoding)
func generateTestPublicKeyPEM() ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	// Encode as PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return pemBytes, privateKey, nil
}

var _ = Describe("SignerReconciler", func() {
	Describe("TestReconcilerExists", func() {
		It("should instantiate SignerReconciler struct", func() {
			// Test that the SignerReconciler can be instantiated
			reconciler := &SignerReconciler{}
			Expect(reconciler).NotTo(BeNil())
		})
	})

	Describe("TestEmptyTestSuite", func() {
		It("should verify the framework works", func() {
			// Basic sanity test to verify Ginkgo/Gomega framework works
			value := 42
			Expect(value).To(Equal(42))
		})
	})
})

var _ = Describe("CA Helper", func() {
	Describe("TestNewCACertIsValid", func() {
		It("should return CAHelper with valid x509.Certificate", func() {
			ca, err := NewCA()

			Expect(err).NotTo(HaveOccurred())
			Expect(ca).NotTo(BeNil())
			Expect(ca.Cert).NotTo(BeNil())

			// Verify certificate is valid by checking it can be used and has expected fields
			Expect(ca.Cert.SerialNumber).NotTo(BeNil())
		})
	})

	Describe("TestNewCAKeyIsRSA2048", func() {
		It("should return RSA 2048 private key", func() {
			ca, err := NewCA()

			Expect(err).NotTo(HaveOccurred())
			Expect(ca).NotTo(BeNil())
			Expect(ca.Key).NotTo(BeNil())

			// Verify key size is 2048 bits
			Expect(ca.Key.PublicKey.N.BitLen()).To(Equal(2048))
		})
	})

	Describe("TestNewCACommonName", func() {
		It("should set certificate Subject CommonName to NovoG93 Signer CA", func() {
			ca, err := NewCA()

			Expect(err).NotTo(HaveOccurred())
			Expect(ca).NotTo(BeNil())
			Expect(ca.Cert).NotTo(BeNil())
			Expect(ca.Cert.Subject.CommonName).To(Equal("NovoG93 Signer CA"))
		})
	})

	Describe("TestNewCAIsRoot", func() {
		It("should set certificate as CA with no path length constraint", func() {
			ca, err := NewCA()

			Expect(err).NotTo(HaveOccurred())
			Expect(ca).NotTo(BeNil())
			Expect(ca.Cert).NotTo(BeNil())
			Expect(ca.Cert.IsCA).To(BeTrue())
			Expect(ca.Cert.MaxPathLen).To(Equal(-1))
		})
	})

	Describe("TestNewCAValidityPeriod", func() {
		It("should set certificate validity to 10 years", func() {
			before := time.Now()
			ca, err := NewCA()
			after := time.Now()

			Expect(err).NotTo(HaveOccurred())
			Expect(ca).NotTo(BeNil())
			Expect(ca.Cert).NotTo(BeNil())

			// NotBefore should be approximately now (within 1 second)
			Expect(ca.Cert.NotBefore.After(before.Add(-time.Second))).To(BeTrue())
			Expect(ca.Cert.NotBefore.Before(after.Add(time.Second))).To(BeTrue())

			// NotAfter should be approximately 10 years in future
			expectedNotAfter := before.AddDate(10, 0, 0)
			Expect(ca.Cert.NotAfter.After(expectedNotAfter.Add(-time.Minute))).To(BeTrue())
			Expect(ca.Cert.NotAfter.Before(expectedNotAfter.Add(time.Minute))).To(BeTrue())
		})
	})
})

var _ = Describe("Reconciler Filtering", func() {
	var (
		scheme *runtime.Scheme
		ctx    context.Context
	)

	BeforeEach(func() {
		// Setup scheme with required APIs
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()
	})

	Describe("TestReconcileIgnoresOtherSigners", func() {
		It("should ignore requests from other signers and return no error", func() {
			// Create a PCR with a different signer
			pubKey, _, err := generateTestPublicKeyPEM()
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-other-signer",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "kubernetes.io/kubelet-serving",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      pubKey,
					ProofOfPossession:  []byte("some-proof"),
				},
			}

			// Create fake client with the PCR
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				Build()

			// Create reconciler with fake client
			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-other-signer",
					Namespace: "default",
				},
			})

			// Should return no error and no requeue
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))

			// Verify the PCR is unchanged
			retrieved := &certificatesv1beta1.PodCertificateRequest{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      "test-pcr-other-signer",
				Namespace: "default",
			}, retrieved)
			Expect(err).NotTo(HaveOccurred())

			// Status should still be empty
			Expect(retrieved.Status.CertificateChain).To(Equal(""))
			Expect(retrieved.Status.Conditions).To(HaveLen(0))
		})
	})

	Describe("TestReconcileIgnoresAlreadySigned", func() {
		It("should ignore already-signed requests for our signer", func() {
			// Create a PCR with our signer but already signed
			dummyCert := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHfzfCKvWQMA0GCSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCExh\nYlNpZ25lclJvb3QwHhcNMjEwNzIxMTgzODEwWhcNMzEwNzE5MTgzODEwWjATMREw\nDwYDVQQDDAhMYWJTaWduZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPFk\nZ1w5s3Y6+LcUzXsWKmVZBgjhFMU2P0c7lxj7W3sW3QKkfSIJWaWLQ8FfNgCWJkkK\n8L6K7HJA7zB6dRFwYW8+N3tMwIABjELcA83ynHZj0/kJ0cQmxQnuPQO4B1EiQxLd\nL5a/wE+3qKKRvB6KSqGsKVf1C0VUDc5XkrFQ7qApAgMBAAEwDQYJKoZIhvcNAQEF\nBQADgYEARN6UJPvJmLhP5N9qJaW5c9NLGpKDg6o4PNPF5GLkFvBL7AiKRQ7A0U2p\nPf8IlUzF3fT/TvLgZBJ7k5/m7kC82bZ3zJ7gHKQJCKqKCVHf3Rk/N3KrJ/+LaLAW\nsL7YhO3DqWdCJ8C9aGe0JTR1K5nfKQ9VqKzRx1aDhEeIIDSLuGM=\n-----END CERTIFICATE-----"
			pubKey, _, err := generateTestPublicKeyPEM()
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-already-signed",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer", // Our signer
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      pubKey,
					ProofOfPossession:  []byte("some-proof"),
				},
				Status: certificatesv1beta1.PodCertificateRequestStatus{
					CertificateChain: dummyCert,
				},
			}

			// Create fake client with the PCR
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				Build()

			// Create reconciler with fake client
			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-already-signed",
					Namespace: "default",
				},
			})

			// Should return no error and no requeue
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))

			// Verify the PCR is unchanged
			retrieved := &certificatesv1beta1.PodCertificateRequest{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      "test-pcr-already-signed",
				Namespace: "default",
			}, retrieved)
			Expect(err).NotTo(HaveOccurred())

			// Status should still have the original dummy certificate
			Expect(retrieved.Status.CertificateChain).To(Equal(dummyCert))
		})
	})

	Describe("TestReconcileProcessesTargetSigner", func() {
		It("should attempt to process requests from our signer when not yet signed", func() {
			// Create a PCR with our signer and NO certificate yet
			// Use DER format - this matches what Kubernetes kubelet sends (after base64 decoding)
			pubKeyDER, privKey, err := generateTestPublicKeyDER()
			Expect(err).NotTo(HaveOccurred())
			pop, err := generateRSASignature(pubKeyDER, privKey)
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-to-sign",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer", // Our signer
					PodName:            "example-pod",
					PodUID:             "pod-uid-12345",
					NodeName:           "node-1",
					NodeUID:            "node-uid-67890",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid-abc",
					PKIXPublicKey:      pubKeyDER,
					ProofOfPossession:  []byte(pop),
				},
				Status: certificatesv1beta1.PodCertificateRequestStatus{
					CertificateChain: "", // Not yet signed
				},
			}

			// Create fake client with the PCR
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr). // Enable status subresource support
				Build()

			// Create reconciler with fake client and CA
			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-to-sign",
					Namespace: "default",
				},
			})

			// Should return no error and no requeue
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))

			// Verify the PCR has been updated with a certificate
			retrieved := &certificatesv1beta1.PodCertificateRequest{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      "test-pcr-to-sign",
				Namespace: "default",
			}, retrieved)
			Expect(err).NotTo(HaveOccurred())

			// Status should now have a certificate
			Expect(retrieved.Status.CertificateChain).NotTo(Equal(""))
			Expect(retrieved.Status.CertificateChain).To(ContainSubstring("BEGIN CERTIFICATE"))
			Expect(retrieved.Status.CertificateChain).To(ContainSubstring("END CERTIFICATE"))

			// Should have conditions set
			Expect(retrieved.Status.Conditions).NotTo(HaveLen(0))
			Expect(retrieved.Status.Conditions[0].Type).To(Equal("Issued"))

			// Should have timing fields set
			Expect(retrieved.Status.NotBefore).NotTo(BeNil())
			Expect(retrieved.Status.NotAfter).NotTo(BeNil())
			Expect(retrieved.Status.BeginRefreshAt).NotTo(BeNil())
		})
	})
})

// MockClient for error simulation
type MockClient struct {
	client.Client
	MockGet          func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
	MockStatusUpdate func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error
}

func (m *MockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if m.MockGet != nil {
		return m.MockGet(ctx, key, obj, opts...)
	}
	return m.Client.Get(ctx, key, obj, opts...) // Fallback to inner client
}

func (m *MockClient) Status() client.StatusWriter {
	return &MockStatusWriter{
		StatusWriter: m.Client.Status(),
		Parent:       m,
	}
}

type MockStatusWriter struct {
	client.StatusWriter
	Parent *MockClient
}

func (m *MockStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if m.Parent.MockStatusUpdate != nil {
		return m.Parent.MockStatusUpdate(ctx, obj, opts...)
	}
	return m.StatusWriter.Update(ctx, obj, opts...)
}

var _ = Describe("Reconciler Error Handling", func() {
	var (
		scheme *runtime.Scheme
		ctx    context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()
	})

	Describe("TestReconcile_InvalidPublicKey", func() {
		It("should return an error when public key is invalid", func() {
			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-invalid-key",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      []byte("invalid-key-garbage"),
					ProofOfPossession:  []byte("some-proof"),
				},
			}

			// Create fake client with the PCR
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				Build()

			// Create reconciler with fake client
			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-invalid-key",
					Namespace: "default",
				},
			})

			// Should return error
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to parse PKIX public key"))
		})
	})

	Describe("TestReconcile_GetError", func() {
		It("should return error when Get fails with non-NotFound error", func() {
			mockErr := fmt.Errorf("connection refused")
			mockClient := &MockClient{
				Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
				MockGet: func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					return mockErr
				},
			}

			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     mockClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "whatever", Namespace: "default"},
			})

			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(mockErr))
		})

		It("should ignore NotFound error during Get", func() {
			// Fake client returns NotFound by default
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			_, errCalled := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "missing-pcr", Namespace: "default"},
			})

			Expect(errCalled).NotTo(HaveOccurred())
		})
	})

	Describe("TestReconcile_UpdateStatusError", func() {
		It("should return error when Status Update fails", func() {
			pubKeyDER, privKey, err := generateTestPublicKeyDER()
			Expect(err).NotTo(HaveOccurred())
			pop, err := generateRSASignature(pubKeyDER, privKey)
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-update-fail",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      pubKeyDER,
					ProofOfPossession:  []byte(pop),
				},
			}

			innerClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()

			updateErr := fmt.Errorf("failed to update status")
			mockClient := &MockClient{
				Client: innerClient,
				MockStatusUpdate: func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					return updateErr
				},
			}

			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     mockClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-update-fail",
					Namespace: "default",
				},
			})

			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(updateErr))
		})
	})

	Describe("TestReconcile_ParseKeyError_SetsCondition", func() {
		It("should set Failed condition when public key parsing fails", func() {
			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-invalid-key-condition",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      []byte("invalid-key-garbage"),
					ProofOfPossession:  []byte("some-proof"),
				},
			}

			// Create fake client with the PCR
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()

			// Create reconciler with fake client
			ca, errCA := NewCA()
			Expect(errCA).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     fakeClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-invalid-key-condition",
					Namespace: "default",
				},
			})

			// Should return error but also set condition
			Expect(err).To(HaveOccurred())

			// Retrieve the PCR and check condition was set
			retrieved := &certificatesv1beta1.PodCertificateRequest{}
			errGet := fakeClient.Get(ctx, types.NamespacedName{
				Name:      "test-pcr-invalid-key-condition",
				Namespace: "default",
			}, retrieved)
			Expect(errGet).NotTo(HaveOccurred())

			// Status should have a Failed condition
			Expect(retrieved.Status.Conditions).NotTo(HaveLen(0))
			foundCondition := false
			for _, cond := range retrieved.Status.Conditions {
				if cond.Type == "Issued" && cond.Status == metav1.ConditionFalse {
					foundCondition = true
					Expect(cond.Reason).To(Equal("InvalidPublicKey"))
					break
				}
			}
			Expect(foundCondition).To(BeTrue(), "Expected to find Failed Issued condition with InvalidPublicKey reason")
		})
	})

	Describe("TestReconcile_SigningError_SetsCondition", func() {
		It("should set Failed condition when certificate signing fails", func() {
			pubKeyDER, privKey, err := generateTestPublicKeyDER()
			Expect(err).NotTo(HaveOccurred())
			pop, err := generateRSASignature(pubKeyDER, privKey)
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-signing-error",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      pubKeyDER,
					ProofOfPossession:  []byte(pop),
				},
			}

			innerClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()

			// Create a reconciler with a broken CA to cause signing to fail
			reconciler := &SignerReconciler{
				Client:     innerClient,
				CA:         nil, // Null CA will cause signing to fail
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile
			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-signing-error",
					Namespace: "default",
				},
			})

			// Should return error
			Expect(err).To(HaveOccurred())

			// Retrieve the PCR and check condition was set
			retrieved := &certificatesv1beta1.PodCertificateRequest{}
			errGet := innerClient.Get(ctx, types.NamespacedName{
				Name:      "test-pcr-signing-error",
				Namespace: "default",
			}, retrieved)
			Expect(errGet).NotTo(HaveOccurred())

			// Status should have a Failed condition
			Expect(retrieved.Status.Conditions).NotTo(HaveLen(0))
			foundCondition := false
			for _, cond := range retrieved.Status.Conditions {
				if cond.Type == "Issued" && cond.Status == metav1.ConditionFalse {
					foundCondition = true
					Expect(cond.Reason).To(Equal("SigningFailed"))
					break
				}
			}
			Expect(foundCondition).To(BeTrue(), "Expected to find Failed Issued condition with SigningFailed reason")
		})
	})

	Describe("TestReconcile_StatusUpdateConflict_Retries", func() {
		It("should retry with backoff when status update conflicts", func() {
			pubKeyDER, privKey, err := generateTestPublicKeyDER()
			Expect(err).NotTo(HaveOccurred())
			pop, err := generateRSASignature(pubKeyDER, privKey)
			Expect(err).NotTo(HaveOccurred())

			pcr := &certificatesv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pcr-conflict",
					Namespace: "default",
				},
				Spec: certificatesv1beta1.PodCertificateRequestSpec{
					SignerName:         "novog93.ghcr/signer",
					PodName:            "test-pod",
					PodUID:             "test-uid",
					NodeName:           "test-node",
					NodeUID:            "test-node-uid",
					ServiceAccountName: "default",
					ServiceAccountUID:  "sa-uid",
					PKIXPublicKey:      pubKeyDER,
					ProofOfPossession:  []byte(pop),
				},
			}

			innerClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()

			// Create a mock client that fails on first update, succeeds on second
			callCount := 0
			mockClient := &MockClient{
				Client: innerClient,
				MockStatusUpdate: func(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					callCount++
					if callCount == 1 {
						// First call: conflict
						return apierrors.NewConflict(schema.GroupResource{}, "test-pcr-conflict", fmt.Errorf("resource version mismatch"))
					}
					// Second call: success - use inner client
					return innerClient.Status().Update(ctx, obj, opts...)
				},
			}

			ca, err := NewCA()
			Expect(err).NotTo(HaveOccurred())

			reconciler := &SignerReconciler{
				Client:     mockClient,
				CA:         ca,
				SignerName: "novog93.ghcr/signer",
			}

			// Call Reconcile - should succeed despite conflict
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-pcr-conflict",
					Namespace: "default",
				},
			})

			// The call should eventually succeed (after internal retries via RetryOnConflict)
			// If retry.RetryOnConflict works correctly, err should be nil
			Expect(err).NotTo(HaveOccurred(), "Expected reconciliation to succeed after retry")
			Expect(result.Requeue).To(BeFalse())

			// Verify the mock was called at least once (and ideally twice due to retry)
			Expect(callCount).To(BeNumerically(">=", 1), "Mock should be called at least once")
		})
	})
})

var _ = Describe("Reconciler Policy", func() {
	var (
		scheme     *runtime.Scheme
		ctx        context.Context
		pubKeyDER  []byte
		pop        string
		reconciler *SignerReconciler
		clientFunc func(*certificatesv1beta1.PodCertificateRequest) client.Client
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()

		var err error
		var privKey *rsa.PrivateKey
		pubKeyDER, privKey, err = generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())
		pop, err = generateRSASignature(pubKeyDER, privKey)
		Expect(err).NotTo(HaveOccurred())

		ca, err := NewCA()
		Expect(err).NotTo(HaveOccurred())

		reconciler = &SignerReconciler{
			CA:         ca,
			SignerName: "novog93.ghcr/signer",
			Config: &Config{
				CertValidity:      time.Hour,
				CertRefreshBefore: 30 * time.Minute,
			},
		}

		clientFunc = func(pcr *certificatesv1beta1.PodCertificateRequest) client.Client {
			return fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()
		}
	})

	It("Reconcile_Respects_MaxExpirationSeconds", func() {
		// Create PCR spec with maxExpirationSeconds=1800 (30 mins)
		duration := int32(1800)
		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pcr-max-expiration",
				Namespace: "default",
			},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:           "novog93.ghcr/signer",
				PodName:              "test-pod",
				PodUID:               "test-uid",
				NodeName:             "test-node",
				NodeUID:              "test-node-uid",
				ServiceAccountName:   "default",
				ServiceAccountUID:    "sa-uid",
				PKIXPublicKey:        pubKeyDER,
				ProofOfPossession:    []byte(pop),
				MaxExpirationSeconds: &duration,
			},
		}

		reconciler.Client = clientFunc(pcr)

		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace},
		})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		// Assert notAfter is capped by maxExpirationSeconds (30m)
		diff := retrieved.Status.NotAfter.Time.Sub(time.Now())
		Expect(diff).To(BeNumerically("<=", 30*time.Minute+5*time.Second))
		Expect(diff).To(BeNumerically(">", 29*time.Minute))
	})

	It("Reconcile_Uses_Configured_Validity", func() {
		// Set config.CertValidity = 2h
		reconciler.Config.CertValidity = 2 * time.Hour

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pcr-config-validity",
				Namespace: "default",
			},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PodUID:             "test-uid",
				NodeName:           "test-node",
				NodeUID:            "test-node-uid",
				ServiceAccountName: "default",
				ServiceAccountUID:  "sa-uid",
				PKIXPublicKey:      pubKeyDER,
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)

		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace},
		})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		// Reconcile should set notAfter = now + 2h
		diff := retrieved.Status.NotAfter.Time.Sub(time.Now())
		Expect(diff).To(BeNumerically("~", 2*time.Hour, 5*time.Second))
	})

	It("Reconcile_Uses_Configured_Refresh", func() {
		// Set config.CertRefreshBefore = 45m
		reconciler.Config.CertValidity = 2 * time.Hour
		reconciler.Config.CertRefreshBefore = 45 * time.Minute

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pcr-config-refresh",
				Namespace: "default",
			},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PodUID:             "test-uid",
				NodeName:           "test-node",
				NodeUID:            "test-node-uid",
				ServiceAccountName: "default",
				ServiceAccountUID:  "sa-uid",
				PKIXPublicKey:      pubKeyDER,
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)

		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace},
		})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		// Reconcile should set beginRefreshAt = notAfter - 45m
		expectedRefreshDuration := (2 * time.Hour) - (45 * time.Minute)
		diff := retrieved.Status.BeginRefreshAt.Time.Sub(time.Now())
		Expect(diff).To(BeNumerically("~", expectedRefreshDuration, 5*time.Second))
	})

	It("Reconcile_Refresh_Within_Bounds", func() {
		// Should never allow refresh before notBefore or after notAfter
		reconciler.Config.CertValidity = 10 * time.Minute
		reconciler.Config.CertRefreshBefore = 20 * time.Minute

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pcr-refresh-bounds",
				Namespace: "default",
			},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PodUID:             "test-uid",
				NodeName:           "test-node",
				NodeUID:            "test-node-uid",
				ServiceAccountName: "default",
				ServiceAccountUID:  "sa-uid",
				PKIXPublicKey:      pubKeyDER,
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)

		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace},
		})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		// Check NotBefore <= BeginRefreshAt
		Expect(retrieved.Status.BeginRefreshAt.Time.Before(retrieved.Status.NotBefore.Time)).To(BeFalse(), "BeginRefreshAt should not be before NotBefore")

		// Check BeginRefreshAt <= NotAfter
		Expect(retrieved.Status.BeginRefreshAt.Time.After(retrieved.Status.NotAfter.Time)).To(BeFalse(), "BeginRefreshAt should not be after NotAfter")
	})

	It("Reconcile_Enforces_Min_CertValidity", func() {
		// Create a config with validity < 1h (e.g., 30m)
		pubKeyDER, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKeyDER, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "minvalidity", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PKIXPublicKey:      pubKeyDER,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		ca, err := NewCA()
		Expect(err).NotTo(HaveOccurred())

		// Create reconciler with too-low validity (30m)
		reconciler := &SignerReconciler{
			CA:         ca,
			SignerName: "novog93.ghcr/signer",
			Config: &Config{
				CertValidity:      30 * time.Minute, // Too low!
				CertRefreshBefore: 30 * time.Minute,
			},
		}

		clientFunc := func(pcrObj *certificatesv1beta1.PodCertificateRequest) client.Client {
			return fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcrObj).
				WithStatusSubresource(pcrObj).
				Build()
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())

		// Despite config saying 30m, the cert should be issued with minimum 1h
		notAfter := cert.NotAfter
		now := time.Now()
		diff := notAfter.Sub(now)

		// Should be approx 1h (allowing for time drift in test execution)
		Expect(diff).To(BeNumerically(">", 59*time.Minute))
		Expect(diff).To(BeNumerically("<", 61*time.Minute))
	})

	It("Reconcile_Enforces_Min_CertRefreshBefore", func() {
		// Create a config with refresh < 30m (e.g., 5m)
		pubKeyDER, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKeyDER, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "minrefresh", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PKIXPublicKey:      pubKeyDER,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		ca, err := NewCA()
		Expect(err).NotTo(HaveOccurred())

		// Create reconciler with too-low refresh (5m)
		reconciler := &SignerReconciler{
			CA:         ca,
			SignerName: "novog93.ghcr/signer",
			Config: &Config{
				CertValidity:      time.Hour,       // OK
				CertRefreshBefore: 5 * time.Minute, // Too low!
			},
		}

		clientFunc := func(pcrObj *certificatesv1beta1.PodCertificateRequest) client.Client {
			return fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcrObj).
				WithStatusSubresource(pcrObj).
				Build()
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())

		// Despite config saying 5m refresh, should be 30m
		notAfter := cert.NotAfter
		beginRefresh := retrieved.Status.BeginRefreshAt.Time

		// beginRefreshAt should be notAfter - 30m (minimum refresh)
		expectedRefresh := notAfter.Add(-30 * time.Minute)

		// Allow small time drift
		diff := beginRefresh.Sub(expectedRefresh)
		if diff < 0 {
			diff = -diff
		}
		Expect(diff).To(BeNumerically("<", 5*time.Second))
	})
})

// Helper to parse the PEM certificate string from status
func parseCertificateFromStatus(certChain string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certChain))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// generateTestPublicKeyDERECDSA creates a test ECDSA public key in DER format
func generateTestPublicKeyDERECDSA() ([]byte, *ecdsa.PrivateKey, error) {
	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privateKey, nil
}

var _ = Describe("SANs and Key Types", func() {
	var (
		scheme     *runtime.Scheme
		ctx        context.Context
		reconciler *SignerReconciler
		clientFunc func(*certificatesv1beta1.PodCertificateRequest) client.Client
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()

		ca, err := NewCA()
		Expect(err).NotTo(HaveOccurred())

		reconciler = &SignerReconciler{
			CA:         ca,
			SignerName: "novog93.ghcr/signer",
			Config:     &Config{}, // Default config
		}

		clientFunc = func(pcr *certificatesv1beta1.PodCertificateRequest) client.Client {
			return fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(pcr).
				Build()
		}
	})

	It("SignCertificate_AddsDNSSAN", func() {
		pubKey, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "santest", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:    "novog93.ghcr/signer",
				PodName:       "test-pod-dns",
				PKIXPublicKey: pubKey,
				// Required fields
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())

		// Verify DNS SANs
		Expect(cert.DNSNames).To(ContainElement("test-pod-dns.pod.cluster.local"))
	})

	It("SignCertificate_SetsSubjectCNToPodName", func() {
		pubKey, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "cntest", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:    "novog93.ghcr/signer",
				PodName:       "my-pod-cn",
				PKIXPublicKey: pubKey,
				// Required fields
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())

		// Verify CommonName
		Expect(cert.Subject.CommonName).To(Equal("my-pod-cn.pod.cluster.local"))
	})

	It("SignCertificate_SupportsRSAKeys", func() {
		// Existing tests cover this, but explicit test ensures no regression
		pubKey, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "rsatest", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "rsa-pod",
				PKIXPublicKey:      pubKey,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.PublicKeyAlgorithm).To(Equal(x509.RSA))
	})

	It("SignCertificate_SupportsECDSAKeys", func() {
		pubKey, privKey, err := generateTestPublicKeyDERECDSA()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateECDSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "ecdsatest", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "ecdsa-pod",
				PKIXPublicKey:      pubKey,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.PublicKeyAlgorithm).To(Equal(x509.ECDSA))
	})

	It("SignCertificate_SetsProperKeyUsage", func() {
		pubKey, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())

		pop, err := generateRSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "keyusagetest", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "usage-pod",
				PKIXPublicKey:      pubKey,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = clientFunc(pcr)
		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		err = reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)
		Expect(err).NotTo(HaveOccurred())

		cert, err := parseCertificateFromStatus(retrieved.Status.CertificateChain)
		Expect(err).NotTo(HaveOccurred())

		// ExtKeyUsage
		Expect(cert.ExtKeyUsage).To(ContainElement(x509.ExtKeyUsageClientAuth))
		Expect(cert.ExtKeyUsage).To(ContainElement(x509.ExtKeyUsageServerAuth))

		// KeyUsage
		// Should include DigitalSignature (1)
		Expect(cert.KeyUsage & x509.KeyUsageDigitalSignature).To(Equal(x509.KeyUsageDigitalSignature))
	})
})

// base64UrlEncode encodes data without padding
func base64UrlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func generateRSASignature(pubKeyBytes []byte, privateKey *rsa.PrivateKey) (string, error) {
	// Hash the public key bytes (this is what kubelet signs for POP)
	hash := sha256.Sum256(pubKeyBytes)

	// Sign with RSA PKCS#1 v1.5
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	// Return as base64-encoded string (not base64url, matching kubelet behavior)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func generateECDSASignature(pubKeyBytes []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	// Hash the public key bytes (this is what kubelet signs for POP)
	hash := sha256.Sum256(pubKeyBytes)

	// Sign with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Encode r and s into fixed-width byte arrays (32 bytes each for P-256)
	curveBits := privateKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	signature := append(rBytesPadded, sBytesPadded...)

	// Return as base64-encoded string (not base64url)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func getCounterVecValue(counter *prometheus.CounterVec, labelValues ...string) float64 {
	metric := counter.WithLabelValues(labelValues...)
	var m dto.Metric
	metric.Write(&m)
	return m.GetCounter().GetValue()
}

var _ = Describe("Metrics", func() {
	var (
		scheme     *runtime.Scheme
		ctx        context.Context
		reconciler *SignerReconciler
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()

		ca, err := NewCA()
		Expect(err).NotTo(HaveOccurred())

		reconciler = &SignerReconciler{
			CA:         ca,
			SignerName: "novog93.ghcr/signer",
		}
	})

	It("Metrics_IssuedCounterIncrements", func() {
		// Reset counter if possible, or just read start value
		// Since we can't easily reset a package level var without exposing a method, we read current value
		startVal := getCounterVecValue(IssuedCounter, "1h0m0s")

		pubKey, privKey, err := generateTestPublicKeyDER()
		Expect(err).NotTo(HaveOccurred())
		pop, err := generateRSASignature(pubKey, privKey)
		Expect(err).NotTo(HaveOccurred())

		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "metrics-issued", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PKIXPublicKey:      pubKey,
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte(pop),
			},
		}

		reconciler.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pcr).
			WithStatusSubresource(pcr).
			Build()

		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})
		Expect(err).NotTo(HaveOccurred())

		// Verify counter incremented
		endVal := getCounterVecValue(IssuedCounter, "1h0m0s")
		Expect(endVal).To(Equal(startVal + 1))
	})

	It("Metrics_FailedCounterIncrements", func() {
		pcr := &certificatesv1beta1.PodCertificateRequest{
			ObjectMeta: metav1.ObjectMeta{Name: "metrics-failed", Namespace: "default"},
			Spec: certificatesv1beta1.PodCertificateRequestSpec{
				SignerName:         "novog93.ghcr/signer",
				PodName:            "test-pod",
				PKIXPublicKey:      []byte("invalid-key"),
				NodeName:           "node1",
				NodeUID:            "node-uid",
				PodUID:             "pod-uid",
				ServiceAccountName: "sa",
				ServiceAccountUID:  "sa-uid",
				ProofOfPossession:  []byte("pop"),
			},
		}

		reconciler.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pcr).
			WithStatusSubresource(pcr).
			Build()

		// Reconciliation will fail with InvalidPublicKey
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}})

		// Verify the error occurred
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to parse PKIX public key"))

		// Retrieve the PCR to get the actual reason from the condition
		retrieved := &certificatesv1beta1.PodCertificateRequest{}
		Expect(reconciler.Client.Get(ctx, types.NamespacedName{Name: pcr.Name, Namespace: pcr.Namespace}, retrieved)).To(Succeed())

		// Extract the actual reason from the condition set by setFailedCondition
		Expect(retrieved.Status.Conditions).To(HaveLen(1))
		reason := retrieved.Status.Conditions[0].Reason

		// Verify the counter was incremented with the actual reason
		endVal := getCounterVecValue(FailedCounter, reason)
		Expect(endVal).To(BeNumerically(">", 0))
	})
})
