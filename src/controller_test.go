package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

// generateTestPublicKeyDER creates a test RSA public key in DER format (PKIX)
func generateTestPublicKeyDER() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubBytes, nil
}

// generateTestPublicKeyPEM creates a test RSA public key in PEM format (as []byte)
// This matches what Kubernetes kubelet sends in PodCertificateRequest.Spec.PKIXPublicKey (after base64 decoding)
func generateTestPublicKeyPEM() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// Encode as PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return pemBytes, nil
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
			pubKey, err := generateTestPublicKeyPEM()
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
			pubKey, err := generateTestPublicKeyPEM()
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
			pubKeyDER, err := generateTestPublicKeyDER()
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
					ProofOfPossession:  []byte("some-proof"),
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
			pubKeyDER, err := generateTestPublicKeyDER()
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
					ProofOfPossession:  []byte("some-proof"),
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
})

var _ = Describe("Reconciler Policy", func() {
	var (
		scheme     *runtime.Scheme
		ctx        context.Context
		pubKeyDER  []byte
		reconciler *SignerReconciler
		clientFunc func(*certificatesv1beta1.PodCertificateRequest) client.Client
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		utilruntime.Must(certificatesv1beta1.AddToScheme(scheme))
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		ctx = context.Background()

		var err error
		pubKeyDER, err = generateTestPublicKeyDER()
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
				ProofOfPossession:    []byte("some-proof"),
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
				ProofOfPossession:  []byte("some-proof"),
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
				ProofOfPossession:  []byte("some-proof"),
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
				ProofOfPossession:  []byte("some-proof"),
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
func generateTestPublicKeyDERECDSA() ([]byte, error) {
	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// Export public key in PKIX/DER format
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubBytes, nil
}

var _ = Describe("Phase 5: SANs and Key Types", func() {
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
		pubKey, err := generateTestPublicKeyDER()
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
				ProofOfPossession:  []byte("pop"),
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
		pubKey, err := generateTestPublicKeyDER()
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
				ProofOfPossession:  []byte("pop"),
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
		pubKey, err := generateTestPublicKeyDER()
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
				ProofOfPossession:  []byte("pop"),
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
		pubKey, err := generateTestPublicKeyDERECDSA()
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
				ProofOfPossession:  []byte("pop"),
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
		pubKey, err := generateTestPublicKeyDER()
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
				ProofOfPossession:  []byte("pop"),
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
