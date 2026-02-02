package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var _ = Describe("ManagerFactory Unit", func() {
	It("should return error if config is nil", func() {
		_, err := CreateManager(nil, nil)
		Expect(err).To(HaveOccurred())
	})

	It("TestCreateManager_LeaderElectionEnabled", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		var capturedOptions ctrl.Options
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			capturedOptions = options
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			return nil
		}

		customConfig := &Config{
			LeaderElection:          true,
			LeaderElectionID:        "test-id",
			LeaderElectionNamespace: "test-ns",
			MetricsBindAddress:      ":9999",
			HealthProbeBindAddress:  ":8888",
			SignerName:              "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, customConfig)
		Expect(err).NotTo(HaveOccurred())

		Expect(capturedOptions.LeaderElection).To(BeTrue())
		Expect(capturedOptions.LeaderElectionID).To(Equal("test-id"))
		Expect(capturedOptions.LeaderElectionNamespace).To(Equal("test-ns"))
		Expect(capturedOptions.HealthProbeBindAddress).To(Equal(":8888"))
	})

	It("TestCreateManager_LeaderElectionDisabled", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		var capturedOptions ctrl.Options
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			capturedOptions = options
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			return nil
		}

		customConfig := &Config{
			LeaderElection:         false,
			LeaderElectionID:       "test-id",
			MetricsBindAddress:     ":9999",
			HealthProbeBindAddress: ":8888",
			SignerName:             "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, customConfig)
		Expect(err).NotTo(HaveOccurred())

		Expect(capturedOptions.LeaderElection).To(BeFalse())
	})

	It("TestCreateManager_PassesConfigToReconciler", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()

		var capturedReconciler *SignerReconciler
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			capturedReconciler = r
			return nil
		}

		testConfig := &Config{
			CertValidity:      2 * time.Hour,
			CertRefreshBefore: 15 * time.Minute,
			SignerName:        "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedReconciler).NotTo(BeNil())
		Expect(capturedReconciler.Config).To(Equal(testConfig))
	})

	It("TestCreateManager_SetupSecretWatcher", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		fakeSecret := createFakeSecret("test-secret", "test-ns")
		scheme := runtime.NewScheme()
		_ = clientgoscheme.AddToScheme(scheme)
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(fakeSecret).Build()

		fakeManager := &mockManager{
			apiReader: fakeClient,
		}
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return fakeManager, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			return nil
		}

		origSetupSecretFunc := setupSecretWatcherFunc
		defer func() { setupSecretWatcherFunc = origSetupSecretFunc }()
		secretWatcherCalled := false
		setupSecretWatcherFunc = func(mgr ctrl.Manager, ca *CAHelper, config *Config) error {
			secretWatcherCalled = true
			return nil
		}

		testConfig := &Config{
			CASecretName:      "test-secret",
			CASecretNamespace: "test-ns",
			SignerName:        "test-signer",
			CACertKey:         "ca.crt",
			CAKeyKey:          "ca.key",
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(secretWatcherCalled).To(BeTrue())
	})

	It("TestCreateManager_NoSecretWatcher", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			return nil
		}

		origSetupSecretFunc := setupSecretWatcherFunc
		defer func() { setupSecretWatcherFunc = origSetupSecretFunc }()
		secretWatcherCalled := false
		setupSecretWatcherFunc = func(mgr ctrl.Manager, ca *CAHelper, config *Config) error {
			secretWatcherCalled = true
			return nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		testConfig := &Config{
			CASecretName: "",
			SignerName:   "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(secretWatcherCalled).To(BeFalse())
	})

	It("TestCreateManager_UsesMetricsBindAddress", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		var capturedOptions ctrl.Options
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			capturedOptions = options
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			return nil
		}

		testConfig := &Config{
			MetricsBindAddress: ":1234",
			SignerName:         "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedOptions.Metrics.BindAddress).To(Equal(":1234"))
	})

	It("Manager_UsesMaxConcurrentReconciles", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()

		var capturedOptions controller.Options
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			capturedOptions = opts
			return nil
		}

		testConfig := &Config{
			SignerName:              "test-signer",
			MaxConcurrentReconciles: 5,
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedOptions.MaxConcurrentReconciles).To(Equal(5))
	})

	It("Manager_UsesRateLimiter", func() {
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()

		var capturedOptions controller.Options
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager, opts controller.Options) error {
			capturedOptions = opts
			return nil
		}

		testConfig := &Config{
			SignerName:              "test-signer",
			MaxConcurrentReconciles: 1, // Ensure non-zero
		}

		_, err := CreateManager(&rest.Config{}, testConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(capturedOptions.RateLimiter).NotTo(BeNil())
	})
})

type mockManager struct {
	ctrl.Manager
	addHealthzCheckErr error
	addReadyzCheckErr  error
	apiReader          client.Reader
}

func (m *mockManager) AddHealthzCheck(name string, check healthz.Checker) error {
	return m.addHealthzCheckErr
}

func (m *mockManager) AddReadyzCheck(name string, check healthz.Checker) error {
	return m.addReadyzCheckErr
}

func (m *mockManager) GetClient() client.Client {
	return nil
}

func (m *mockManager) GetAPIReader() client.Reader {
	if m.apiReader != nil {
		return m.apiReader
	}
	// Fallback to empty fake client
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func (m *mockManager) Start(ctx context.Context) error {
	return nil
}

func createFakeSecret(name, namespace string) *corev1.Secret {
	// Generate valid cert/key
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data: map[string][]byte{
			"ca.crt": certPEM,
			"ca.key": keyPEM,
		},
	}
}
