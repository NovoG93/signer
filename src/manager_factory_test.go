package main

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var _ = Describe("ManagerFactory Unit", func() {
	BeforeEach(func() {
		// Test setup if needed
	})

	It("should return error if config is nil", func() {
		_, err := CreateManager(nil, nil)
		Expect(err).To(HaveOccurred())
	})

	It("TestCreateManager_AcceptsConfig", func() {
		// Mock manager creation to inspect options
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		var capturedOptions ctrl.Options
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			capturedOptions = options
			return &mockManager{}, nil
		}

		// Mock CA creation
		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		// Mock SetupWithManager
		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager) error {
			return nil
		}

		customConfig := &Config{
			LeaderElection:         true,
			LeaderElectionID:       "test-id",
			MetricsBindAddress:     ":9999",
			HealthProbeBindAddress: ":8888",
			SignerName:             "test-signer",
		}

		_, err := CreateManager(&rest.Config{}, customConfig)
		Expect(err).NotTo(HaveOccurred())

		Expect(capturedOptions.LeaderElection).To(BeTrue())
		Expect(capturedOptions.LeaderElectionID).To(Equal("test-id"))
		Expect(capturedOptions.HealthProbeBindAddress).To(Equal(":8888"))
	})

	It("TestCreateManager_PassesConfigToReconciler", func() {
		// Mock manager creation
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()
		newManagerFunc = func(restConfig *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		// Mock CA creation
		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()
		newCAFunc = func() (*CAHelper, error) {
			return &CAHelper{}, nil
		}

		// Mock SetupWithManager to capture the reconciler
		origSetupFunc := setupWithManagerFunc
		defer func() { setupWithManagerFunc = origSetupFunc }()

		var capturedReconciler *SignerReconciler
		setupWithManagerFunc = func(r *SignerReconciler, mgr ctrl.Manager) error {
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
})

// mockManager implements ctrl.Manager for testing
type mockManager struct {
	ctrl.Manager
	addHealthzCheckErr error
	addReadyzCheckErr  error
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

func (m *mockManager) Start(ctx context.Context) error {
	return nil
}
