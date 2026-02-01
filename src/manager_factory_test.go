package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var _ = Describe("ManagerFactory", func() {
	var (
		testEnv *envtest.Environment
		ctx     context.Context
		cancel  context.CancelFunc
		cfg     *rest.Config
	)

	BeforeEach(func() {
		// Skip if kubebuilder envtest binaries aren't installed
		// These are typically installed via: make envtest or setup-envtest
		envtestPath := os.Getenv("KUBEBUILDER_ASSETS")
		if envtestPath == "" {
			// Check default location
			if _, err := os.Stat("/usr/local/kubebuilder/bin/etcd"); os.IsNotExist(err) {
				Skip("Skipping: kubebuilder envtest binaries not installed. Set KUBEBUILDER_ASSETS or install via setup-envtest.")
			}
		}

		ctx, cancel = context.WithCancel(context.Background())
		testEnv = &envtest.Environment{
			// We don't have CRDs in the test environment for now,
			// so the Reconciler might fail to sync, but the Manager should start.
		}

		var err error
		cfg, err = testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).NotTo(BeNil())
	})

	AfterEach(func() {
		cancel()
		err := testEnv.Stop()
		Expect(err).NotTo(HaveOccurred())
	})

	It("should serve health probes", func() {
		// Create the manager using the factory
		mgr, err := CreateManager(cfg, "test-signer")
		Expect(err).NotTo(HaveOccurred())

		// Run manager in a goroutine
		go func() {
			defer GinkgoRecover() // Capture panics in goroutine
			// Manager.Start blocks
			if err := mgr.Start(ctx); err != nil {
				// We might expect some errors if CRDs are missing, but the web server should start?
				// If web server fails to bind, we want to know.
				fmt.Printf("Manager stopped with error: %v\n", err)
			}
		}()

		// Wait for the manager to be potentially ready or at least serving
		// We expect 200 OK from /healthz

		timeout := 5 * time.Second
		interval := 100 * time.Millisecond

		Eventually(func() int {
			resp, err := http.Get("http://localhost:8081/healthz")
			if err != nil {
				return 0 // Connection refused or other error
			}
			defer resp.Body.Close()
			return resp.StatusCode
		}, timeout, interval).Should(Equal(200), "Expected health probe to respond with 200 OK")
	})
})

var _ = Describe("ManagerFactory Unit", func() {
	It("should return error if config is nil", func() {
		// This uses the real newManagerFunc (ctrl.NewManager) which checks config
		_, err := CreateManager(nil, "test")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("must specify Config"))
	})

	It("should return error if AddHealthzCheck fails", func() {
		// Mock manager creation
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		newManagerFunc = func(config *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{
				addHealthzCheckErr: fmt.Errorf("healthz error"),
			}, nil
		}

		_, err := CreateManager(&rest.Config{}, "test")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("healthz error"))
	})

	It("should return error if AddReadyzCheck fails", func() {
		// Mock manager creation
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		newManagerFunc = func(config *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{
				addReadyzCheckErr: fmt.Errorf("readyz error"),
			}, nil
		}

		_, err := CreateManager(&rest.Config{}, "test")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("readyz error"))
	})

	It("should return error if NewCA fails", func() {
		// Mock manager creation
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		// Mock CA creation
		origNewCAFunc := newCAFunc
		defer func() { newCAFunc = origNewCAFunc }()

		newManagerFunc = func(config *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
			return &mockManager{}, nil
		}

		newCAFunc = func() (*CAHelper, error) {
			return nil, fmt.Errorf("ca error")
		}

		_, err := CreateManager(&rest.Config{}, "test")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("ca error"))
	})

	It("should return error if SetupWithManager fails", func() {
		// Mock manager creation
		origNewManagerFunc := newManagerFunc
		defer func() { newManagerFunc = origNewManagerFunc }()

		newManagerFunc = func(config *rest.Config, options ctrl.Options) (ctrl.Manager, error) {
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
			return fmt.Errorf("setup error")
		}

		_, err := CreateManager(&rest.Config{}, "test")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("setup error"))
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
