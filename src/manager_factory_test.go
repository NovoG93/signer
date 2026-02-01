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
	"sigs.k8s.io/controller-runtime/pkg/envtest"
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
