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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CAHelper holds our Authority
type CAHelper struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
	mu   sync.RWMutex
}

// GetCert returns the current certificate in a thread-safe way
func (c *CAHelper) GetCert() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Cert
}

// GetKey returns the current private key in a thread-safe way
func (c *CAHelper) GetKey() *rsa.PrivateKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Key
}

// NewCAFromSecret loads CA from a secret.
func NewCAFromSecret(ctx context.Context, apiReader client.Reader, secretName, secretNamespace, certKey, keyKey string) (*CAHelper, error) {
	ca := &CAHelper{}
	if err := ca.LoadFromSecret(ctx, apiReader, secretName, secretNamespace, certKey, keyKey); err != nil {
		return nil, err
	}
	return ca, nil
}

// LoadFromSecret updates the CAHelper from a Kubernetes Secret.
func (c *CAHelper) LoadFromSecret(ctx context.Context, apiReader client.Reader, secretName, secretNamespace, certKey, keyKey string) error {
	var secret corev1.Secret
	if err := apiReader.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, &secret); err != nil {
		return fmt.Errorf("failed to get CA secret %s/%s: %w", secretNamespace, secretName, err)
	}

	certBytes, ok := secret.Data[certKey]
	if !ok {
		return fmt.Errorf("certificate key %s not found in secret", certKey)
	}
	keyBytes, ok := secret.Data[keyKey]
	if !ok {
		return fmt.Errorf("private key key %s not found in secret", keyKey)
	}

	// Parse PEM
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse Key
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	var key *rsa.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else if keyBlock.Type == "PRIVATE KEY" {
		// Try PKCS#8
		pk, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 == nil {
			var ok bool
			key, ok = pk.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("private key is not RSA")
			}
		} else {
			err = err2
		}
	} else {
		err = fmt.Errorf("unknown private key type: %s", keyBlock.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Cert = cert
	c.Key = key

	return nil
}

// NewCA generates an in-memory self-signed root CA certificate for the novog93.ghcr/signer.
// It creates an RSA 2048-bit private key and a corresponding x509 certificate
// with 10 year validity period. The certificate is suitable for signing child certificates.
//
// Returns:
// - *CAHelper: Contains the generated x509.Certificate and RSA private key
// - error: If key generation or certificate creation fails
func NewCA() (*CAHelper, error) {
	// Step 1: Generate RSA 2048-bit private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	// Step 2: Create the root CA certificate template
	now := time.Now()
	// Use small number logic from previous implementation
	// Note: previous implementation used big.Int Lsh 128.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "NovoG93 Signer CA",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0), // 10 years validity
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            -1, // No constraint on path length
	}

	// Step 3: Create the self-signed certificate
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template, // Self-signed: parent is same as template
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Step 4: Parse the created certificate bytes back into x509.Certificate struct
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return &CAHelper{
		Cert: cert,
		Key:  privateKey,
	}, nil
}
