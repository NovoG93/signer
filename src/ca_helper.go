package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// NewCA generates an in-memory self-signed root CA certificate for the novog93/signer.
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
