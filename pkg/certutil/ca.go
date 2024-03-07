package certutil

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"encoding/pem"
	"time"
)

func CreateCA(duration time.Duration, name *pkix.Name, keyType KeyType) (caPEM []byte, caPrivKeyPEM []byte, err error) {
	if duration < 0 {
		return nil, nil, errors.New("duration is required")
	}
	if keyType == "" {
		return nil, nil, errors.New("keyType is required")
	}
	if name == nil {
		return nil, nil, errors.New("name is required")
	}
	ca := &x509.Certificate{
		SerialNumber:          getSerial(),
		Subject:               *name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().UTC().Add(duration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPubKey, caPrivKey, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot generate private key")
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPubKey, caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot create certificate")
	}

	// pem encode
	caPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(caPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "cannot encode certificate")
	}
	caPEM = caPEMBuffer.Bytes()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot marshal private key")
	}
	caPrivKeyPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEMBuffer, &pem.Block{
		Type:  "PRIVATE KEY", // PEMKeyType(caPrivKey),
		Bytes: keyBytes,
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "cannot encode private key")
	}
	caPrivKeyPEM = caPrivKeyPEMBuffer.Bytes()

	return
}
