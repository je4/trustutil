package certutil

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"
)

var getSerialMutex = &sync.Mutex{}

func getSerial() *big.Int {
	getSerialMutex.Lock()
	defer getSerialMutex.Unlock()
	defer time.Sleep(1 * time.Millisecond)
	return big.NewInt(time.Now().UnixMilli())
}

func CreateCertificate(client, server bool, duration time.Duration, ca *x509.Certificate, caPrivKey any, ips []net.IP, dnsNames []string, email, uri []string, name *pkix.Name, keyType KeyType) (certPEM []byte, certPrivKeyPEM []byte, err error) {
	if !client && !server {
		return nil, nil, errors.New("client and/or server must be true")
	}
	if keyType == "" {
		return nil, nil, errors.New("keyType is required")
	}
	if name == nil {
		return nil, nil, errors.New("name is required")
	}
	if server && len(ips) == 0 && len(dnsNames) == 0 {
		return nil, nil, errors.New("IP address and/or DNS name is required")
	}

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: getSerial(),
		Subject:      *name,
		IPAddresses:  ips,
		DNSNames:     dnsNames,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().Add(duration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if client {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if server {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	cert.EmailAddresses = email
	for _, u := range uri {
		_u, err := url.Parse(u)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "cannot parse URI %s", u)
		}
		cert.URIs = append(cert.URIs, _u)
	}

	certPubKey, certPrivKey, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot generate private key")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, certPubKey, caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create certificate")
	}

	certPEMBuffer := new(bytes.Buffer)
	pem.Encode(certPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPEM = certPEMBuffer.Bytes()

	certPrivKeyPEMBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot marshal private key")
	}
	certPrivKeyPEMBuffer := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEMBuffer, &pem.Block{
		Type:  "PRIVATE KEY", // PEMKeyType(certPrivKey),
		Bytes: certPrivKeyPEMBytes,
	})
	certPrivKeyPEM = certPrivKeyPEMBuffer.Bytes()

	return
}
