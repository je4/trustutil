package certutil

import (
	"crypto/x509/pkix"
	_ "embed"
	"emperror.dev/errors"
	"net"
	"time"
)

//go:embed dummyCA.crt
var DefaultCACrt []byte

//go:embed dummyCA.key
var DefaultCAKey []byte

var DefaultKeyType KeyType = ECDSAP384

var DefaultName = &pkix.Name{
	Organization:  []string{"University Library Basel"},
	Country:       []string{"CH"},
	Province:      []string{"Basel City"},
	Locality:      []string{"Basel"},
	StreetAddress: []string{"Schönbeinstrasse 18-20"},
	PostalCode:    []string{"4056"},
}

var DefaultDNSNames = []string{"localhost"}

var DefaultIPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

var DefaultDuration = time.Hour * 24 * 365 * 10

func CreateDefaultCertificate(client, server bool, uris []string) (certPEM []byte, certPrivKeyPEM []byte, err error) {
	defaultCA, defaultCAPrivKey, err := CertificateKeyFromPEM(DefaultCACrt, DefaultCAKey, nil)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return CreateCertificate(
		client, server,
		DefaultDuration,
		defaultCA,
		defaultCAPrivKey,
		DefaultIPAddresses,
		DefaultDNSNames,
		nil,
		uris,
		DefaultName,
		DefaultKeyType,
	)
}
