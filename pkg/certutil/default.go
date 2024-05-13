package certutil

import (
	"crypto/x509/pkix"
	_ "embed"
	"net"
	"slices"
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

func AddDefaultDNSNames(names ...string) {
	DefaultDNSNames = slices.Compact(append(DefaultDNSNames, names...))
}

var DefaultIPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

var AddDefaultIPAddresses = func(ips ...net.IP) {
	DefaultIPAddresses = slices.CompactFunc(append(DefaultIPAddresses, ips...), func(i1, i2 net.IP) bool {
		return i1.String() == i2.String()
	})
}

var DefaultDuration = time.Hour * 24 * 365 * 10
