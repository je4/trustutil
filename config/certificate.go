package config

import (
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/pem"
	"os"
	"regexp"
	"strings"
)

type Certificate struct {
	*x509.Certificate
	Key any
}

var envRegexp = regexp.MustCompile(`%%([^%]+)%%`)

func (cp *Certificate) UnmarshalText(text []byte) error {
	pemString := strings.TrimSpace(string(text))
	if found := envRegexp.FindStringSubmatch(pemString); found != nil {
		pemString = os.Getenv(found[1])
		if pemString == "" {
			return errors.Errorf("environment variable %s is empty", found[1])
		}
	} else {
		if !strings.HasPrefix(pemString, "-----BEGIN CERTIFICATE-----") {
			fi, err := os.Stat(pemString)
			if err != nil {
				if os.IsNotExist(err) {
					return errors.Errorf("'%s' not a certificate", pemString)
				}
				return errors.Wrapf(err, "cannot stat file %s", pemString)
			} else {
				if fi.IsDir() {
					return errors.Errorf("file %s is a directory", pemString)
				}
				data, err := os.ReadFile(pemString)
				if err != nil {
					return errors.Wrapf(err, "cannot read file %s", pemString)
				}
				pemString = string(data)
			}
		}
	}
	newCert := Certificate{}
	for block, rest := pem.Decode([]byte(pemString)); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.Wrap(err, "cannot parse certificate")
			}
			newCert.Certificate = cert
		case "PRIVATE KEY":
			var key any
			var err error
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					key, err = x509.ParseECPrivateKey(block.Bytes)
					if err != nil {
						return errors.Wrap(err, "cannot parse private key")
					}
				}
				newCert.Key = key
			}
		}
	}
	if newCert.Certificate != nil {
		*cp = newCert
		return nil
	}
	return errors.New("no certificate found")
}
