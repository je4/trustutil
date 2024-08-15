package config

import (
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/pem"
	"github.com/je4/utils/v2/pkg/config"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

type Certificate struct {
	*x509.Certificate
	Key any
}

func (cp *Certificate) UnmarshalText(text []byte) error {
	var pe config.EnvString
	if err := pe.UnmarshalText(text); err != nil {
		return errors.Wrap(err, "cannot unmarshal certificate string")
	}
	pemString := strings.TrimSpace(string(pe))
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

func (cp *Certificate) UnmarshalYAML(value *yaml.Node) error {
	var text string
	value.Decode(&text)
	return cp.UnmarshalText([]byte(text))
}
