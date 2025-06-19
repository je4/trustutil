package certutil

import (
	crand "crypto/rand"
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/binary"
	"encoding/pem"
	"log"
	"math/rand"
)

func CertificateFromPEM(certPEM []byte) (*x509.Certificate, error) {
	caBlock, _ := pem.Decode(certPEM)
	if caBlock == nil {
		return nil, errors.New("cannot decode PEM")
	}
	c, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse certificate")
	}
	return c, nil
}

func KeyFromPEM(keyPEM, password []byte) (any, error) {
	var err error
	caPrivKeyBlock, _ := pem.Decode(keyPEM)
	if caPrivKeyBlock.Type == "ENCRYPTED PRIVATE KEY" {
		if len(password) == 0 {
			return nil, errors.New("private key is encrypted, but no password provided")
		}
		keyPEM, err = DecryptPrivateKey(keyPEM, password)
		if err != nil {
			return nil, errors.Wrap(err, "cannot decrypt private key")
		}
		caPrivKeyBlock, _ = pem.Decode(keyPEM)
	}
	if caPrivKeyBlock == nil {
		return nil, errors.New("cannot decode private key PEM")
	}
	var key any
	var err1, err2, err3 error
	key, err1 = x509.ParseECPrivateKey(caPrivKeyBlock.Bytes)
	if err1 != nil {
		key, err2 = x509.ParsePKCS8PrivateKey(caPrivKeyBlock.Bytes)
		if err2 != nil {
			key, err3 = x509.ParsePKCS1PrivateKey(caPrivKeyBlock.Bytes)
			if err3 != nil {
				return nil, errors.Wrap(errors.Combine(err1, err2, err3), "cannot parse EC, PKCS8, PKCS1 private key")
			}
		}
	}
	return key, nil
}

func PublicKeyFromPEM(keyPEM []byte) (any, error) {
	caPubKeyBlock, _ := pem.Decode(keyPEM)
	var key any
	var err1, err2 error
	key, err1 = x509.ParsePKIXPublicKey(caPubKeyBlock.Bytes)
	if err1 != nil {
		key, err2 = x509.ParsePKCS1PublicKey(caPubKeyBlock.Bytes)
		if err2 != nil {
			return nil, errors.Wrap(errors.Combine(err1, err2), "cannot parse PKIX, PKCS1 public key")
		}
	}
	return key, nil
}

func CertificateKeyFromPEM(certPEM, keyPEM, password []byte) (*x509.Certificate, any, error) {
	c, err := CertificateFromPEM(certPEM)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	key, err := KeyFromPEM(keyPEM, password)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return c, key, nil
}

type cryptoSource struct{}

func (s cryptoSource) Seed(seed int64) {}

func (s cryptoSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (s cryptoSource) Uint64() (v uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &v)
	if err != nil {
		log.Fatal(err)
	}
	return v
}

var digits = "0123456789"
var specials = "~=+%^*/()[]{}/!@#$?|"
var all = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz" +
	digits + specials

func GeneratePassword(length int) (string, error) {
	var src cryptoSource
	rnd := rand.New(src)

	buf := make([]byte, length)
	buf[0] = digits[rnd.Intn(len(digits))]
	buf[1] = specials[rnd.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rnd.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf) // E.g. "3i[g0|)z"
	return str, nil
}
