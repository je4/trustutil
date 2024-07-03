package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/certutil"
)

func CreateServerTLSConfig(cert tls.Certificate, mutual bool, uris []string, caCertPool *x509.CertPool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    caCertPool,
		/*
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		*/
	}
	fmt.Println("\n\n\nCreateServerTLSConfig uris", uris)
	if !mutual && len(uris) > 0 {
		return nil, errors.New("uris is only allowed with mutual tls")
	}
	if mutual {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		fmt.Println("tlsConfig.ClientAuth", tls.RequestClientCert)
		if len(uris) > 0 {
			tlsConfig.VerifyPeerCertificate = func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(verifiedChains) < 1 {
					return errors.New("no verified chains")
				}
				if len(verifiedChains[0]) < 1 {
					return errors.New("no verified chain 0")
				}
				c := verifiedChains[0][0]
				clientURIs := []string{}
				for _, u := range c.URIs {
					clientURIs = append(clientURIs, u.String())
				}
				for _, u := range uris {
					if !slices.Contains(clientURIs, u) {
						return errors.Errorf("no match for uri %s", u)
					}
				}
				/*
					result, err := certinfo.CertificateText(c)
					if err != nil {
						return errors.Wrap(err, "cannot get certificate text")
					}
					log.Println("cert [0][0]")
					log.Println(result)
					if len(verifiedChains[0]) > 1 {
						result, err := certinfo.CertificateText(verifiedChains[0][1])
						if err != nil {
							return errors.Wrap(err, "cannot get certificate text")
						}
						log.Println("cert [0][1]")
						log.Println(result)
					}
				*/
				return nil
			}
		}
	}
	return tlsConfig, nil
}

func CreateClientMTLSConfig(clientCert tls.Certificate, caCertPool *x509.CertPool) (*tls.Config, error) {
	clientTLSConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}

	return clientTLSConf, nil
}

func CreateDefaultServerTLSConfig(commonName string, useSystemCertPool bool) (*tls.Config, error) {
	defaultCA, defaultCAPrivKey, err := certutil.CertificateKeyFromPEM(certutil.DefaultCACrt, certutil.DefaultCAKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode default ca certificate")
	}
	name := certutil.DefaultName
	name.CommonName = commonName
	certPEM, certPrivKeyPEM, err := certutil.CreateCertificate(
		false,
		true,
		time.Hour*24,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		nil,
		name,
		certutil.DefaultKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}

	certPool := x509.NewCertPool()
	if useSystemCertPool {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrap(err, "cannot get system cert pool")
		}
		certPool = systemCertPool
	}
	if !certPool.AppendCertsFromPEM(certutil.DefaultCACrt) {
		return nil, errors.New("cannot append ca from default ca")
	}

	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate from key pair")
	}
	tlsConfig, err := CreateServerTLSConfig(serverCert, true, nil, certPool)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server tls config")
	}
	return tlsConfig, nil
}
