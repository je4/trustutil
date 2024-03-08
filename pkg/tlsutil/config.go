package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"slices"
)

func CreateServerTLSConfig(cert tls.Certificate, mutual bool, uris []string, clientCAPEMs [][]byte) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		/*
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		*/
	}
	if !mutual && len(uris) > 0 {
		return nil, errors.New("uris is only allowed with mutual tls")
	}
	if mutual {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
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
	if len(clientCAPEMs) > 0 {
		clientCAPool := x509.NewCertPool()
		for _, caPEM := range clientCAPEMs {
			clientCAPool.AppendCertsFromPEM(caPEM)
		}
		tlsConfig.ClientCAs = clientCAPool
	}
	return tlsConfig, nil
}

func CreateClientMTLSConfig(clientCert tls.Certificate, caPEMs [][]byte) (*tls.Config, error) {
	certPool := x509.NewCertPool()
	for _, caPEM := range caPEMs {
		certPool.AppendCertsFromPEM(caPEM)
	}
	clientTLSConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return clientTLSConf, nil
}
