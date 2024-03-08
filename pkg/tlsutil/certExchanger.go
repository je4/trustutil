package tlsutil

import (
	"crypto/tls"
	"emperror.dev/errors"
	"sync"
)

func UpgradeTLSConfigServerExchanger(tlsConfig *tls.Config, certChannel chan *tls.Certificate) error {
	if len(tlsConfig.Certificates) != 1 {
		return errors.New("exactly one certificate is required in tlsConfig.Certificates")
	}
	tlsConfig.GetCertificate = NewCertExchanger(&tlsConfig.Certificates[0], certChannel).GetCertificateFunc()
	tlsConfig.Certificates = []tls.Certificate{}
	return nil
}

func UpgradeTLSConfigClientExchanger(tlsConfig *tls.Config, certChannel chan *tls.Certificate) error {
	if len(tlsConfig.Certificates) != 1 {
		return errors.New("exactly one certificate is required in tlsConfig.Certificates")
	}
	tlsConfig.GetClientCertificate = NewCertExchanger(&tlsConfig.Certificates[0], certChannel).GetClientCertificateFunc()
	tlsConfig.Certificates = []tls.Certificate{}
	return nil
}

func NewCertExchanger(cert *tls.Certificate, certChannel chan *tls.Certificate) *certExchanger {
	xChanger := &certExchanger{cert: cert}
	go func() {
		xChanger.exchange(certChannel)
	}()
	return xChanger
}

type certExchanger struct {
	m    sync.RWMutex
	cert *tls.Certificate
}

func (c *certExchanger) getCertificate() *tls.Certificate {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.cert
}

func (c *certExchanger) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.getCertificate(), nil
	}
}

func (c *certExchanger) GetClientCertificateFunc() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(requestInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return c.getCertificate(), nil
	}
}

func (c *certExchanger) exchange(certChannel chan *tls.Certificate) {
	for cert := range certChannel {
		c.m.Lock()
		c.cert = cert
		c.m.Unlock()
	}
}
