package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/smallstep/certinfo"
	"sync"
)

func UpgradeTLSConfigServerExchanger(tlsConfig *tls.Config, certChannel chan *tls.Certificate, logger zLogger.ZLogger) error {
	if len(tlsConfig.Certificates) != 1 {
		return errors.New("exactly one certificate is required in tlsConfig.Certificates")
	}
	tlsConfig.GetCertificate = NewCertExchanger(&tlsConfig.Certificates[0], certChannel, logger).GetCertificateFunc()
	tlsConfig.Certificates = []tls.Certificate{}
	return nil
}

func UpgradeTLSConfigClientExchanger(tlsConfig *tls.Config, certChannel chan *tls.Certificate, logger zLogger.ZLogger) error {
	if len(tlsConfig.Certificates) != 1 {
		return errors.New("exactly one certificate is required in tlsConfig.Certificates")
	}
	tlsConfig.GetClientCertificate = NewCertExchanger(&tlsConfig.Certificates[0], certChannel, logger).GetClientCertificateFunc()
	tlsConfig.Certificates = []tls.Certificate{}
	return nil
}

func NewCertExchanger(cert *tls.Certificate, certChannel chan *tls.Certificate, logger zLogger.ZLogger) *certExchanger {
	xChanger := &certExchanger{cert: cert, logger: logger}
	go func() {
		xChanger.exchange(certChannel)
	}()
	return xChanger
}

type certExchanger struct {
	m      sync.RWMutex
	cert   *tls.Certificate
	logger zLogger.ZLogger
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
		if c.logger != nil {
			for _, cRaw := range cert.Certificate {
				crt, err := x509.ParseCertificate(cRaw)
				if err != nil {
					c.logger.Error().Err(err).Msg("cannot parse certificate")
				}
				if info, err := certinfo.CertificateText(crt); err == nil {
					c.logger.Debug().Msgf("client certificate loaded: %s", info)
				} else {
					c.logger.Debug().Msg("client certificate loaded")
				}
			}
		}
	}
}
