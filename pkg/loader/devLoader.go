package loader

import (
	"crypto/tls"
	"time"

	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/certutil"
)

func NewDevLoader(certChannel chan *tls.Certificate, client bool) Loader {
	l := &devLoader{
		certChannel: certChannel,
		client:      client,
		done:        make(chan bool),
	}
	return l
}

type devLoader struct {
	certChannel chan *tls.Certificate
	client      bool
	done        chan bool
}

func (d *devLoader) Close() error {
	d.done <- true
	close(d.done)
	close(d.certChannel)
	return nil
}

func (d *devLoader) Start() error {
	defaultCA, defaultCAPrivKey, err := certutil.CertificateKeyFromPEM(certutil.DefaultCACrt, certutil.DefaultCAKey, nil)
	if err != nil {
		return errors.Wrap(err, "cannot decode default ca certificate")
	}
	name := certutil.DefaultName
	certPEM, certPrivKeyPEM, err := certutil.CreateCertificate(
		d.client,
		!d.client,
		time.Hour*24,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		certutil.DefaultURIs,
		name,
		certutil.DefaultKeyType)
	if err != nil {
		return errors.Wrap(err, "cannot create server certificate")
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return errors.Wrap(err, "cannot create server certificate from key pair")
	}

	d.certChannel <- &serverCert
	<-d.done
	return nil
}

func (d *devLoader) GetCA() []byte {
	return certutil.DefaultCACrt
}

var _ Loader = (*devLoader)(nil)
