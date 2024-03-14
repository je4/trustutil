package loader

import (
	"crypto/tls"
	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/certutil"
)

func NewDevLoader(certChannel chan *tls.Certificate) Loader {
	l := &devLoader{
		certChannel: certChannel,
	}
	return l
}

type devLoader struct {
	certChannel chan *tls.Certificate
}

func (d devLoader) Close() error {
	return nil
}

func (d devLoader) Start() error {
	cert, err := tls.X509KeyPair(certutil.DefaultCACrt, certutil.DefaultCAKey)
	if err != nil {
		return errors.Wrap(err, "cannot create x509 key pair")
	}
	d.certChannel <- &cert
	return nil
}

func (d devLoader) GetCA() []byte {
	return certutil.DefaultCACrt
}

var _ Loader = (*devLoader)(nil)
