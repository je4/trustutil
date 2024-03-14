package loader

import (
	"crypto/tls"
	"emperror.dev/errors"
	"github.com/je4/utils/v2/pkg/zLogger"
	"os"
	"time"
)

func NewEnvLoader(certChannel chan *tls.Certificate, client bool, cert, key, ca string, interval time.Duration, logger zLogger.ZLogger) *EnvLoader {
	return &EnvLoader{
		certChannel: certChannel,
		cert:        cert,
		key:         key,
		ca:          ca,
		interval:    interval,
		done:        make(chan bool),
		logger:      logger,
	}
}

type EnvLoader struct {
	certChannel chan *tls.Certificate
	cert        string
	key         string
	ca          string
	certPEM     string
	keyPEM      string
	caPEM       []byte
	done        chan bool
	interval    time.Duration
	logger      zLogger.ZLogger
}

func (f *EnvLoader) GetCA() []byte {
	return f.caPEM
}

func (f *EnvLoader) load() error {
	certPEM := os.Getenv(f.cert)
	if len(certPEM) == 0 {
		return errors.Errorf("certificate environment variable %s is empty", f.cert)
	}
	keyPEM := os.Getenv(f.key)
	if len(keyPEM) == 0 {
		return errors.Errorf("key environment variable %s is empty", f.key)
	}
	if f.certPEM == certPEM && f.keyPEM == keyPEM {
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return errors.Wrap(err, "cannot create x509 key pair")
	}
	f.certChannel <- &cert
	f.certPEM = certPEM
	f.keyPEM = keyPEM
	return nil
}

func (f *EnvLoader) Close() error {
	f.done <- true
	close(f.certChannel)
	return nil
}

func (f *EnvLoader) Start() error {
	f.caPEM = []byte(os.Getenv(f.ca))
	go func() {
		for {
			if err := f.load(); err != nil {
				f.logger.Error().Err(err).Msg("cannot load")
			}
			select {
			case <-f.done:
				return
			case <-time.After(f.interval):
			}
		}
	}()
	return nil
}

var _ Loader = (*EnvLoader)(nil)
