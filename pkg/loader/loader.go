package loader

import (
	"crypto/tls"
	"emperror.dev/errors"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	"github.com/je4/utils/v2/pkg/zLogger"
	"io"
	"strings"
	"time"
)

type Loader interface {
	io.Closer
	Start() error
	GetCA() []byte
}

func initLoader(conf *TLSConfig, certChannel chan *tls.Certificate, client bool, logger zLogger.ZLogger) (l Loader, err error) {
	switch strings.ToUpper(conf.Type) {
	case "ENV":
		l = NewEnvLoader(certChannel, client, conf.Cert, conf.Key, conf.CA, time.Duration(conf.Interval), logger)
	case "FILE":
		l = NewFileLoader(certChannel, client, conf.Cert, conf.Key, conf.CA, time.Duration(conf.Interval), logger)
	case "DEV":
		l = NewDevLoader(certChannel, client)
	default:
		err = errors.Errorf("unknown loader type %s", conf.Type)
		return
	}
	go func() {
		logger.Info().Msg("starting loader")
		if err := l.Start(); err != nil {
			logger.Error().Err(err).Msg("error starting loader")
		} else {
			logger.Info().Msg("loader stopped")
		}
	}()
	return
}

func CreateServerLoader(mutual bool, conf *TLSConfig, uris []string, logger zLogger.ZLogger) (tlsConfig *tls.Config, l Loader, err error) {
	certChannel := make(chan *tls.Certificate)
	l, err = initLoader(conf, certChannel, false, logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create loader")
	}
	var cert *tls.Certificate
	select {
	case cert = <-certChannel:
	case <-time.After(5 * time.Second):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	tlsConfig, err = tlsutil.CreateServerTLSConfig(*cert, mutual, uris, [][]byte{l.GetCA()})
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigServerExchanger(tlsConfig, certChannel); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}

func CreateClientLoader(conf *TLSConfig, logger zLogger.ZLogger, hosts ...string) (tlsConfig *tls.Config, l Loader, err error) {
	certChannel := make(chan *tls.Certificate)
	l, err = initLoader(conf, certChannel, true, logger)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create loader")
	}
	var cert *tls.Certificate
	select {
	case cert = <-certChannel:
	case <-time.After(5 * time.Second):
		return nil, nil, errors.New("timeout waiting for initial certificate")
	}
	tlsConfig, err = tlsutil.CreateClientMTLSConfig(*cert, [][]byte{l.GetCA()})
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create server tls config")
	}
	if err := tlsutil.UpgradeTLSConfigClientExchanger(tlsConfig, certChannel); err != nil {
		return nil, nil, errors.Wrap(err, "cannot upgrade tls config")
	}
	return
}
