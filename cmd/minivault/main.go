package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/je4/trustutil/v2/config"
	"github.com/je4/trustutil/v2/configs"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/trustutil/v2/pkg/vaultservice"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/rs/zerolog"
	"io"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var configfile = flag.String("config", "", "location of toml configuration file")
var first = flag.Bool("first", false, "run with first time setup")
var initCerts = flag.Bool("initcerts", false, "create initial certificates for all clients")

func main() {
	flag.Parse()
	var configFS fs.FS
	var configFile string
	if *configfile != "" {
		configFS = os.DirFS(filepath.Dir(*configfile))
		configFile = filepath.Base(*configfile)
	} else {
		configFS = configs.ConfigFS
		configFile = "minivault.toml"
	}
	conf := &config.MiniVaultConfig{
		LocalAddr:    "localhost:8443",
		ExternalAddr: "https://localhost:8443",
		TLSCert:      "",
		TLSKey:       "",
		TLSKeyPass:   "",
		LogFile:      "",
		LogLevel:     "DEBUG",
	}

	if err := config.LoadMiniVaultConfig(configFS, configFile, conf); err != nil {
		log.Panicf("cannot load config file [%v] %s: %v", configFS, configFile, err)
	}

	// create logger instance
	var out io.Writer = os.Stdout
	if conf.LogFile != "" {
		fp, err := os.OpenFile(conf.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("cannot open logfile %s: %v", conf.LogFile, err)
		}
		defer fp.Close()
		out = fp
	}

	output := zerolog.ConsoleWriter{Out: out, TimeFormat: time.RFC3339}
	_logger := zerolog.New(output).With().Timestamp().Logger()
	_logger.Level(zLogger.LogLevel(conf.LogLevel))
	var logger zLogger.ZLogger = &_logger

	caBytes, err := os.ReadFile(conf.Vault.CA)
	if err != nil {
		logger.Fatal().Msgf("cannot read CA file %v: %v", conf.Vault.CA, err)
	}
	caKeyBytes, err := os.ReadFile(conf.Vault.CAKey)
	if err != nil {
		logger.Fatal().Msgf("cannot read CA key file %v: %v", conf.Vault.CAKey, err)
	}

	logger.Info().Msg("parsing CA / decrypting CA key")
	caCert, caKey, err := certutil.CertificateKeyFromPEM(caBytes, caKeyBytes, []byte(conf.Vault.CAKeyPass))
	if err != nil {
		logger.Fatal().Msgf("cannot parse CA / decrypt key: %v", err)

	}
	if *first {
		logger.Info().Msg("first time setup")
		name := certutil.DefaultName
		name.CommonName = "MiniVault Server"
		logger.Info().Msg("creating server certificate")

		serverCert, serverKey, err := certutil.CreateCertificate(false, true, time.Hour*24*365*1, caCert, caKey, certutil.DefaultIPAddresses, certutil.DefaultDNSNames, nil, nil, name, certutil.DefaultKeyType)
		if err != nil {
			logger.Fatal().Msgf("cannot create server certificate: %v", err)
		}
		logger.Info().Msg("encrypting server key")
		encServerKey, err := certutil.EncryptPrivateKey(serverKey, []byte(conf.TLSKeyPass))
		if err != nil {
			logger.Fatal().Msgf("cannot encrypt server key: %v", err)
		}
		logger.Info().Msgf("writing server certificate %s", conf.TLSCert)
		if err := os.WriteFile(conf.TLSCert, serverCert, 0644); err != nil {
			logger.Fatal().Msgf("cannot write server certificate to %s: %v", conf.TLSCert, err)
		}
		logger.Info().Msgf("writing server key %s", conf.TLSKey)
		if err := os.WriteFile(conf.TLSKey, encServerKey, 0644); err != nil {
			logger.Fatal().Msgf("cannot write server key to %s: %v", conf.TLSKey, err)
		}
		logger.Info().Msg("first time setup done")
		return
	}

	if *initCerts {
		logger.Info().Msgf("initializing clientcertificates in folder %s", conf.ClientCerts)
		for _, client := range conf.Client {
			logger.Info().Msgf("*** creating client certificate for %s", client.Name)
			name := certutil.DefaultName
			name.CommonName = client.Name
			clientCert, clientKey, err := certutil.CreateCertificate(true, false, time.Duration(client.Validity), caCert, caKey, nil, nil, nil, []string{"rest:clientcert"}, name, certutil.DefaultKeyType)
			if err != nil {
				logger.Fatal().Msgf("cannot create client certificate for %s: %v", client.Name, err)
			}
			logger.Info().Msg("encrypting client key")
			pw, err := certutil.GeneratePassword(64)
			if err != nil {
				logger.Fatal().Msgf("cannot generate password: %v", err)
			}
			encClientKey, err := certutil.EncryptPrivateKey(clientKey, []byte(pw))
			if err != nil {
				logger.Fatal().Msgf("cannot encrypt client key: %v", err)
			}
			certName := filepath.Join(conf.ClientCerts, client.Name+".crt")
			logger.Info().Msgf("writing client certificate %s", certName)
			if err := os.WriteFile(certName, clientCert, 0644); err != nil {
				logger.Fatal().Msgf("cannot write client certificate to %s: %v", certName, err)
			}
			keyName := filepath.Join(conf.ClientCerts, client.Name+".key")
			logger.Info().Msgf("writing client key %s", keyName)
			if err := os.WriteFile(keyName, encClientKey, 0644); err != nil {
				logger.Fatal().Msgf("cannot write client key to %s: %v", keyName, err)
			}
			pwName := filepath.Join(conf.ClientCerts, client.Name+".pw")
			logger.Info().Msgf("writing client key password %s", pwName)
			if err := os.WriteFile(pwName, []byte(pw), 0644); err != nil {
				logger.Fatal().Msgf("cannot write client password key to %s: %v", pwName, err)
			}
		}
		return
	}

	logger.Info().Msg("Starting minivault")
	logger.Info().Msgf("LocalAddr: %v", conf.LocalAddr)
	logger.Info().Msgf("ExternalAddr: %v", conf.ExternalAddr)
	logger.Info().Msgf("TLSCert: %v", conf.TLSCert)
	logger.Info().Msgf("TLSKey: %v", conf.TLSKey)

	// get all ip adresses
	ips := []net.IP{}
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Fatal().Msgf("cannot get network interfaces: %v", err)
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			logger.Fatal().Msgf("cannot get addresses for interface %v: %v", i.Name, err)
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	u, err := url.Parse(conf.ExternalAddr)
	if err != nil {
		logger.Fatal().Msgf("cannot parse external address %s: %v", conf.ExternalAddr, err)
	}

	certPEM, keyPEM, err := certutil.CreateCertificate(false, true, time.Hour*24, caCert, caKey, ips, []string{"localhost", u.Hostname()}, nil, nil, certutil.DefaultName, certutil.DefaultKeyType)
	if err != nil {
		logger.Fatal().Msgf("cannot create server certificate: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logger.Fatal().Msgf("cannot create server certificate: %v", err)
	}
	certFS := os.DirFS(conf.ClientCerts)
	ctrl, err := vaultservice.NewController(conf.LocalAddr, conf.ExternalAddr, "/", cert, caCert, caKey, certFS, logger, conf.Client)
	if err != nil {
		logger.Fatal().Msgf("cannot create controller: %v", err)
	}
	wg := &sync.WaitGroup{}
	ctrl.Start(wg)
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	fmt.Println("press ctrl+c to stop server")
	s := <-done
	fmt.Println("got signal:", s)

	ctrl.GracefulStop()

	wg.Wait()

}
