package vaultclient

import (
	"crypto/tls"
	"github.com/je4/trustutil/v2/certificates"
	"github.com/je4/trustutil/v2/config"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/trustutil/v2/pkg/vaultservice"
	configutil "github.com/je4/utils/v2/pkg/config"
	"github.com/rs/zerolog"
	"sync"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	// Start server
	defaultCA, defaultCAPrivKey, err := certutil.CertificateKeyFromPEM(certutil.DefaultCACrt, certutil.DefaultCAKey, nil)
	if err != nil {
		t.Fatalf("cannot decode ca: %v", err)
	}
	name := certutil.DefaultName
	name.CommonName = "testServer"

	certPEM, certPrivKeyPEM, err := certutil.CreateCertificate(
		false, true,
		time.Hour*24*365*10,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		[]string{"cert:clientcert"},
		name,
		certutil.DefaultKeyType,
	)
	if err != nil {
		t.Fatalf("cannot create server certificate: %v", err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create server certificate from key pair: %v", err)
	}

	logger := zerolog.Nop()
	srv, err := vaultservice.NewController(
		"localhost:12345",
		"https://localhost:12345",
		"/",
		serverCert,
		defaultCA,
		defaultCAPrivKey,
		certificates.CertFS,
		&logger,
		[]*config.MiniVaultClientConfig{
			&config.MiniVaultClientConfig{
				Name:     "test1",
				URIs:     []string{"srv:test"},
				Validity: configutil.Duration(time.Hour),
			},
		},
	)
	if err != nil {
		t.Fatalf("cannot create server: %v", err)
	}
	wg := &sync.WaitGroup{}
	srv.Start(wg)
	defer srv.Stop()

	// Create client
	/*
		clientCertPEM, clientCertPrivKeyPEM, err := certutil.CreateDefaultCertificate(true, false, []string{"cert:clientcert"})
		if err != nil {
			t.Fatalf("cannot create client certificate: %v", err)
		}
	*/
	clientName := certutil.DefaultName
	clientName.CommonName = "test1"
	clientCertPEM, clientCertPrivKeyPEM, err := certutil.CreateCertificate(
		true,
		false,
		certutil.DefaultDuration,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		[]string{"cert:clientcert"},
		clientName,
		certutil.DefaultKeyType,
	)
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientCertPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create client certificate key pair: %v", err)
	}
	client, err := NewClient("https://localhost:12345/api/v1", clientCert, certutil.DefaultCACrt)
	if err != nil {
		t.Fatalf("cannot create client: %v", err)
	}
	c, err := client.GetClientCertificate()
	if err != nil {
		t.Fatalf("cannot get certificate: %v", err)
	}
	_ = c
	/*
		result, err := certinfo.CertificateText(c.)
		if err != nil {
			t.Fatalf("cannot get certificate text: %v", err)
		}
		log.Println("cert [0][0]")
		log.Println(result)

	*/
}
