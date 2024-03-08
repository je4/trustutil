package tlsutil

import (
	"bytes"
	"crypto/tls"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"io"
	"log"
	"net/http"
	"testing"
	"time"
)

func printConnState(state *tls.ConnectionState, title string) {
	log.Printf(">>>>>>>>>>>>>>>> %s State <<<<<<<<<<<<<<<<", title)

	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s", state.NegotiatedProtocol)

	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	}
}

func TestHTTPMTLSConfig(t *testing.T) {
	name := certutil.DefaultName
	name.CommonName = "dummyServer"
	defaultCA, defaultCAPrivKey, err := certutil.CertificateKeyFromPEM(certutil.DefaultCACrt, certutil.DefaultCAKey, nil)
	if err != nil {
		t.Fatalf("cannot decode ca: %v", err)
	}
	certPEM, certPrivKeyPEM, err := certutil.CreateCertificate(
		false, true,
		time.Hour*24*365*10,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		nil,
		name,
		certutil.DefaultKeyType,
	)
	if err != nil {
		t.Fatalf("cannot create server certificate: %v", err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create server certificate: %v", err)
	}
	serverTLSConf, err := CreateServerTLSConfig(serverCert, true, []string{"grpc:dummy"}, [][]byte{certutil.DefaultCACrt})
	if err != nil {
		t.Fatalf("cannot create server tls config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		//printConnState(r.TLS, "Client")
		printConnState(r.TLS, "Client")
		w.Write([]byte("pong"))
	})

	serverCertChannel := make(chan *tls.Certificate)
	defer close(serverCertChannel)
	if err := UpgradeTLSConfigServerExchanger(serverTLSConf, serverCertChannel); err != nil {
		t.Fatalf("cannot upgrade client tls config: %v", err)
	}

	srv := http.Server{
		Addr:      "localhost:12345",
		Handler:   mux,
		TLSConfig: serverTLSConf,
	}
	go srv.ListenAndServeTLS("", "")
	defer srv.Close()

	name = certutil.DefaultName
	name.CommonName = "dummyClient"
	clientCertPEM, clientCertPrivKeyPEM, err := certutil.CreateCertificate(
		true, false,
		time.Hour*24*365*10,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		[]string{"grpc:dummy"},
		name,
		certutil.DefaultKeyType,
	)
	if err != nil {
		t.Fatalf("cannot create client certificate: %v", err)
	}
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientCertPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create client certificate: %v", err)
	}
	clientTLSConf, err := CreateClientMTLSConfig(clientCert, [][]byte{certutil.DefaultCACrt})
	if err != nil {
		t.Fatalf("cannot create client tls config: %v", err)
	}
	clientCertChannel := make(chan *tls.Certificate)
	defer close(clientCertChannel)
	if err := UpgradeTLSConfigClientExchanger(clientTLSConf, clientCertChannel); err != nil {
		t.Fatalf("cannot upgrade client tls config: %v", err)
	}
	tr := http.Transport{
		TLSClientConfig: clientTLSConf,
	}
	tr.IdleConnTimeout = time.Second * 5
	client := http.Client{
		Transport: &tr,
	}
	resp, err := client.Get("https://localhost:12345/ping")
	if err != nil {
		t.Fatalf("cannot get https://localhost:12345/ping: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	result := bytes.NewBuffer(nil)
	io.Copy(result, resp.Body)
	if result.String() != "pong" {
		t.Errorf("unexpected response: %s", result.String())
	}
	printConnState(resp.TLS, "Server")

	// New certificate
	name = certutil.DefaultName
	name.CommonName = "dummyServer2"
	certPEM, certPrivKeyPEM, err = certutil.CreateCertificate(
		false, true,
		time.Hour,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		nil,
		name,
		certutil.DefaultKeyType,
	)
	if err != nil {
		t.Fatalf("cannot create client certificate: %v", err)
	}
	serverCert, err = tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create client certificate: %v", err)
	}
	serverCertChannel <- &serverCert

	name = certutil.DefaultName
	name.CommonName = "dummyClient2"

	clientCertPEM, clientCertPrivKeyPEM, err = certutil.CreateCertificate(
		true, false,
		time.Hour,
		defaultCA,
		defaultCAPrivKey,
		certutil.DefaultIPAddresses,
		certutil.DefaultDNSNames,
		nil,
		[]string{"grpc:dummy"},
		name,
		certutil.DefaultKeyType,
	)
	if err != nil {
		t.Fatalf("cannot create client tls config: %v", err)
	}
	clientCert, err = tls.X509KeyPair(clientCertPEM, clientCertPrivKeyPEM)
	if err != nil {
		t.Fatalf("cannot create client certificate: %v", err)
	}
	clientCertChannel <- &clientCert

	time.Sleep(time.Second * 7)
	resp, err = client.Get("https://localhost:12345/ping")
	if err != nil {
		t.Errorf("cannot get https://localhost:12345/ping: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	result = bytes.NewBuffer(nil)
	io.Copy(result, resp.Body)
	if result.String() != "pong" {
		t.Errorf("unexpected response: %s", result.String())
	}
	printConnState(resp.TLS, "Server")

}
