package config

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var certs = []string{
	// Dummy CA #0
	`-----BEGIN CERTIFICATE-----
MIICzDCCAlKgAwIBAgIGAZExKXU/MAoGCCqGSM49BAMDMIGcMQswCQYDVQQGEwJD
SDETMBEGA1UECBMKQmFzZWwgQ2l0eTEOMAwGA1UEBxMFQmFzZWwxIDAeBgNVBAkM
F1NjaMO2bmJlaW5zdHJhc3NlIDE4LTIwMQ0wCwYDVQQREwQ0MDU2MSEwHwYDVQQK
ExhVbml2ZXJzaXR5IExpYnJhcnkgQmFzZWwxFDASBgNVBAMMC0R1bW15IENBICMw
MB4XDTI0MDgwODA4NDQ0NloXDTM0MDgwNjA4NDQ0NlowgZwxCzAJBgNVBAYTAkNI
MRMwEQYDVQQIEwpCYXNlbCBDaXR5MQ4wDAYDVQQHEwVCYXNlbDEgMB4GA1UECQwX
U2Now7ZuYmVpbnN0cmFzc2UgMTgtMjAxDTALBgNVBBETBDQwNTYxITAfBgNVBAoT
GFVuaXZlcnNpdHkgTGlicmFyeSBCYXNlbDEUMBIGA1UEAwwLRHVtbXkgQ0EgIzAw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAATfHjy6C+KlfRAue4hh1ZVQ09k0dshv7xzX
F+Xu6PXcQw/fL1pu/8SgJaKpIhZcRZ+div+k2qG97j2XLqbsVPQKIMZD8bWyPspf
rLeNKn+bAUAbppUeCIEU0sc7xNLXdg+jYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNV
HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUtqiQJvnDgCmiML5jpSlphf1U1xwwCgYIKoZIzj0EAwMDaAAwZQIwV2L4
3p2bv4nErFD0w3JTUko0QU/ww17yLv8E+O8g8llYGI7SRX0oLV2MtXCXXk/oAjEA
kEJazWKdbrxtfT4kL9m9pU2vCxClJMmdxYk2tl+GSOW4nKiowZfrH27ST2XIMxOK
-----END CERTIFICATE-----

-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDKGHn9DPTQczoQ17UH
v40C3+Zk0ye+BCm7gyK0SZx8pVDsb4xa1P4rlqXZa1Yxf02hZANiAAQStfIQGbwo
f1ydEI0Ey5555fQ0hvG3ll0KNBJB4ngFdHBEqvmIV4eIEBpmc3aCf1+6X0J++NhU
JTzPdLhHyj/B9yHUliAVc30H9fXG3n7e+KWmP70UAdZqbg9mrpoQjAM=
-----END PRIVATE KEY-----`,
	// Dummy CA #1
	`-----BEGIN CERTIFICATE-----
MIICzDCCAlKgAwIBAgIGAZExKXVNMAoGCCqGSM49BAMDMIGcMQswCQYDVQQGEwJD
SDETMBEGA1UECBMKQmFzZWwgQ2l0eTEOMAwGA1UEBxMFQmFzZWwxIDAeBgNVBAkM
F1NjaMO2bmJlaW5zdHJhc3NlIDE4LTIwMQ0wCwYDVQQREwQ0MDU2MSEwHwYDVQQK
ExhVbml2ZXJzaXR5IExpYnJhcnkgQmFzZWwxFDASBgNVBAMMC0R1bW15IENBICMx
MB4XDTI0MDgwODA4NDQ0NloXDTM0MDgwNjA4NDQ0NlowgZwxCzAJBgNVBAYTAkNI
MRMwEQYDVQQIEwpCYXNlbCBDaXR5MQ4wDAYDVQQHEwVCYXNlbDEgMB4GA1UECQwX
U2Now7ZuYmVpbnN0cmFzc2UgMTgtMjAxDTALBgNVBBETBDQwNTYxITAfBgNVBAoT
GFVuaXZlcnNpdHkgTGlicmFyeSBCYXNlbDEUMBIGA1UEAwwLRHVtbXkgQ0EgIzEw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAARge6ID4vOlHDExO1iQqZAsIcbfKX5YbK+q
eejRvV7q7UO57NFaFDIdHLgtESJbu80yEAoXhZ9P1eAYbjrDu1eHrevnkkMwWNpR
S4HBNTJsyTWmQzyomJRsr8ToD42WdYKjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNV
HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU0gfo399HkhBTbaQDN+e5RUZTvKowCgYIKoZIzj0EAwMDaAAwZQIwMidZ
ArALn9+YXv63+1nEM5FTGip7WPDVeBR02sOxa0vxBXlCik0SIVLS+uvN08qCAjEA
0UK3Yf4a6TUCsUn+HbFC1L6tGb9aTlma+upoobctmpkkibNPfnzUmDZd9hurbRld
-----END CERTIFICATE-----`,
	// Dummy CA #2
	`-----BEGIN CERTIFICATE-----
MIICzDCCAlKgAwIBAgIGAZExKXVbMAoGCCqGSM49BAMDMIGcMQswCQYDVQQGEwJD
SDETMBEGA1UECBMKQmFzZWwgQ2l0eTEOMAwGA1UEBxMFQmFzZWwxIDAeBgNVBAkM
F1NjaMO2bmJlaW5zdHJhc3NlIDE4LTIwMQ0wCwYDVQQREwQ0MDU2MSEwHwYDVQQK
ExhVbml2ZXJzaXR5IExpYnJhcnkgQmFzZWwxFDASBgNVBAMMC0R1bW15IENBICMy
MB4XDTI0MDgwODA4NDQ0NloXDTM0MDgwNjA4NDQ0NlowgZwxCzAJBgNVBAYTAkNI
MRMwEQYDVQQIEwpCYXNlbCBDaXR5MQ4wDAYDVQQHEwVCYXNlbDEgMB4GA1UECQwX
U2Now7ZuYmVpbnN0cmFzc2UgMTgtMjAxDTALBgNVBBETBDQwNTYxITAfBgNVBAoT
GFVuaXZlcnNpdHkgTGlicmFyeSBCYXNlbDEUMBIGA1UEAwwLRHVtbXkgQ0EgIzIw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAARaRDOwGvGG5RHOZ+aJ7JJN/uz0vKZCA+U3
0NwXup1dXBjPznrKarDSPy0RNNHpGEYeNkzwBmgH5Q+10Gr7VJxjUrSlric9I22z
vr5n/Ft6BPLaburMITfvypOYnS8IiAKjYTBfMA4GA1UdDwEB/wQEAwIChDAdBgNV
HSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUid5SIL/2bppgTHyd1sWIu1/JvSAwCgYIKoZIzj0EAwMDaAAwZQIwQKz3
lkNEqQdlHlhHn053aQDnfdxx06rfMaxv5t5vOAF1zruzk1A1K3Dd2PpJTdEzAjEA
3luM46qrPxzQzJOZ4IIgule5f33HFBkyhHTjGxGL2bVzTDxADhaQPODcZHZ/v0Xg
-----END CERTIFICATE-----`,
}

func checkCerts(t *testing.T, certs []Certificate) {
	if len(certs) != 3 {
		t.Error("expected 3 certificates, got", len(certs))
	}
	for i, cert := range certs {
		if i == 0 {
			_, ok := cert.Key.(*ecdsa.PrivateKey)
			if !ok {
				t.Error(i, fmt.Sprintf("unexpected key type %T", cert.Key))
			}
		}
		if cert.Subject.CommonName != fmt.Sprintf("Dummy CA #%d", i) {
			t.Error("unexpected common name", cert.Subject.CommonName)
		}
	}
}

func TestCertCertificateEmbedded(t *testing.T) {
	type Config struct {
		Certificates []Certificate `toml:"certificates"`
	}
	var tomlData = fmt.Sprintf(`
certificates = [
"""%s""",
"""%s""",
"""%s"""
]
`, certs[0], certs[1], certs[2])
	var conf = &Config{}
	if _, err := toml.Decode(tomlData, &conf); err != nil {
		t.Error("toml decode failed", err)
	}
	checkCerts(t, conf.Certificates)
}

func TestCertCertificateEnv(t *testing.T) {
	type Config struct {
		Certificates []Certificate `toml:"certificates"`
	}
	var tomlData = `
certificates = [`
	for i, cert := range certs {
		tomlData += fmt.Sprintf(`
"%%%%ENV_CERT%d%%%%",`, i)
		if err := os.Setenv(fmt.Sprintf("ENV_CERT%d", i), cert); err != nil {
			t.Error("setenv failed", err)
		}
	}
	tomlData = strings.TrimSuffix(tomlData, ",") + `
]`
	var conf = &Config{}
	if _, err := toml.Decode(tomlData, &conf); err != nil {
		t.Error("toml decode failed", err)
	}
	checkCerts(t, conf.Certificates)
	for i, _ := range certs {
		if err := os.Unsetenv(fmt.Sprintf("ENV_CERT%d", i)); err != nil {
			t.Error("unsetenv failed", err)
		}
	}
}

func TestCertCertificateFile(t *testing.T) {
	type Config struct {
		Certificates []Certificate `toml:"certificates"`
	}
	tempdir := filepath.ToSlash(os.TempDir())
	var tomlData = `
certificates = [`
	for i, cert := range certs {
		certFile := fmt.Sprintf("%s/test_cert_%d.pem", tempdir, i)
		tomlData += fmt.Sprintf(`"%s",`, certFile)
		if err := os.WriteFile(certFile, []byte(cert), 0644); err != nil {
			t.Error(certFile, "writefile failed", err)
		}
	}
	tomlData = strings.TrimSuffix(tomlData, ",") + `
]`
	var conf = &Config{}
	if _, err := toml.Decode(tomlData, &conf); err != nil {
		t.Error("toml decode failed", err)
	}
	checkCerts(t, conf.Certificates)
	for i, _ := range certs {
		certFile := fmt.Sprintf("%s/test_cert_%d.pem", tempdir, i)
		if err := os.Remove(certFile); err != nil {
			t.Error(certFile, "remove failed", err)
		}
	}
}
