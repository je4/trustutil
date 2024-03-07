package vaultclient

import (
	"bytes"
	"crypto/tls"
	"emperror.dev/errors"
	"encoding/json"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	"github.com/je4/trustutil/v2/pkg/vaultservice"
	"net/http"
)

func NewClient(baseURL string, clientCert tls.Certificate, caPEM []byte) (*Client, error) {
	tlsConfig, err := tlsutil.CreateClientMTLSConfig(clientCert, caPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create client mTLS config")
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &Client{
		Client: http.Client{
			Transport: tr,
		},
		baseURL: baseURL,
	}, nil
}

type Client struct {
	http.Client
	baseURL string
}

func (c *Client) GetClientCertificate() (tls.Certificate, error) {
	resp, err := c.Get(c.baseURL + "/clientcert")
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "cannot get client certificate")
	}
	defer resp.Body.Close()
	buf := bytes.NewBuffer(nil)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "cannot read client certificate")
	}
	if resp.StatusCode != http.StatusOK {
		errMsg := &vaultservice.HTTPResultMessage{}
		if err := json.Unmarshal(buf.Bytes(), errMsg); err != nil {
			return tls.Certificate{}, errors.Wrap(err, "cannot unmarshal error message")
		}
		return tls.Certificate{}, errors.New(errMsg.Message)
	}
	result := &vaultservice.HTTPCertResult{}
	if err := json.Unmarshal(buf.Bytes(), result); err != nil {
		return tls.Certificate{}, errors.Wrap(err, "cannot unmarshal client certificate")
	}

	cert, err := tls.X509KeyPair([]byte(result.Cert), []byte(result.Key))
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "cannot create certificate key pair")
	}
	return cert, nil
}
