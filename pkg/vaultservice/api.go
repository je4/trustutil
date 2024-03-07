package vaultservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/je4/trustutil/v2/config"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	"github.com/je4/trustutil/v2/pkg/vaultservice/docs"
	"github.com/je4/utils/v2/pkg/zLogger"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/net/http2"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const V1BASEPATH = "/api/v1"

//	@title			miniVault API
//	@version		1.0
//	@description	minimalistic vault for generating client and server certificates
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	Jürgen Enge
//	@contact.url	https://ub.unibas.ch
//	@contact.email	juergen.enge@unibas.ch

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

func NewController(addr string, addrExt string, subpath string, cert tls.Certificate, ca *x509.Certificate, caPrivKey any, clientCerts fs.FS, logger zLogger.ZLogger, client []*config.MiniVaultClientConfig) (*controller, error) {
	u, err := url.Parse(addrExt)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid external address '%s'", addrExt)
	}
	router := gin.Default()

	// programmatically set swagger info
	docs.SwaggerInfo.Host = strings.TrimRight(fmt.Sprintf("%s:%s", u.Hostname(), u.Port()), " :")
	docs.SwaggerInfo.BasePath = "/" + strings.Trim(subpath+V1BASEPATH, "/")
	docs.SwaggerInfo.Schemes = []string{"https"}

	ctrl := &controller{
		addr:        addr,
		subpath:     subpath,
		ca:          ca,
		caPrivKey:   caPrivKey,
		logger:      logger,
		router:      router,
		client:      client,
		clientCerts: clientCerts,
	}
	return ctrl, ctrl.Init(cert)
}

type controller struct {
	server      http.Server
	router      *gin.Engine
	addr        string
	subpath     string
	logger      zLogger.ZLogger
	client      []*config.MiniVaultClientConfig
	clientCerts fs.FS
	ca          *x509.Certificate
	caPrivKey   any
	certChan    chan *tls.Certificate
}

func (ctrl *controller) Init(cert tls.Certificate) error {
	v1 := ctrl.router.Group(V1BASEPATH)

	v1.GET("/clientcert", ctrl.clientCert)

	ctrl.router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	//ctrl.router.StaticFS("/swagger/", http.FS(swaggerFiles.FS))

	tlsConfig, err := tlsutil.CreateServerTLSConfig(cert, true, []string{"cert:clientcert"})
	if err != nil {
		return errors.Wrap(err, "cannot create tls config")
	}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(ctrl.ca)
	tlsConfig.ClientCAs = x509.NewCertPool()
	tlsConfig.ClientCAs.AddCert(ctrl.ca)
	ctrl.certChan, err = tlsutil.UpgradeTLSConfigServerExchanger(tlsConfig)
	if err != nil {
		return errors.Wrap(err, "cannot upgrade tls config")
	}
	ctrl.server = http.Server{
		Addr:      ctrl.addr,
		Handler:   ctrl.router,
		TLSConfig: tlsConfig,
	}

	if err := http2.ConfigureServer(&ctrl.server, nil); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
func (ctrl *controller) Start(wg *sync.WaitGroup) {
	go func() {
		wg.Add(1)
		defer wg.Done() // let main know we are done cleaning up

		if ctrl.server.TLSConfig == nil {
			ctrl.logger.Error().Msg("no tls config set. cannot start server")
			return
		}
		fmt.Printf("starting server at https://%s\n", ctrl.addr)
		if err := ctrl.server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			// unexpected error. port in use?
			ctrl.logger.Error().Msgf("server on '%s' ended: %v", ctrl.addr, err)
		}

		// always returns error. ErrServerClosed on graceful close
	}()
}

func (ctrl *controller) Stop() {
	close(ctrl.certChan)
	ctrl.server.Shutdown(context.Background())
}

func (ctrl *controller) GracefulStop() {
	close(ctrl.certChan)
	ctrl.server.Shutdown(context.Background())
}

// clientCert godoc
// @Summary      gets GPT query context to query
// @ID			 get-client-cert
// @Description  retrieves a new minivault client access certificate
// @Tags         Vault
// @Produce      plain
// @Success      200  {string}  vaultservice.ClientCertResultMessage
// @Failure      400  {object}  vaultservice.HTTPResultMessage
// @Failure      404  {object}  vaultservice.HTTPResultMessage
// @Failure      500  {object}  vaultservice.HTTPResultMessage
// @Router       /clientcert [get]
func (ctrl *controller) clientCert(c *gin.Context) {
	state := c.Request.TLS
	if len(state.PeerCertificates) == 0 {
		NewResultMessage(c, http.StatusForbidden, errors.New("no client certificate found"))
		return
	}
	peerCert := state.PeerCertificates[0]
	clientName := peerCert.Subject.CommonName
	var client *config.MiniVaultClientConfig
	for _, cl := range ctrl.client {
		if cl.Name == clientName {
			client = cl
			break
		}
	}
	if client == nil {
		NewResultMessage(c, http.StatusNotFound, errors.Errorf("client %s is not configured", clientName))
		return
	}
	pwFile := clientName + ".pw"
	pw, err := fs.ReadFile(ctrl.clientCerts, pwFile)
	if err != nil {
		NewResultMessage(c, http.StatusNotFound, errors.Wrap(err, "cannot read password file"))
		return
	}
	pw = []byte(strings.TrimSpace(string(pw)))

	ctrl.logger.Info().Msgf("*** creating client certificate for %s", clientName)
	name := certutil.DefaultName
	name.CommonName = clientName
	ip := net.ParseIP(c.ClientIP())
	if ip == nil {
		NewResultMessage(c, http.StatusInternalServerError, errors.Errorf("cannot parse client ip %s", c.ClientIP()))
		return
	}
	clientCert, clientKey, err := certutil.CreateCertificate(true, false, time.Duration(client.Validity), ctrl.ca, ctrl.caPrivKey, []net.IP{ip}, nil, nil, nil, name, certutil.DefaultKeyType)
	if err != nil {
		NewResultMessage(c, http.StatusInternalServerError, errors.Wrap(err, "cannot create client certificate"))
		return
	}
	ctrl.logger.Info().Msg("encrypting client key")
	encClientKey, err := certutil.EncryptPrivateKey(clientKey, pw)
	if err != nil {
		NewResultMessage(c, http.StatusInternalServerError, errors.Wrap(err, "cannot encrypt client key"))
		return
	}
	NewClientCertResultMessage(c, clientCert, encClientKey)
}
