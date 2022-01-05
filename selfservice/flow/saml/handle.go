package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
)

const (
	RouteSamlMetadata = "/self-service/saml/metadata"
	RouteSamlAcs      = "/self-service/saml/acs"
)

var samlMiddleware *samlsp.Middleware

type (
	handlerDependencies interface {
		x.WriterProvider
		x.CSRFProvider
		session.ManagementProvider
		session.PersistenceProvider
		errorx.ManagementProvider
		config.Provider
	}
	HandlerProvider interface {
		LogoutHandler() *Handler
	}
	Handler struct {
		d  handlerDependencies
		dx *decoderx.HTTP
	}
)

func NewHandler(d handlerDependencies) *Handler {

	return &Handler{
		d:  d,
		dx: decoderx.NewHTTP(),
	}

}

// swagger:model selfServiceLogoutUrl
type selfServiceLogoutUrl struct {
	// SamlMetadataURL is a get endpoint to get the metadata
	//
	// format: uri
	// required: true
	SamlMetadataURL string `json:"saml_metadata_url"`

	// SamlAcsURL is a post endpoint to handle SAML Response
	//
	// format: uri
	// required: true
	SamlAcsURL string `json:"saml_acs_url"`
}

func (h *Handler) RegisterPublicRoutes(router *x.RouterPublic) {

	router.GET(RouteSamlMetadata, h.submitMetadata)
	router.POST(RouteSamlAcs, h.handleResponse)
}

func (h *Handler) submitMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if samlMiddleware == nil {
		h.instantiateMiddleware(r)
	}

	samlMiddleware.ServeMetadata(w, r)

}

func (h *Handler) handleResponse(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if samlMiddleware == nil {
		h.instantiateMiddleware(r)
	}

	samlMiddleware.ServeACS(w, r)

}

func (h *Handler) instantiateMiddleware(r *http.Request) {

	conf := h.d.Config(r.Context())

	keyPair, err := tls.LoadX509KeyPair(conf.SamlPublicCertPath().Path, conf.SamlPrivateKeyPath().Path)
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(conf.SamlIdpMetadataUrl().String())
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse(conf.SelfServiceBrowserDefaultReturnTo().String())
	if err != nil {
		panic(err) // TODO handle error
	}

	samlMiddleware, _ = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})

}
