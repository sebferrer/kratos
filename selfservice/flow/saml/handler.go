package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	samlstrategy "github.com/ory/kratos/selfservice/strategy/saml"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/jsonx"
)

const (
	RouteSamlMetadata  = "/self-service/methods/saml/metadata"
	RouteSamlLoginInit = "/self-service/methods/saml/browser"
	RouteSamlAcs       = "/self-service/methods/saml/acs"
)

var ErrNoSession = errors.New("saml: session not present")
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

type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    samlsp.SessionCodec
}

func NewHandler(d handlerDependencies) *Handler {
	return &Handler{
		d:  d,
		dx: decoderx.NewHTTP(),
	}
}

// swagger:model selfServiceSamlUrl
type selfServiceSamlUrl struct {
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

	h.d.CSRFHandler().IgnorePath(RouteSamlLoginInit)
	h.d.CSRFHandler().IgnorePath(RouteSamlAcs)

	router.GET(RouteSamlMetadata, h.submitMetadata)
	router.GET(RouteSamlLoginInit, h.loginWithIdp)
}

func (h *Handler) submitMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if samlMiddleware == nil {
		h.instantiateMiddleware(r)
	}

	samlMiddleware.ServeMetadata(w, r)

}

// swagger:route GET /self-service/saml/browser v0alpha2 initializeSelfServiceSamlFlowForBrowsers
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if samlMiddleware == nil {
		if err := h.instantiateMiddleware(r); err != nil {
			panic(err)
		}
	}
	fmt.Println("TEST", samlMiddleware.ServiceProvider.IDPMetadata)
	if samlMiddleware == nil {
		fmt.Println("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
		panic("FUCK")

	}

	conf := h.d.Config(r.Context())
	fmt.Println("YOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")

	_, err := h.d.SessionManager().FetchFromRequest(r.Context(), r)
	if e := new(session.ErrNoActiveSessionFound); errors.As(err, &e) {
		// No session exists yet
		fmt.Println("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP")
		fmt.Println(r.URL.Query())
		fmt.Println("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP")
		samlMiddleware.HandleStartAuthFlow(w, r)
		return

	} else {

		http.Redirect(w, r, conf.SelfPublicURL().Path, http.StatusTemporaryRedirect)

	}

}

func (h *Handler) instantiateMiddleware(r *http.Request) error {
	config := h.d.Config(r.Context())

	var c samlstrategy.ConfigurationCollection

	conf := config.SelfServiceStrategy("saml").Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return errors.Wrapf(err, "Unable to decode config %v", string(conf))
	}

	keyPair, err := tls.LoadX509KeyPair(c.SAMLProviders[0].PublicCertPath, c.SAMLProviders[0].PrivateKeyPath)
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	idpMetadataURL, err := url.Parse(c.SAMLProviders[0].IDPMetadataURL)
	if err != nil {
		return err
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		return err
	}

	rootURL, err := url.Parse(config.SelfServiceBrowserDefaultReturnTo().String())
	if err != nil {
		return err
	}

	samlMiddleWare, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	if err != nil {
		return err
	}

	var publicUrlString = config.SelfPublicURL().String()
	u, err := url.Parse(publicUrlString + RouteSamlAcs)
	if err != nil {
		return err
	}
	samlMiddleWare.ServiceProvider.AcsURL = *u

	samlMiddleware = samlMiddleWare
	return nil
}

func GetMiddleware() *samlsp.Middleware {
	return samlMiddleware
}
