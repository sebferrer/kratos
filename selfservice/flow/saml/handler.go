package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
)

const (
	RouteSamlMetadata  = "/self-service/saml/metadata"
	RouteSamlAcs       = "/self-service/saml/acs"
	RouteSamlLoginInit = "/self-service/saml/browser"
)

var ErrNoSession = errors.New("saml: session not present")

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
		d              handlerDependencies
		dx             *decoderx.HTTP
		samlMiddleware *samlsp.Middleware
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

func NewHandler(d handlerDependencies, ctx context.Context) *Handler {
	middleware, err := instantiateMiddleware(d.Config(ctx))
	if err != nil {
		panic(err)
	}
	return &Handler{
		d:              d,
		dx:             decoderx.NewHTTP(),
		samlMiddleware: middleware,
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
	router.POST(RouteSamlAcs, h.serveAcs)
}

func (h *Handler) submitMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	h.samlMiddleware.ServeMetadata(w, r)

}

// swagger:route GET /self-service/saml/browser v0alpha2 initializeSelfServiceSamlFlowForBrowsers
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	conf := h.d.Config(r.Context())
	_, err := h.d.SessionManager().FetchFromRequest(r.Context(), r)

	session, err := h.samlMiddleware.Session.GetSession(r)

	if session != nil {
		http.Redirect(w, r, conf.SelfPublicURL().Path, http.StatusTemporaryRedirect)
	}
	if err == ErrNoSession {
		h.samlMiddleware.HandleStartAuthFlow(w, r)
		return
	}

	//if e := new(session.ErrNoActiveSessionFound); errors.As(err, &e) {
	// No session
	//h.samlMiddleware.HandleStartAuthFlow(w, r)
	//} else if err != nil {
	// Some other error happened
	//} else {
	// A session exists already
	//http.Redirect(w, r, conf.SelfPublicURL().Path, http.StatusTemporaryRedirect)
	//}

	//h.samlMiddleware.OnError(w, r, err)

}

func (h *Handler) serveAcs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	r.ParseForm()

	possibleRequestIDs := []string{}
	if h.samlMiddleware.ServiceProvider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := h.samlMiddleware.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := h.samlMiddleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		h.samlMiddleware.OnError(w, r, err)
	}
	h.samlMiddleware.CreateSessionFromAssertion(w, r, assertion, h.samlMiddleware.ServiceProvider.DefaultRedirectURI)

}

func instantiateMiddleware(conf *config.Config) (*samlsp.Middleware, error) {

	keyPair, err := tls.LoadX509KeyPair(conf.SamlPublicCertPath().Path, conf.SamlPrivateKeyPath().Path)
	if err != nil {
		return nil, err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}

	idpMetadataURL, err := url.Parse(conf.SamlIdpMetadataUrl().String())
	if err != nil {
		return nil, err
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		return nil, err
	}

	rootURL, err := url.Parse(conf.SelfServiceBrowserDefaultReturnTo().String())
	if err != nil {
		return nil, err
	}

	samlMiddleware, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	if err != nil {
		return nil, err
	}

	var publicUrlString = conf.SelfPublicURL().String()
	u, err := url.Parse(publicUrlString + RouteSamlAcs)
	if err != nil {
		return nil, err
	}
	samlMiddleware.ServiceProvider.AcsURL = *u

	return samlMiddleware, nil
}
