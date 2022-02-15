package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	samlidp "github.com/crewjam/saml"
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

// swagger:route GET /self-service/methods/saml/browser v0alpha2 initializeSelfServiceSamlFlowForBrowsers
//
// Initialize Registration Flow for APIs, Services, Apps, ...
//
// This endpoint initiates a registration flow for API clients such as mobile devices, smart TVs, and so on.
//
// If a valid provided session cookie or session token is provided, a 400 Bad Request error
// will be returned unless the URL query parameter `?refresh=true` is set.
//
// To fetch an existing registration flow call `/self-service/registration/flows?flow=<flow_id>`.
//
// You MUST NOT use this endpoint in client-side (Single Page Apps, ReactJS, AngularJS) nor server-side (Java Server
// Pages, NodeJS, PHP, Golang, ...) browser applications. Using this endpoint in these applications will make
// you vulnerable to a variety of CSRF attacks.
//
// In the case of an error, the `error.id` of the JSON response body can be one of:
//
// - `session_already_available`: The user is already signed in.
// - `security_csrf_violation`: Unable to fetch the flow because a CSRF violation occurred.
//
// This endpoint MUST ONLY be used in scenarios such as native mobile apps (React Native, Objective C, Swift, Java, ...).
//
// More information can be found at [Ory Kratos User Login and User Registration Documentation](https://www.ory.sh/docs/next/kratos/self-service/flows/user-login-user-registration).
//
//     Schemes: http, https
//
//     Responses:
//       200: selfServiceRegistrationFlow
//       400: jsonError
//       500: jsonError
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if samlMiddleware == nil {
		if err := h.instantiateMiddleware(r); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		}
	}

	conf := h.d.Config(r.Context())

	if _, err := h.d.SessionManager().FetchFromRequest(r.Context(), r); err != nil {
		if e := new(session.ErrNoActiveSessionFound); errors.As(err, &e) {
			// No session exists yet

			samlMiddleware.HandleStartAuthFlow(w, r)
		} else {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		}
	} else {
		http.Redirect(w, r, conf.SelfServiceBrowserDefaultReturnTo().Path, http.StatusTemporaryRedirect)
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

	keyPair, err := tls.LoadX509KeyPair(strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].PublicCertPath, "file://", "", 1), strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].PrivateKeyPath, "file://", "", 1))
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	var idpMetadata *samlidp.EntityDescriptor

	if c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_metadata_url"] != "" {
		//The metadata file is provided
		idpMetadataURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_metadata_url"])
		if err != nil {
			return err
		}

		idpMetadata, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
		if err != nil {
			return err
		}
	} else {
		//The metadata file is not provided
		// So were are creating fake IDP metadata based on what is provided by the user on the config file
		entityIDURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_entity_id"]) //A modifier
		if err != nil {
			return err
		}

		IDPSSOURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_sso_url"])
		if err != nil {
			return err
		}

		IDPlogoutURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_logout_url"])
		if err != nil {
			return err
		}
		certificate, err := ioutil.ReadFile(strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_certificate_path"], "file://", "", 1))
		if err != nil {
			return err
		}

		IDPCertificate := mustParseCertificate(certificate)

		simulatedIDP := samlidp.IdentityProvider{
			Key:         nil,
			Certificate: IDPCertificate,
			Logger:      nil,
			MetadataURL: *entityIDURL,
			SSOURL:      *IDPSSOURL,
			LogoutURL:   *IDPlogoutURL,
		}

		idpMetadata = simulatedIDP.Metadata()

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

	RouteSamlAcsWithSlash := RouteSamlAcs

	if RouteSamlAcs[0] != '/' && publicUrlString[len(publicUrlString)-1] != '/' {
		u, err := url.Parse(publicUrlString + "/" + RouteSamlAcsWithSlash)
		if err != nil {
			return err
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	} else if RouteSamlAcs[0] == '/' && publicUrlString[len(publicUrlString)-1] == '/' {

		publicUrlStringWithoutSlash := strings.ReplaceAll(publicUrlString, "/", "")
		u, err := url.Parse(publicUrlStringWithoutSlash + RouteSamlAcsWithSlash)
		if err != nil {
			return err
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	} else {
		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return err
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	}

	samlMiddleware = samlMiddleWare

	return nil
}

func GetMiddleware() (*samlsp.Middleware, error) {
	if samlMiddleware == nil {
		return nil, errors.Errorf("The MiddleWare for SAML is null (Probably due to a backward step)")
	}
	return samlMiddleware, nil
}

func mustParseCertificate(pemStr []byte) *x509.Certificate {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}
