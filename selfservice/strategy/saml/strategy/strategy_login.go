package strategy

import (
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	samlsp "github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/x"
)

var _ login.Strategy = new(Strategy)

func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
}

func (s *Strategy) processLogin(w http.ResponseWriter, r *http.Request, a *login.Flow, provider samlsp.Provider, i *identity.Identity, claims *samlsp.Claims) (*registration.Flow, error) {

	sess := session.NewInactiveSession() //creation of an inactive session
	sess.CompletedLoginFor(s.ID())       //Add saml to the Authentication Method References

	if err := s.d.LoginHookExecutor().PostLoginHook(w, r, a, i, sess); err != nil {
		return nil, s.handleError(w, r, a, "saml", nil, err)
	}

	return nil, nil
}

func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, ss *session.Session) (i *identity.Identity, err error) {
	return nil, nil
}

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, l *login.Flow) error {
	if l.Type != flow.TypeBrowser {
		return nil
	}

	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	return s.populateMethod(r, l.UI, text.NewInfoLoginWith)
}
