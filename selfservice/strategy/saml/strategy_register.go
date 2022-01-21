package saml

import (
	"net/http"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"golang.org/x/oauth2"
)

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, token *oauth2.Token, claims *Claims) (*login.Flow, error) {

	if _, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeOIDC, claims.Subject); err == nil {

		s.d.Logger().WithRequest(r).WithField("provider", "saml").
			WithField("subject", claims.Subject).
			Debug("Received successful OpenID Connect callback but user is already registered. Re-initializing login flow now.")

		// This endpoint only handles browser flow at the moment.
		ar, err := s.d.LoginHandler().NewLoginFlow(w, r, flow.TypeBrowser)
		if err != nil {
			return nil, s.handleError(w, r, a, "saml", nil, err)
		}

		if _, err := s.processLogin(w, r, ar, claims); err != nil {
			return ar, err
		}
		return nil, nil

	}

	//caler tous les traits
	i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)

	creds, err := NewCredentialsForSaml(claims.Subject)
	if err != nil {
		return nil, s.handleError(w, r, a, "saml", i.Traits, err)
	}

	i.SetCredentials(s.ID(), *creds)
	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeOIDC, a, i); err != nil {
		return nil, s.handleError(w, r, a, "saml", i.Traits, err)
	}

	return nil, nil

}
