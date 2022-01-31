package strategy

import (
	"errors"
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	samlsp "github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/x/sqlcon"
)

func (s *Strategy) processLoginOrRegister(w http.ResponseWriter, r *http.Request, provider samlsp.Provider, claims *samlsp.Claims) (*flow.Flow, error) {

	i, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, claims.Subject) //We retrieve the identity from the DB

	if err != nil {
		if errors.Is(err, sqlcon.ErrNoRows) { //We check that the user exists in the database, if not, we register him
			registerFlow, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, flow.TypeBrowser)
			if err != nil {
				return nil, s.handleError(w, r, registerFlow, provider.Config().ID, i.Traits, err)
			}
			if _, err = s.processRegistration(w, r, registerFlow, provider, claims); err != nil {
				return nil, s.handleError(w, r, registerFlow, provider.Config().ID, i.Traits, err)
			}

			return nil, nil

		} else {
			loginFlow, err := s.d.LoginHandler().NewLoginFlow(w, r, flow.TypeBrowser) //If the user is already register, we create a login flow to connect him
			if err != nil {
				return nil, s.handleError(w, r, loginFlow, provider.Config().ID, i.Traits, err)
			}
			if _, err = s.processLogin(w, r, loginFlow, provider, i, claims); err != nil {
				return nil, s.handleError(w, r, loginFlow, provider.Config().ID, i.Traits, err)
			}
			return nil, nil

		}
	} else {
		return nil, nil
	}
}
