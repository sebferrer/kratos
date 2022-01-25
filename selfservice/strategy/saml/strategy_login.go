package saml

import (
	"errors"
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/session"
	"github.com/ory/x/sqlcon"
)

func (s *Strategy) processLogin(w http.ResponseWriter, r *http.Request, a *login.Flow, provider Provider, claims *Claims) (*registration.Flow, error) {
	i, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, claims.Subject) //We retrieve the identity from the DB

	if err != nil {
		if errors.Is(err, sqlcon.ErrNoRows) { //We check that the user exists in the database, if not, we register him

			aa, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, flow.TypeBrowser) //Creation of a register flow
			if err != nil {
				return nil, s.handleError(w, r, a, "saml", nil, err)
			}

			if _, err := s.processRegistration(w, r, aa, provider, claims); err != nil { //We register the user
				return aa, err
			}

			return nil, nil
		}
	}

	sess := session.NewInactiveSession() //creation of an inactive session
	sess.CompletedLoginFor(s.ID())       //Add saml to the Authentication Method References

	if err = s.d.LoginHookExecutor().PostLoginHook(w, r, a, i, sess); err != nil {
		return nil, s.handleError(w, r, a, "saml", nil, err)
	}
	return nil, nil

}
