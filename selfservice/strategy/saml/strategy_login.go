package saml

import (
	"errors"
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/session"
	"github.com/ory/x/sqlcon"
)

func (s *Strategy) processLogin(w http.ResponseWriter, r *http.Request, a *login.Flow, claims *Claims) (*registration.Flow, error) {

	i, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeOIDC, claims.Subject)
	if err != nil {
		if errors.Is(err, sqlcon.ErrNoRows) {

			s.d.Logger().WithField("provider", "SAML").WithField("subject", claims.Subject).Debug("Received successful OpenID Connect callback but user is not registered. Re-initializing registration flow now.")
			//HANDLE REGISTER ACCOUNT en recuperant les infos dans l'assertion SAML
		}
	}

	//ensuite on démarre la session
	sess := session.NewInactiveSession()
	sess.CompletedLoginFor(s.ID())

	var o CredentialsConfig
	for _, c := range o.Providers {
		if c.Subject == claims.Subject {
			if err = s.d.LoginHookExecutor().PostLoginHook(w, r, a, i, sess); err != nil {
				return nil, s.handleError(w, r, a, "saml", nil, err)
			}
			return nil, nil
		}
	}
	s.d.LoginHookExecutor().PostLoginHook(w, r, a, i, sess)

	return nil, s.handleError(w, r, a, "saml", nil, err)

}
