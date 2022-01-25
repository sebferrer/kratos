package saml

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/google/go-jsonnet"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/tidwall/gjson"
)

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, provider Provider, claims *Claims) (*login.Flow, error) {

	if _, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeOIDC, claims.Subject); err == nil { //We check if the user is present in the DB

		s.d.Logger().WithRequest(r).WithField("provider", "saml").
			WithField("subject", claims.Subject).
			Debug("Received successful SAML Assertion but user is already registered. Re-initializing login flow now.")

		// This endpoint only handles browser flow at the moment.
		ar, err := s.d.LoginHandler().NewLoginFlow(w, r, flow.TypeBrowser) //If the user is already register, we create a login flow to connect him
		if err != nil {
			return nil, s.handleError(w, r, a, "saml", nil, err)
		}

		if _, err := s.processLogin(w, r, ar, provider, claims); err != nil { //Process the login
			return ar, err
		}
		return nil, nil

	}

	jn, err := s.f.Fetch(provider.Config().Mapper)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return nil, s.handleError(w, r, a, "saml", nil, err)
	}

	i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID) // identity creation

	vm := jsonnet.MakeVM()
	vm.ExtCode("claims", jsonClaims.String())
	evaluated, err := vm.EvaluateAnonymousSnippet(provider.Config().Mapper, jn.String())
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	} else if traits := gjson.Get(evaluated, "identity.traits"); !traits.IsObject() {
		i.Traits = []byte{'{', '}'}
		s.d.Logger().
			WithRequest(r).
			WithField("Provider", provider.Config().ID).
			WithSensitiveField("saml_claims", claims).
			WithField("mapper_jsonnet_output", evaluated).
			WithField("mapper_jsonnet_url", provider.Config().Mapper).
			Error("SAML Jsonnet mapper did not return an object for key identity.traits. Please check your Jsonnet code!")
	} else {
		i.Traits = []byte(traits.Raw)
	}

	creds, err := NewCredentialsForSAML(claims.Subject)
	if err != nil {
		return nil, s.handleError(w, r, a, "saml", i.Traits, err)
	}

	i.SetCredentials(s.ID(), *creds)
	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeSAML, a, i); err != nil {
		return nil, s.handleError(w, r, a, "saml", i.Traits, err)
	}

	return nil, nil

}
