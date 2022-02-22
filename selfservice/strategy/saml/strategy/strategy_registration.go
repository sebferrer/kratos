package strategy

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
	samlsp "github.com/ory/kratos/selfservice/strategy/saml"

	"github.com/tidwall/gjson"

	"github.com/ory/kratos/text"
	"github.com/ory/kratos/x"
)

var _ registration.Strategy = new(Strategy)

func (s *Strategy) RegisterRegistrationRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
}

func (s *Strategy) PopulateRegistrationMethod(r *http.Request, f *registration.Flow) error {
	if f.Type != flow.TypeBrowser {
		return nil
	}

	return s.populateMethod(r, f.UI, text.NewInfoRegistrationWith)
}

func (s *Strategy) Register(w http.ResponseWriter, r *http.Request, f *registration.Flow, i *identity.Identity) (err error) {
	return nil
}

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, provider samlsp.Provider, claims *samlsp.Claims) (*login.Flow, error) {
	jn, err := s.f.Fetch(provider.Config().Mapper)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}
	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
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

	s.d.Logger().
		WithRequest(r).
		WithField("saml_provider", provider.Config().ID).
		WithSensitiveField("saml_claims", claims).
		WithSensitiveField("mapper_jsonnet_output", evaluated).
		WithField("mapper_jsonnet_url", provider.Config().Mapper).
		Debug("SAML Jsonnet mapper completed.")

	s.d.Logger().
		WithRequest(r).
		WithField("saml_provider", provider.Config().ID).
		WithSensitiveField("identity_traits", i.Traits).
		WithSensitiveField("mapper_jsonnet_output", evaluated).
		WithField("mapper_jsonnet_url", provider.Config().Mapper).
		Debug("Merged form values and SAML Jsonnet output.")

	if err := s.d.IdentityValidator().Validate(r.Context(), i); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	creds, err := NewCredentialsForSAML(claims.Subject, provider.Config().ID)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	i.SetCredentials(s.ID(), *creds)

	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeSAML, a, i); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	return nil, nil
}
