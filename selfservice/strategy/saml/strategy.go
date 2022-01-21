package saml

import (
	"fmt"
	"net/http"

	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"

	"github.com/go-playground/validator/v10"

	"github.com/ory/x/decoderx"

	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/hash"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

type registrationStrategyDependencies interface {
	x.LoggingProvider
	x.WriterProvider
	x.CSRFTokenGeneratorProvider
	x.CSRFProvider

	config.Provider

	continuity.ManagementProvider

	errorx.ManagementProvider
	hash.HashProvider

	registration.HandlerProvider
	registration.HooksProvider
	registration.ErrorHandlerProvider
	registration.HookExecutorProvider
	registration.FlowPersistenceProvider

	login.HooksProvider
	login.ErrorHandlerProvider
	login.HookExecutorProvider
	login.FlowPersistenceProvider
	login.HandlerProvider

	settings.FlowPersistenceProvider
	settings.HookExecutorProvider
	settings.HooksProvider
	settings.ErrorHandlerProvider

	identity.PrivilegedPoolProvider
	identity.ValidationProvider

	session.HandlerProvider
	session.ManagementProvider
}

type Strategy struct {
	d  registrationStrategyDependencies
	v  *validator.Validate
	hd *decoderx.HTTP
}

func NewStrategy(d registrationStrategyDependencies) *Strategy {
	return &Strategy{
		d:  d,
		v:  validator.New(),
		hd: decoderx.NewHTTP(),
	}
}

func (s *Strategy) CountActiveCredentials(cc map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	return
}

func (s *Strategy) ID() identity.CredentialsType {
	return identity.CredentialsTypePassword
}

func (s *Strategy) NodeGroup() node.Group {
	return node.PasswordGroup
}

func (s *Strategy) handleError(w http.ResponseWriter, r *http.Request, f flow.Flow, provider string, traits []byte, err error) error {
	switch rf := f.(type) {
	case *login.Flow:
		return err
	case *registration.Flow:
		// Reset all nodes to not confuse users.
		// This is kinda hacky and will probably need to be updated at some point.

		rf.UI.Nodes = node.Nodes{}

		// Adds the "Continue" button
		rf.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		//AddProvider(rf.UI, provider, text.NewInfoRegistrationContinue())

		if traits != nil {
			traitNodes, err := container.NodesFromJSONSchema(node.OpenIDConnectGroup,
				s.d.Config(r.Context()).DefaultIdentityTraitsSchemaURL().String(), "", nil)
			if err != nil {
				return err
			}

			rf.UI.Nodes = append(rf.UI.Nodes, traitNodes...)
			rf.UI.UpdateNodeValuesFromJSON(traits, "traits", node.OpenIDConnectGroup)
		}

		return err
	case *settings.Flow:
		return err
	}

	return err
}

func uid(provider, subject string) string {
	return fmt.Sprintf("%s:%s", provider, subject)
}
