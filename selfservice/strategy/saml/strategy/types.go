package strategy

import (
	"bytes"
	"encoding/json"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"

	"github.com/pkg/errors"
)

type CredentialsConfig struct {
	Providers []ProviderCredentialsConfig `json:"providers"`
}

func NewCredentialsForSAML(subject string) (*identity.Credentials, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(CredentialsConfig{
		Providers: []ProviderCredentialsConfig{
			{
				Subject: subject,
			}},
	}); err != nil {
		return nil, errors.WithStack(x.PseudoPanic.
			WithDebugf("Unable to encode password options to JSON: %s", err))
	}

	return &identity.Credentials{
		Type:        identity.CredentialsTypeSAML,
		Identifiers: []string{uid("saml", subject)},
		Config:      b.Bytes(),
	}, nil
}

func AddProvider(c *container.Container, providerID string, message *text.Message) {
	c.GetNodes().Append(
		node.NewInputField("provider", providerID, node.OpenIDConnectGroup, node.InputAttributeTypeSubmit).WithMetaLabel(message),
	)
}

type ProviderCredentialsConfig struct {
	Subject string `json:"subject"`
}

type FlowMethod struct {
	*container.Container
}
