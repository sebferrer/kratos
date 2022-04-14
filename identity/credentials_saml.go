package identity

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/ory/kratos/x"
)

// CredentialsSAML is contains the configuration for credentials of the type saml.
//
// swagger:model identityCredentialsSaml
type CredentialsSAML struct {
	Providers []CredentialsSAMLProvider `json:"providers"`
}

// CredentialsSAMLProvider is contains a specific saml credential
//
// swagger:model identityCredentialsSamlProvider
type CredentialsSAMLProvider struct {
	Subject  string `json:"subject"`
	Provider string `json:"provider"`
}

// NewCredentialsSAML creates a new SAML credential.
func NewCredentialsSAML(idToken, accessToken, refreshToken, provider, subject string) (*Credentials, error) {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(CredentialsSAML{
		Providers: []CredentialsSAMLProvider{
			{
				Subject:  subject,
				Provider: provider,
			}},
	}); err != nil {
		return nil, errors.WithStack(x.PseudoPanic.
			WithDebugf("Unable to encode password options to JSON: %s", err))
	}

	return &Credentials{
		Type:        CredentialsTypeSAML,
		Identifiers: []string{SAMLUniqueID(provider, subject)},
		Config:      b.Bytes(),
	}, nil
}

func SAMLUniqueID(provider, subject string) string {
	return fmt.Sprintf("%s:%s", provider, subject)
}
