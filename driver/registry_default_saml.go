package driver

import (
	"context"

	"github.com/ory/kratos/selfservice/flow/saml"
)

func (m *RegistryDefault) SamlHandler(ctx context.Context) *saml.Handler {
	if m.selfserviceSamlHandler == nil {
		m.selfserviceSamlHandler = saml.NewHandler(m, ctx)
	}

	return m.selfserviceSamlHandler
}
