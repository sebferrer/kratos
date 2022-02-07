package driver

import (
	samlflow "github.com/ory/kratos/selfservice/flow/saml"
)

func (m *RegistryDefault) SAMLHandler() *samlflow.Handler {
	if m.selfserviceSAMLHandler == nil {
		m.selfserviceSAMLHandler = samlflow.NewHandler(m)
	}

	return m.selfserviceSAMLHandler
}

func (m *RegistryDefault) SAMLAuthFlowErrorHandler() *samlflow.ErrorHandler {
	if m.selfserviceSAMLAuthRequestErrorHandler == nil {
		m.selfserviceSAMLAuthRequestErrorHandler = samlflow.NewFlowErrorHandler(m)
	}

	return m.selfserviceSAMLAuthRequestErrorHandler
}
