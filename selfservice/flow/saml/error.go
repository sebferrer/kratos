package saml

import (
	"net/http"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
)

type (
	errorHandlerDependencies interface {
		errorx.ManagementProvider
		x.WriterProvider
		x.LoggingProvider
		config.Provider

		FlowPersistenceProvider
		HandlerProvider
	}

	ErrorHandlerProvider interface{ SAMLAuthFlowErrorHandler() *ErrorHandler }

	ErrorHandler struct {
		d errorHandlerDependencies
	}
)

func NewFlowErrorHandler(d errorHandlerDependencies) *ErrorHandler {
	return &ErrorHandler{d: d}
}

func (s *ErrorHandler) WriteFlowError(w http.ResponseWriter, r *http.Request, group node.Group, err error) {
	s.d.Audit().
		WithError(err).
		WithRequest(r).
		WithField("auth_flow", "SAML").
		Info("Encountered self-service auth error.")

	s.forward(w, r, err)
	return
}

func (s *ErrorHandler) forward(w http.ResponseWriter, r *http.Request, err error) {
	if x.IsJSONRequest(r) {
		s.d.Writer().WriteError(w, r, err)
		return
	}
	s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
	return

}
