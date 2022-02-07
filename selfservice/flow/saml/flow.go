package saml

import (
	"context"
	"time"

	"github.com/ory/x/sqlxx"

	"github.com/ory/kratos/ui/container"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
)

type FlowPersister interface {
	UpdateRegistrationFlow(context.Context, *Flow) error
	CreateRegistrationFlow(context.Context, *Flow) error
	GetRegistrationFlow(context.Context, uuid.UUID) (*Flow, error)
}

type FlowPersistenceProvider interface {
	RegistrationFlowPersister() FlowPersister
}

// swagger:model selfServiceRegistrationFlow
type Flow struct {
	// ID represents the flow's unique ID. When performing the registration flow, this
	// represents the id in the registration ui's query parameter: http://<selfservice.flows.registration.ui_url>/?flow=<id>
	//
	// required: true
	ID uuid.UUID `json:"id" faker:"-" db:"id"`

	// Type represents the flow's type which can be either "api" or "browser", depending on the flow interaction.
	Type flow.Type `json:"type" db:"type" faker:"flow_type"`

	// ExpiresAt is the time (UTC) when the flow expires. If the user still wishes to log in,
	// a new flow has to be initiated.
	//
	// required: true
	ExpiresAt time.Time `json:"expires_at" faker:"time_type" db:"expires_at"`

	// IssuedAt is the time (UTC) when the flow occurred.
	//
	// required: true
	IssuedAt time.Time `json:"issued_at" faker:"time_type" db:"issued_at"`

	// InternalContext stores internal context used by internals - for example MFA keys.
	InternalContext sqlxx.JSONRawMessage `db:"internal_context" json:"-" faker:"-"`

	// RequestURL is the initial URL that was requested from Ory Kratos. It can be used
	// to forward information contained in the URL's path or query for example.
	//
	// required: true
	RequestURL string `json:"request_url" faker:"url" db:"request_url"`

	// ReturnTo contains the requested return_to URL.
	ReturnTo string `json:"return_to,omitempty" db:"-"`

	// Active, if set, contains the registration method that is being used. It is initially
	// not set.
	Active identity.CredentialsType `json:"active,omitempty" faker:"identity_credentials_type" db:"active_method"`

	// UI contains data which must be shown in the user interface.
	//
	// required: true
	UI *container.Container `json:"ui" db:"ui"`

	// CreatedAt is a helper struct field for gobuffalo.pop.
	CreatedAt time.Time `json:"-" faker:"-" db:"created_at"`

	// UpdatedAt is a helper struct field for gobuffalo.pop.
	UpdatedAt time.Time `json:"-" faker:"-" db:"updated_at"`

	// CSRFToken contains the anti-csrf token associated with this flow. Only set for browser flows.
	CSRFToken string    `json:"-" db:"csrf_token"`
	NID       uuid.UUID `json:"-"  faker:"-" db:"nid"`
}
