package continuity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/x/sqlcon"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"

	samlhandler "github.com/ory/kratos/selfservice/flow/saml"
)

var _ Manager = new(ManagerRelayState)
var ErrNotResumableRelayState = *herodot.ErrBadRequest.WithError("no resumable session found").WithReasonf("The browser does not contain the necessary RelayState value to resume the session. This is a security violation and was blocked. Please try again!")

type (
	managerRelayStateDependencies interface {
		PersistenceProvider
		x.RelayStateProvider
		session.ManagementProvider
	}
	ManagerRelayState struct {
		d managerRelayStateDependencies
	}
)

// To ensure continuity even after redirection to the IDP, we cannot use cookies because the IDP and the SP are on two different domains.
// So we have to pass the continuity value through the relaystate.
// This value corresponds to the session ID
func NewManagerRelayState(d managerRelayStateDependencies) *ManagerRelayState {
	return &ManagerRelayState{d: d}
}

func (m *ManagerRelayState) Pause(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, opts ...ManagerOption) error {
	if len(name) == 0 {
		return errors.Errorf("continuity container name must be set")
	}

	o, err := newManagerOptions(opts)
	if err != nil {
		return err
	}
	c := NewContainer(name, *o)

	// Here we put the user's session ID in the relaystate to ensure continuity for the POST method
	if err = x.SessionPersistValuesRelayState(r, c.ID.String()); err != nil {
		return errors.WithStack(err)
	}

	if err := m.d.ContinuityPersister().SaveContinuitySession(r.Context(), c); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (m *ManagerRelayState) Continue(ctx context.Context, w http.ResponseWriter, r *http.Request, name string, opts ...ManagerOption) (*Container, error) {
	container, err := m.container(ctx, w, r, name)
	if err != nil {
		return nil, err
	}

	o, err := newManagerOptions(opts)
	if err != nil {
		return nil, err
	}

	if err := container.Valid(o.iid); err != nil {
		return nil, err
	}

	if o.payloadRaw != nil && container.Payload != nil {
		if err := json.NewDecoder(bytes.NewBuffer(container.Payload)).Decode(o.payloadRaw); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	if err := x.SessionUnsetRelayState(&samlhandler.RelayStateValue); err != nil {
		return nil, err
	}

	if err := m.d.ContinuityPersister().DeleteContinuitySession(ctx, container.ID); err != nil && !errors.Is(err, sqlcon.ErrNoRows) {
		return nil, err
	}

	return container, nil
}

func (m *ManagerRelayState) sid(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, error) {
	var sid uuid.UUID
	if s, err := x.SessionGetStringRelayState(r); err != nil {
		_ = x.SessionUnsetRelayState(&samlhandler.RelayStateValue)
		return sid, errors.WithStack(ErrNotResumable.WithDebugf("%+v", err))

	} else if sid = x.ParseUUID(s); sid == uuid.Nil {
		_ = x.SessionUnsetRelayState(&samlhandler.RelayStateValue)
		return sid, errors.WithStack(ErrNotResumable.WithDebug("session id is not a valid uuid"))

	}

	return sid, nil
}

func (m *ManagerRelayState) container(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) (*Container, error) {
	sid, err := m.sid(ctx, w, r, name)
	if err != nil {
		return nil, err
	}

	container, err := m.d.ContinuityPersister().GetContinuitySession(ctx, sid)

	if err != nil {
		_ = x.SessionUnsetRelayState(&samlhandler.RelayStateValue)
	}

	if errors.Is(err, sqlcon.ErrNoRows) {
		return nil, errors.WithStack(ErrNotResumable.WithDebugf("Resumable ID from RelayState could not be found in the datastore: %+v", err))
	} else if err != nil {
		return nil, err
	}

	return container, err
}

func (m ManagerRelayState) Abort(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) error {
	sid, err := m.sid(ctx, w, r, name)
	if errors.Is(err, &ErrNotResumable) {
		// We do not care about an error here
		return nil
	} else if err != nil {
		return err
	}

	if err := x.SessionUnsetRelayState(&samlhandler.RelayStateValue); err != nil {
		return err
	}

	if err := m.d.ContinuityPersister().DeleteContinuitySession(ctx, sid); err != nil && !errors.Is(err, sqlcon.ErrNoRows) {
		return errors.WithStack(err)
	}

	return nil
}
