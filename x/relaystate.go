package x

import (
	"net/http"

	"github.com/pkg/errors"
)

// SessionPersistValues adds values to the session store and persists the changes.
func SessionPersistValuesRelayState(relayStateValue *string, id string) error {
	*relayStateValue = id

	return nil
}

// SessionGetRelayState returns a string of the content of the relaystate for the current session.
func SessionGetStringRelayState(r *http.Request) (string, error) {
	relayState := r.PostForm.Get("RelayState")
	if relayState == "" {
		return "", errors.New("The RelayState is empty or not exists")
	}

	return relayState, nil
}

func SessionUnsetRelayState(relayStateValue *string) error {
	*relayStateValue = ""

	return nil
}
