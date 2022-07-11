package x

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

// SessionPersistValues adds values to the session store and persists the changes.
func SessionPersistValuesRelayState(r *http.Request, id string) error {

	body, err := ioutil.ReadAll(r.Body)
	r2 := r.Clone(context.WithValue(r.Context(), "sid", id))
	r2.Body = ioutil.NopCloser(bytes.NewReader(body))

	*r = *r2

	return err
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
